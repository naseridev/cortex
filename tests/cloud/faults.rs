use cortex::cloud::client::{CloudClient, Precondition};
use opendal::raw::{
    Access, AccessorInfo, Layer, LayeredAccess, OpList, OpRead, OpStat, OpWrite, RpDelete, RpList,
    RpRead, RpStat, RpWrite,
};
use opendal::{ErrorKind, Operator, services};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

use crate::common::{TestResult, failure};

const CONFLICT: &str = "changed during the upload";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Stat,
    Read,
    Write,
}

struct Failure {
    op: Op,
    path: String,
    remaining: usize,
}

struct Hook {
    op: Op,
    path: String,
    nth: usize,
    seen: usize,
    action: Box<dyn FnOnce() + Send>,
}

pub struct Faults {
    root: PathBuf,
    conditional: bool,
    failures: Mutex<Vec<Failure>>,
    hooks: Mutex<Vec<Hook>>,
    if_match_log: Mutex<Vec<Option<String>>>,
}

impl fmt::Debug for Faults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Faults")
    }
}

impl Faults {
    fn new(root: &Path, conditional: bool) -> Self {
        Self {
            root: root.to_path_buf(),
            conditional,
            failures: Mutex::new(Vec::new()),
            hooks: Mutex::new(Vec::new()),
            if_match_log: Mutex::new(Vec::new()),
        }
    }

    pub fn fail_next(&self, op: Op, path: &str, times: usize) {
        self.failures.lock().unwrap().push(Failure {
            op,
            path: path.to_string(),
            remaining: times,
        });
    }

    pub fn on_nth(&self, op: Op, path: &str, nth: usize, action: impl FnOnce() + Send + 'static) {
        self.hooks.lock().unwrap().push(Hook {
            op,
            path: path.to_string(),
            nth,
            seen: 0,
            action: Box::new(action),
        });
    }

    pub fn if_match_log(&self) -> Vec<Option<String>> {
        self.if_match_log.lock().unwrap().clone()
    }

    fn before(&self, op: Op, path: &str) -> opendal::Result<()> {
        let mut due = Vec::new();
        {
            let mut hooks = self.hooks.lock().unwrap();
            let mut kept = Vec::new();
            for mut hook in hooks.drain(..) {
                if hook.op == op && hook.path == path {
                    hook.seen += 1;
                    if hook.seen == hook.nth {
                        due.push(hook.action);
                        continue;
                    }
                }
                kept.push(hook);
            }
            *hooks = kept;
        }
        for action in due {
            action();
        }

        let mut failures = self.failures.lock().unwrap();
        if let Some(index) = failures
            .iter()
            .position(|failure| failure.op == op && failure.path == path)
        {
            failures[index].remaining -= 1;
            if failures[index].remaining == 0 {
                failures.remove(index);
            }
            return Err(opendal::Error::new(
                ErrorKind::Unexpected,
                "injected failure",
            ));
        }
        Ok(())
    }

    fn etag(&self, path: &str) -> opendal::Result<Option<String>> {
        match std::fs::read(self.root.join(path)) {
            Ok(bytes) => Ok(Some(format!("\"{}\"", blake3::hash(&bytes).to_hex()))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(opendal::Error::new(
                ErrorKind::Unexpected,
                format!("etag read failed: {error}"),
            )),
        }
    }
}

pub struct FaultLayer {
    faults: Arc<Faults>,
}

impl<A: Access> Layer<A> for FaultLayer {
    type LayeredAccess = FaultAccess<A>;

    fn layer(&self, inner: A) -> Self::LayeredAccess {
        FaultAccess {
            inner,
            faults: self.faults.clone(),
        }
    }
}

#[derive(Debug)]
pub struct FaultAccess<A> {
    inner: A,
    faults: Arc<Faults>,
}

impl<A: Access> LayeredAccess for FaultAccess<A> {
    type Inner = A;
    type Reader = A::Reader;
    type Writer = A::Writer;
    type Lister = A::Lister;
    type Deleter = A::Deleter;
    type BlockingReader = A::BlockingReader;
    type BlockingWriter = A::BlockingWriter;
    type BlockingLister = A::BlockingLister;
    type BlockingDeleter = A::BlockingDeleter;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    fn info(&self) -> Arc<AccessorInfo> {
        let mut info = self.inner.info().as_ref().clone();
        let conditional = self.faults.conditional;
        let capability = info.full_capability_mut();
        capability.write_with_if_match = conditional;
        capability.write_with_if_not_exists = conditional;
        Arc::new(info)
    }

    async fn read(&self, path: &str, args: OpRead) -> opendal::Result<(RpRead, Self::Reader)> {
        self.faults.before(Op::Read, path)?;
        self.inner.read(path, args).await
    }

    async fn write(&self, path: &str, args: OpWrite) -> opendal::Result<(RpWrite, Self::Writer)> {
        self.faults.before(Op::Write, path)?;
        self.faults
            .if_match_log
            .lock()
            .unwrap()
            .push(args.if_match().map(str::to_owned));
        if self.faults.conditional {
            let current = self.faults.etag(path)?;
            let if_match_failed = match args.if_match() {
                Some(expected) => current.as_deref() != Some(expected),
                None => false,
            };
            let created_elsewhere = args.if_not_exists() && current.is_some();
            if if_match_failed || created_elsewhere {
                return Err(opendal::Error::new(
                    ErrorKind::ConditionNotMatch,
                    "precondition failed",
                ));
            }
        }
        self.inner.write(path, args).await
    }

    async fn stat(&self, path: &str, args: OpStat) -> opendal::Result<RpStat> {
        self.faults.before(Op::Stat, path)?;
        let reply = self.inner.stat(path, args).await?;
        if !self.faults.conditional {
            return Ok(reply);
        }
        let etag = self.faults.etag(path)?;
        Ok(reply.map_metadata(|meta| match etag {
            Some(tag) => meta.with_etag(tag),
            None => meta,
        }))
    }

    async fn delete(&self) -> opendal::Result<(RpDelete, Self::Deleter)> {
        self.inner.delete().await
    }

    async fn list(&self, path: &str, args: OpList) -> opendal::Result<(RpList, Self::Lister)> {
        self.inner.list(path, args).await
    }

    fn blocking_read(
        &self,
        path: &str,
        args: OpRead,
    ) -> opendal::Result<(RpRead, Self::BlockingReader)> {
        self.inner.blocking_read(path, args)
    }

    fn blocking_write(
        &self,
        path: &str,
        args: OpWrite,
    ) -> opendal::Result<(RpWrite, Self::BlockingWriter)> {
        self.inner.blocking_write(path, args)
    }

    fn blocking_delete(&self) -> opendal::Result<(RpDelete, Self::BlockingDeleter)> {
        self.inner.blocking_delete()
    }

    fn blocking_list(
        &self,
        path: &str,
        args: OpList,
    ) -> opendal::Result<(RpList, Self::BlockingLister)> {
        self.inner.blocking_list(path, args)
    }
}

pub struct Harness {
    pub dir: TempDir,
    pub faults: Arc<Faults>,
    pub client: CloudClient,
}

fn client_on(root: &Path, faults: &Arc<Faults>) -> Result<CloudClient, Box<dyn std::error::Error>> {
    let operator = Operator::new(services::Fs::default().root(&root.display().to_string()))?
        .layer(FaultLayer {
            faults: faults.clone(),
        })
        .finish();
    CloudClient::from_operator(operator)
}

impl Harness {
    fn new(conditional: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let faults = Arc::new(Faults::new(dir.path(), conditional));
        let client = client_on(dir.path(), &faults)?;
        Ok(Self {
            dir,
            faults,
            client,
        })
    }

    fn second_device(&self) -> Result<CloudClient, Box<dyn std::error::Error>> {
        client_on(self.dir.path(), &self.faults)
    }

    fn vault_path(&self, account: &str) -> PathBuf {
        self.dir.path().join(CloudClient::vault_filename(account))
    }

    fn backup_path(&self, account: &str) -> PathBuf {
        self.dir.path().join(CloudClient::backup_filename(account))
    }

    fn temp_path(&self, account: &str) -> PathBuf {
        self.dir.path().join(CloudClient::temp_filename(account))
    }

    fn write_remote(&self, account: &str, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(self.vault_path(account), bytes)
    }

    fn delete_remote(&self, account: &str) -> std::io::Result<()> {
        std::fs::remove_file(self.vault_path(account))
    }
}

fn modes() -> [bool; 2] {
    [true, false]
}

#[test]
fn vault_replaced_after_fetch_is_rejected_in_both_modes() -> TestResult {
    for conditional in modes() {
        let h = Harness::new(conditional)?;
        h.client.push("work", b"first")?;
        let observed = h.client.fetch("work")?.ok_or("vault should exist")?;
        h.write_remote("work", b"other_device")?;

        let error = failure(h.client.push_with(
            "work",
            b"merged",
            Precondition::Unchanged(&observed),
        ))?;
        assert!(
            error.to_string().contains(CONFLICT),
            "conditional={conditional}"
        );
        assert_eq!(
            h.client.pull("work")?.as_deref(),
            Some(&b"other_device"[..]),
            "conditional={conditional}"
        );
        assert!(!h.backup_path("work").exists(), "conditional={conditional}");
    }
    Ok(())
}

#[test]
fn vault_replaced_after_precheck_is_rejected_by_the_conditional_write() -> TestResult {
    let h = Harness::new(true)?;
    h.client.push("work", b"first")?;
    let observed = h.client.fetch("work")?.ok_or("vault should exist")?;

    let vault = h.vault_path("work");
    h.faults.on_nth(
        Op::Write,
        &CloudClient::vault_filename("work"),
        1,
        move || std::fs::write(&vault, b"other_device").expect("concurrent write"),
    );

    let error = failure(
        h.client
            .push_with("work", b"merged", Precondition::Unchanged(&observed)),
    )?;
    assert!(error.to_string().contains(CONFLICT));
    assert_eq!(
        h.client.pull("work")?.as_deref(),
        Some(&b"other_device"[..])
    );
    assert_eq!(h.faults.if_match_log().last(), Some(&observed.etag));
    Ok(())
}

#[test]
fn vault_created_before_the_check_is_rejected_for_a_new_vault_in_both_modes() -> TestResult {
    for conditional in modes() {
        let h = Harness::new(conditional)?;
        let vault = h.vault_path("work");
        h.faults.on_nth(
            Op::Stat,
            &CloudClient::vault_filename("work"),
            1,
            move || std::fs::write(&vault, b"other_device").expect("concurrent write"),
        );

        let error = failure(h.client.push_with("work", b"first", Precondition::Absent))?;
        assert!(
            error.to_string().contains(CONFLICT),
            "conditional={conditional}"
        );
        assert_eq!(
            h.client.pull("work")?.as_deref(),
            Some(&b"other_device"[..]),
            "conditional={conditional}"
        );
    }
    Ok(())
}

#[test]
fn vault_created_after_the_check_is_rejected_by_if_not_exists() -> TestResult {
    let h = Harness::new(true)?;
    let vault = h.vault_path("work");
    h.faults.on_nth(
        Op::Write,
        &CloudClient::vault_filename("work"),
        1,
        move || std::fs::write(&vault, b"other_device").expect("concurrent write"),
    );

    let error = failure(h.client.push_with("work", b"first", Precondition::Absent))?;
    assert!(error.to_string().contains(CONFLICT));
    assert_eq!(
        h.client.pull("work")?.as_deref(),
        Some(&b"other_device"[..])
    );
    Ok(())
}

#[test]
fn deleted_vault_is_rejected_for_a_guarded_upload_in_both_modes() -> TestResult {
    for conditional in modes() {
        let h = Harness::new(conditional)?;
        h.client.push("work", b"first")?;
        let observed = h.client.fetch("work")?.ok_or("vault should exist")?;
        h.delete_remote("work")?;

        let error = failure(h.client.push_with(
            "work",
            b"merged",
            Precondition::Unchanged(&observed),
        ))?;
        assert!(
            error.to_string().contains(CONFLICT),
            "conditional={conditional}"
        );
        assert!(
            h.client.pull("work")?.is_none(),
            "conditional={conditional}"
        );
    }
    Ok(())
}

#[test]
fn deleted_vault_can_be_recreated_with_an_absent_precondition_in_both_modes() -> TestResult {
    for conditional in modes() {
        let h = Harness::new(conditional)?;
        h.client.push("work", b"first")?;
        h.delete_remote("work")?;

        h.client
            .push_with("work", b"recreated", Precondition::Absent)?;

        assert_eq!(
            h.client.pull("work")?.as_deref(),
            Some(&b"recreated"[..]),
            "conditional={conditional}"
        );
    }
    Ok(())
}

#[test]
fn temp_object_write_failure_leaves_the_vault_untouched_in_both_modes() -> TestResult {
    for conditional in modes() {
        let h = Harness::new(conditional)?;
        h.client.push("work", b"first")?;
        h.faults
            .fail_next(Op::Write, &CloudClient::temp_filename("work"), 1);

        let error = failure(h.client.push("work", b"second"))?;
        assert!(
            error.to_string().contains("temporary cloud object"),
            "conditional={conditional}"
        );
        assert_eq!(
            h.client.pull("work")?.as_deref(),
            Some(&b"first"[..]),
            "conditional={conditional}"
        );
        assert!(!h.backup_path("work").exists(), "conditional={conditional}");
        assert!(!h.temp_path("work").exists(), "conditional={conditional}");
    }
    Ok(())
}

#[test]
fn backup_write_failure_aborts_before_the_vault_is_replaced_in_both_modes() -> TestResult {
    for conditional in modes() {
        let h = Harness::new(conditional)?;
        h.client.push("work", b"first")?;
        h.client.push("work", b"second")?;
        let observed = h.client.fetch("work")?.ok_or("vault should exist")?;
        h.faults
            .fail_next(Op::Write, &CloudClient::backup_filename("work"), 1);

        let error = failure(h.client.push_with(
            "work",
            b"third",
            Precondition::Unchanged(&observed),
        ))?;
        assert!(
            error.to_string().contains("backup"),
            "conditional={conditional}"
        );
        assert_eq!(
            h.client.pull("work")?.as_deref(),
            Some(&b"second"[..]),
            "conditional={conditional}"
        );
        assert_eq!(
            std::fs::read(h.backup_path("work"))?,
            b"first",
            "conditional={conditional}"
        );
        assert!(!h.temp_path("work").exists(), "conditional={conditional}");
    }
    Ok(())
}

#[test]
fn failed_publish_keeps_the_previous_vault_and_a_retry_succeeds_in_both_modes() -> TestResult {
    for conditional in modes() {
        let h = Harness::new(conditional)?;
        h.client.push("work", b"first")?;
        h.client.push("work", b"second")?;
        h.faults
            .fail_next(Op::Write, &CloudClient::vault_filename("work"), 1);

        let error = failure(h.client.push("work", b"third"))?;
        assert!(
            error.to_string().contains("Failed to publish vault"),
            "conditional={conditional}"
        );
        assert_eq!(
            h.client.pull("work")?.as_deref(),
            Some(&b"second"[..]),
            "conditional={conditional}"
        );

        h.client.push("work", b"third")?;
        assert_eq!(
            h.client.pull("work")?.as_deref(),
            Some(&b"third"[..]),
            "conditional={conditional}"
        );
        assert_eq!(
            std::fs::read(h.backup_path("work"))?,
            b"second",
            "conditional={conditional}"
        );
    }
    Ok(())
}

#[test]
fn failed_precheck_read_stops_the_upload_without_writing_in_both_modes() -> TestResult {
    for conditional in modes() {
        let h = Harness::new(conditional)?;
        h.client.push("work", b"first")?;
        let observed = h.client.fetch("work")?.ok_or("vault should exist")?;
        let precheck = if conditional { Op::Stat } else { Op::Read };
        h.faults
            .fail_next(precheck, &CloudClient::vault_filename("work"), 1);

        let error = failure(h.client.push_with(
            "work",
            b"second",
            Precondition::Unchanged(&observed),
        ))?;
        assert!(
            error
                .to_string()
                .contains("Failed to read the current cloud vault"),
            "conditional={conditional}"
        );
        assert_eq!(
            h.client.pull("work")?.as_deref(),
            Some(&b"first"[..]),
            "conditional={conditional}"
        );
        assert!(!h.backup_path("work").exists(), "conditional={conditional}");
        assert!(!h.temp_path("work").exists(), "conditional={conditional}");
    }
    Ok(())
}

#[test]
fn failed_download_is_reported_by_fetch_in_both_modes() -> TestResult {
    for conditional in modes() {
        let h = Harness::new(conditional)?;
        h.client.push("work", b"first")?;
        h.faults
            .fail_next(Op::Read, &CloudClient::vault_filename("work"), 1);

        let error = failure(h.client.fetch("work"))?;
        assert!(
            error
                .to_string()
                .contains("Failed to download vault from cloud"),
            "conditional={conditional}"
        );
    }
    Ok(())
}

#[test]
fn two_devices_interleaving_never_overwrite_each_other_in_both_modes() -> TestResult {
    for conditional in modes() {
        let h = Harness::new(conditional)?;
        let device_b = h.second_device()?;
        h.client.push("work", b"base")?;

        let observed_a = h.client.fetch("work")?.ok_or("vault should exist")?;
        let observed_b = device_b.fetch("work")?.ok_or("vault should exist")?;

        device_b.push_with("work", b"from_b", Precondition::Unchanged(&observed_b))?;

        let error = failure(h.client.push_with(
            "work",
            b"from_a",
            Precondition::Unchanged(&observed_a),
        ))?;
        assert!(
            error.to_string().contains(CONFLICT),
            "conditional={conditional}"
        );
        assert_eq!(
            h.client.pull("work")?.as_deref(),
            Some(&b"from_b"[..]),
            "conditional={conditional}"
        );

        let refreshed = h.client.fetch("work")?.ok_or("vault should exist")?;
        h.client
            .push_with("work", b"merged", Precondition::Unchanged(&refreshed))?;
        assert_eq!(
            device_b.pull("work")?.as_deref(),
            Some(&b"merged"[..]),
            "conditional={conditional}"
        );
    }
    Ok(())
}
