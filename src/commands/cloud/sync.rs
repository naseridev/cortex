use super::resolve_account;
use crate::{
    cloud::{
        client::{CloudClient, Precondition, RemoteVault},
        config::{CloudConfig, CloudRemote, SyncRecord},
        engine::{ClockSkew, MergeReport, SyncEngine, SyncState, SyncStatus},
    },
    core::{accounts::Accounts, crypto::Crypto, dump::Dump, storage::Storage, time::Time},
    modules::{gateway::Gateway, session::Session},
    ui::prompt::UserPrompt,
};

struct GuardedUpload<'a> {
    client: &'a CloudClient,
    account_name: &'a str,
    observed: &'a RemoteVault,
}

impl GuardedUpload<'_> {
    fn publish(&self, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.client.push_with(
            self.account_name,
            bytes,
            Precondition::Unchanged(self.observed),
        )
    }
}

pub fn execute(
    remote_name: Option<&str>,
    account: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = CloudConfig::load()?;
    let remote = config.resolve_remote(remote_name)?.clone();
    let account_name = resolve_account(account)?;
    let client = CloudClient::connect(&remote)?;

    let local_exists = Accounts::exists(&account_name)?;
    let remote_vault = client.fetch(&account_name)?;

    match (local_exists, remote_vault) {
        (false, None) => Err(format!(
            "Account '{account_name}' does not exist locally or on remote '{}'.",
            remote.name
        )
        .into()),
        (false, Some(vault)) => pull_new_account(&mut config, &remote, &account_name, &vault.bytes),
        (true, None) => push_existing_account(&mut config, &remote, &client, &account_name),
        (true, Some(vault)) => reconcile_both(&mut config, &remote, &client, &account_name, &vault),
    }
}

fn pull_new_account(
    config: &mut CloudConfig,
    remote: &CloudRemote,
    account_name: &str,
    remote_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let dump_file = Dump::decode(remote_bytes)?;
    let password = UserPrompt::password(&format!(
        "Master password for cloud account '{account_name}': "
    ))?;
    let crypto = Crypto::open(&password, &dump_file.salt)?;
    let snapshot = Storage::read_dump(&dump_file, &crypto)?;

    let storage = Storage::open_account(account_name)?;
    storage.replace_with_dump(&snapshot)?;
    storage.bind_integrity(&crypto);
    storage.verify_integrity()?;
    drop(storage);

    Accounts::register(account_name)?;

    let remote_hash = SyncEngine::digest(remote_bytes);
    config.record_sync(
        &remote.name,
        account_name,
        SyncRecord {
            last_sync_timestamp: Time::current_timestamp(),
            last_synced_hash: remote_hash,
            entry_count: snapshot.user_count(),
        },
    )?;

    println!(
        "Pulled new account '{account_name}' ({} entries) from '{}'.",
        snapshot.user_count(),
        remote.name
    );
    Ok(())
}

fn push_existing_account(
    config: &mut CloudConfig,
    remote: &CloudRemote,
    client: &CloudClient,
    account_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (storage, crypto) = Gateway::login_account(account_name)?;
    let entries = storage.list_entries()?;
    let dump_bytes = storage.encode_dump(&crypto)?;
    let local_hash = SyncEngine::digest(&dump_bytes);

    client.push_with(account_name, &dump_bytes, Precondition::Absent)?;

    config.record_sync(
        &remote.name,
        account_name,
        SyncRecord {
            last_sync_timestamp: Time::current_timestamp(),
            last_synced_hash: local_hash,
            entry_count: entries.len(),
        },
    )?;

    println!(
        "Pushed account '{account_name}' ({} entries) to '{}'.",
        entries.len(),
        remote.name
    );
    Ok(())
}

fn record_sync_state(
    config: &mut CloudConfig,
    remote: &CloudRemote,
    account_name: &str,
    hash: [u8; 32],
    entry_count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    config.record_sync(
        &remote.name,
        account_name,
        SyncRecord {
            last_sync_timestamp: Time::current_timestamp(),
            last_synced_hash: hash,
            entry_count,
        },
    )
}

fn publish_merged(
    config: &mut CloudConfig,
    remote: &CloudRemote,
    upload: &GuardedUpload<'_>,
    storage: &Storage,
    local_crypto: &Crypto,
    report: &MergeReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let local_salt = storage
        .get_salt()?
        .ok_or("Database salt not found. Database may be corrupted.")?;
    storage.atomic_merge(
        &report.entries,
        &report.tombstones,
        report.clock,
        local_crypto,
        &local_salt,
    )?;
    storage.verify_integrity()?;

    let merged_bytes = storage.encode_dump(local_crypto)?;
    let merged_hash = SyncEngine::digest(&merged_bytes);
    upload.publish(&merged_bytes)?;

    if Accounts::active()?.as_deref() == Some(upload.account_name) {
        let _ = Session::save_session(local_crypto.key());
    }

    record_sync_state(
        config,
        remote,
        upload.account_name,
        merged_hash,
        report.entries.len(),
    )?;

    println!(
        "Synchronized '{}' with '{}': {} added, {} updated, {} removed, {} kept (total: {}).",
        upload.account_name,
        remote.name,
        report.added_from_remote,
        report.updated_from_remote,
        report.removed_from_remote,
        report.kept_local,
        report.entries.len()
    );
    Ok(())
}

fn handle_identical(remote: &CloudRemote, account_name: &str) {
    println!(
        "Account '{account_name}' is already in sync with '{}'.",
        remote.name
    );
}

fn handle_local_ahead(
    config: &mut CloudConfig,
    remote: &CloudRemote,
    upload: &GuardedUpload<'_>,
    local_bytes: &[u8],
    local_hash: [u8; 32],
    entry_count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    upload.publish(local_bytes)?;
    record_sync_state(config, remote, upload.account_name, local_hash, entry_count)?;
    println!(
        "Local vault is ahead. Uploaded '{}' ({} entries) to '{}'.",
        upload.account_name, entry_count, remote.name
    );
    Ok(())
}

fn handle_remote_ahead_same_key(
    config: &mut CloudConfig,
    remote: &CloudRemote,
    account_name: &str,
    storage: &Storage,
    remote_snapshot: &crate::core::storage::Snapshot,
    remote_hash: [u8; 32],
    remote_entries_len: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    storage.replace_with_dump(remote_snapshot)?;
    storage.verify_integrity()?;
    record_sync_state(
        config,
        remote,
        account_name,
        remote_hash,
        remote_entries_len,
    )?;
    println!(
        "Remote vault is ahead. Updated local account '{account_name}' ({} entries) from '{}'.",
        remote_entries_len, remote.name
    );
    Ok(())
}

fn warn_clock_skew(skew: &ClockSkew, remote_name: &str) {
    if skew.remote_exceeds_tolerance() {
        eprintln!(
            "Warning: remote '{remote_name}' holds timestamps {} seconds ahead of this device's clock. Edits made on a device with a wrong clock may win conflicts. Check the system clock on every device.",
            skew.remote_ahead_secs
        );
    }
    if skew.vault_exceeds_tolerance() {
        eprintln!(
            "Warning: this device's clock is {} seconds behind the newest timestamp in this vault. New changes are ordered after existing ones, but the system clock on this device should be checked.",
            skew.vault_ahead_secs
        );
    }
}

fn reconcile_both(
    config: &mut CloudConfig,
    remote: &CloudRemote,
    client: &CloudClient,
    account_name: &str,
    observed: &RemoteVault,
) -> Result<(), Box<dyn std::error::Error>> {
    let (storage, local_crypto) = Gateway::login_account(account_name)?;
    let local_state = SyncState::from_storage(&storage)?;
    let local_clock = storage.clock()?;
    let local_bytes = storage.encode_dump(&local_crypto)?;
    let local_hash = SyncEngine::digest(&local_bytes);
    let remote_hash = SyncEngine::digest(&observed.bytes);

    if local_hash == remote_hash {
        record_sync_state(
            config,
            remote,
            account_name,
            local_hash,
            local_state.entries.len(),
        )?;
        handle_identical(remote, account_name);
        return Ok(());
    }

    let (remote_snapshot, remote_crypto, same_key) = SyncEngine::open_remote_snapshot(
        &observed.bytes,
        &local_crypto,
        || {
            UserPrompt::password(&format!(
                "Remote vault for '{account_name}' uses a different master password. Enter remote password: "
            ))
        },
    )?;

    let remote_state = SyncEngine::unpack_snapshot(&remote_snapshot)?;
    let remote_clock = Storage::clock_from_records(remote_snapshot.entries())?;
    let skew = SyncEngine::clock_skew(remote_clock, local_clock, Time::current_timestamp());
    warn_clock_skew(&skew, &remote.name);

    let last_hash = remote
        .accounts
        .get(account_name)
        .map(|s| s.last_synced_hash)
        .filter(|h| *h != [0u8; 32]);

    let status = SyncEngine::evaluate_status(
        &local_state,
        &remote_state,
        last_hash,
        local_hash,
        remote_hash,
    );

    let upload = GuardedUpload {
        client,
        account_name,
        observed,
    };

    match status {
        SyncStatus::Identical => handle_identical(remote, account_name),
        SyncStatus::LocalAhead => handle_local_ahead(
            config,
            remote,
            &upload,
            &local_bytes,
            local_hash,
            local_state.entries.len(),
        )?,
        SyncStatus::RemoteAhead if same_key => handle_remote_ahead_same_key(
            config,
            remote,
            account_name,
            &storage,
            &remote_snapshot,
            remote_hash,
            remote_state.entries.len(),
        )?,
        SyncStatus::RemoteAhead | SyncStatus::Diverged => {
            let empty = SyncState::default();
            let base_local = if status == SyncStatus::RemoteAhead {
                &empty
            } else {
                &local_state
            };
            let report = SyncEngine::merge(
                base_local,
                &local_crypto,
                &remote_state,
                &remote_crypto,
                same_key,
            )?;
            publish_merged(config, remote, &upload, &storage, &local_crypto, &report)?;
        }
    }

    Ok(())
}
