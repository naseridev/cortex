use crate::{
    cloud::{
        config::{CloudConfig, CloudRemote},
        provider::{CloudCredentials, ProviderSettings},
    },
    core::{accounts::Accounts, limits::MAX_DUMP_BYTES},
};
use opendal::{ErrorKind, Operator, services};
use tokio::runtime::{Builder, Runtime};

const VAULT_EXT: &str = ".cortex";
const BACKUP_EXT: &str = ".cortex.bak";
const TEMP_EXT: &str = ".cortex.tmp";
const CHANGED_DURING_UPLOAD: &str = "Remote vault changed during the upload and was left untouched. Run 'cortex cloud sync' to merge the changes, then push again.";
const REPLACED_AFTER_UPLOAD: &str = "Remote vault changed during the upload: it was replaced after this device wrote it. Run 'cortex cloud sync' to merge the changes, then push again.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteVault {
    pub bytes: Vec<u8>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precondition<'a> {
    Any,
    Absent,
    Unchanged(&'a RemoteVault),
}

pub struct CloudClient {
    operator: Operator,
    runtime: Runtime,
}

impl CloudClient {
    pub fn connect(remote: &CloudRemote) -> Result<Self, Box<dyn std::error::Error>> {
        let creds = CloudConfig::load_credentials(remote)?;
        Self::from_parts(&remote.settings, &creds)
    }

    pub fn from_parts(
        settings: &ProviderSettings,
        creds: &CloudCredentials,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let operator = Self::build_operator(settings, creds)?;
        Self::from_operator(operator)
    }

    pub fn from_operator(operator: Operator) -> Result<Self, Box<dyn std::error::Error>> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("Failed to initialize cloud runtime: {error}"))?;
        Ok(Self { operator, runtime })
    }

    #[must_use]
    pub fn vault_filename(account_name: &str) -> String {
        Self::format_filename(account_name, VAULT_EXT)
    }

    #[must_use]
    pub fn backup_filename(account_name: &str) -> String {
        Self::format_filename(account_name, BACKUP_EXT)
    }

    #[must_use]
    pub fn temp_filename(account_name: &str) -> String {
        Self::format_filename(account_name, TEMP_EXT)
    }

    pub fn fetch(
        &self,
        account_name: &str,
    ) -> Result<Option<RemoteVault>, Box<dyn std::error::Error>> {
        let path = Self::vault_filename(account_name);
        self.runtime.block_on(async {
            let metadata = match self.operator.stat(&path).await {
                Ok(metadata) => metadata,
                Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
                Err(err) => return Err(format!("Failed to stat remote vault: {err}").into()),
            };
            if metadata.content_length() > MAX_DUMP_BYTES {
                return Err("Remote vault file exceeds the maximum allowed size.".into());
            }
            let etag = metadata.etag().map(str::to_owned);

            match self.operator.read(&path).await {
                Ok(buf) => Ok(Some(RemoteVault {
                    bytes: buf.to_vec(),
                    etag,
                })),
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
                Err(err) => Err(format!("Failed to download vault from cloud: {err}").into()),
            }
        })
    }

    pub fn pull(&self, account_name: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        Ok(self.fetch(account_name)?.map(|vault| vault.bytes))
    }

    pub fn push(&self, account_name: &str, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.push_with(account_name, bytes, Precondition::Any)
    }

    pub fn push_with(
        &self,
        account_name: &str,
        bytes: &[u8],
        precondition: Precondition<'_>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let main_path = Self::vault_filename(account_name);
        let bak_path = Self::backup_filename(account_name);
        let tmp_path = Self::temp_filename(account_name);

        self.runtime.block_on(async {
            self.operator
                .write(&tmp_path, bytes.to_vec())
                .await
                .map_err(|err| format!("Failed to write temporary cloud object: {err}"))?;

            let outcome = self
                .publish(&main_path, &bak_path, bytes, precondition)
                .await;

            if let Err(err) = self.operator.delete(&tmp_path).await {
                eprintln!("Warning: could not remove temporary cloud object '{tmp_path}': {err}");
            }

            outcome
        })
    }

    async fn publish(
        &self,
        main_path: &str,
        bak_path: &str,
        bytes: &[u8],
        precondition: Precondition<'_>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let capability = self.operator.info().full_capability();
        let if_match = match precondition {
            Precondition::Unchanged(vault) if capability.write_with_if_match => {
                vault.etag.as_deref()
            }
            _ => None,
        };
        let if_absent =
            matches!(precondition, Precondition::Absent) && capability.write_with_if_not_exists;

        if !self
            .still_matches(main_path, precondition, if_match)
            .await?
        {
            return Err(CHANGED_DURING_UPLOAD.into());
        }

        self.backup_current(main_path, bak_path, precondition)
            .await?;

        let payload = bytes.to_vec();
        let outcome = match (if_match, if_absent) {
            (Some(etag), _) => {
                self.operator
                    .write_with(main_path, payload)
                    .if_match(etag)
                    .await
            }
            (None, true) => {
                self.operator
                    .write_with(main_path, payload)
                    .if_not_exists(true)
                    .await
            }
            (None, false) => self.operator.write(main_path, payload).await,
        };

        match outcome {
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::ConditionNotMatch | ErrorKind::AlreadyExists
                ) =>
            {
                return Err(CHANGED_DURING_UPLOAD.into());
            }
            Err(err) => return Err(format!("Failed to publish vault to cloud: {err}").into()),
        }

        if if_match.is_none() && !if_absent {
            self.verify_published(main_path, bytes).await?;
        }
        Ok(())
    }

    async fn verify_published(
        &self,
        main_path: &str,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.operator.read(main_path).await {
            Ok(current) if current.to_vec() == bytes => Ok(()),
            Ok(_) => Err(REPLACED_AFTER_UPLOAD.into()),
            Err(err) if err.kind() == ErrorKind::NotFound => Err(REPLACED_AFTER_UPLOAD.into()),
            Err(err) => Err(format!("Failed to verify the uploaded cloud vault: {err}").into()),
        }
    }

    async fn backup_current(
        &self,
        main_path: &str,
        bak_path: &str,
        precondition: Precondition<'_>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current = match precondition {
            Precondition::Absent => return Ok(()),
            Precondition::Unchanged(vault) => vault.bytes.clone(),
            Precondition::Any => match self.operator.read(main_path).await {
                Ok(existing) => existing.to_vec(),
                Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
                Err(err) => {
                    return Err(format!(
                        "Failed to read the current cloud vault, upload aborted: {err}"
                    )
                    .into());
                }
            },
        };

        self.operator
            .write(bak_path, current)
            .await
            .map_err(|err| {
                format!("Failed to write backup of the cloud vault, upload aborted: {err}")
            })?;
        Ok(())
    }

    async fn still_matches(
        &self,
        path: &str,
        precondition: Precondition<'_>,
        if_match: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match precondition {
            Precondition::Any => Ok(true),
            Precondition::Absent => match self.operator.stat(path).await {
                Ok(_) => Ok(false),
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(true),
                Err(err) => Err(format!(
                    "Failed to read the current cloud vault, upload aborted: {err}"
                )
                .into()),
            },
            Precondition::Unchanged(_) if if_match.is_some() => {
                match self.operator.stat(path).await {
                    Ok(metadata) => Ok(metadata.etag() == if_match),
                    Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
                    Err(err) => Err(format!(
                        "Failed to read the current cloud vault, upload aborted: {err}"
                    )
                    .into()),
                }
            }
            Precondition::Unchanged(vault) => match self.operator.read(path).await {
                Ok(current) => Ok(current.to_vec() == vault.bytes),
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
                Err(err) => Err(format!(
                    "Failed to read the current cloud vault, upload aborted: {err}"
                )
                .into()),
            },
        }
    }

    fn format_filename(account_name: &str, extension: &str) -> String {
        let redb_name = Accounts::file_name(account_name);
        let stem = redb_name.strip_suffix(".redb").unwrap_or(&redb_name);
        format!("{stem}{extension}")
    }

    fn build_operator(
        settings: &ProviderSettings,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        match settings {
            ProviderSettings::Gdrive { root } => Self::build_gdrive(root, creds),
            ProviderSettings::Dropbox { root } => Self::build_dropbox(root, creds),
            ProviderSettings::Onedrive { root } => Self::build_onedrive(root, creds),
            ProviderSettings::Nextcloud {
                url,
                username,
                root,
            } => {
                let dav_url = ProviderSettings::nextcloud_dav_endpoint(url, username);
                Self::build_webdav(&dav_url, Some(username.as_str()), root, creds)
            }
            ProviderSettings::S3 {
                bucket,
                region,
                endpoint,
                prefix,
            } => Self::build_s3(bucket, region, endpoint.as_deref(), prefix, creds),
            ProviderSettings::Gcs {
                bucket,
                endpoint,
                prefix,
            } => Self::build_gcs(bucket, endpoint.as_deref(), prefix, creds),
            ProviderSettings::Azblob {
                container,
                account,
                endpoint,
                prefix,
            } => Self::build_azblob(container, account, endpoint.as_deref(), prefix, creds),
            ProviderSettings::B2 {
                bucket,
                bucket_id,
                prefix,
            } => Self::build_b2(bucket, bucket_id, prefix, creds),
            ProviderSettings::Oss {
                bucket,
                endpoint,
                prefix,
            } => Self::build_oss(bucket, endpoint, prefix, creds),
            ProviderSettings::Cos {
                bucket,
                endpoint,
                prefix,
            } => Self::build_cos(bucket, endpoint, prefix, creds),
            ProviderSettings::Pcloud {
                endpoint,
                username,
                root,
            } => Self::build_pcloud(endpoint, username, root, creds),
            ProviderSettings::Yandex { root } => Self::build_yandex(root, creds),
            ProviderSettings::Koofr {
                endpoint,
                email,
                root,
            } => Self::build_koofr(endpoint, email, root, creds),
            ProviderSettings::Webdav {
                endpoint,
                username,
                root,
            } => Self::build_webdav(endpoint, username.as_deref(), root, creds),
            ProviderSettings::Local { root } => {
                let builder = services::Fs::default().root(root);
                Ok(Operator::new(builder)?.finish())
            }
        }
    }

    fn build_gdrive(
        root: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::Gdrive::default().root(root);
        if let Some(token) = creds.token.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.access_token(token);
        }
        if let Some(refresh) = creds.refresh_token.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.refresh_token(refresh);
        }
        if let Some(id) = creds.client_id.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.client_id(id);
        }
        if let Some(secret) = creds.client_secret.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.client_secret(secret);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_dropbox(
        root: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::Dropbox::default().root(root);
        if let Some(token) = creds.token.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.access_token(token);
        }
        if let Some(refresh) = creds.refresh_token.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.refresh_token(refresh);
        }
        if let Some(id) = creds.client_id.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.client_id(id);
        }
        if let Some(secret) = creds.client_secret.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.client_secret(secret);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_onedrive(
        root: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::Onedrive::default().root(root);
        if let Some(token) = creds.token.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.access_token(token);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_s3(
        bucket: &str,
        region: &str,
        endpoint: Option<&str>,
        prefix: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::S3::default()
            .bucket(bucket)
            .region(region)
            .root(prefix);
        if let Some(ep) = endpoint.filter(|s| !s.is_empty()) {
            builder = builder.endpoint(ep);
        }
        if let Some(ak) = creds.access_key.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.access_key_id(ak);
        }
        if let Some(sk) = creds.secret_key.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.secret_access_key(sk);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_gcs(
        bucket: &str,
        endpoint: Option<&str>,
        prefix: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::Gcs::default().bucket(bucket).root(prefix);
        if let Some(ep) = endpoint.filter(|s| !s.is_empty()) {
            builder = builder.endpoint(ep);
        }
        if let Some(token) = creds.token.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.token(token.to_string());
        }
        if let Some(cred) = creds.secret_key.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.credential(cred);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_azblob(
        container: &str,
        account: &str,
        endpoint: Option<&str>,
        prefix: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let default_ep = format!("https://{account}.blob.core.windows.net");
        let resolved_ep = endpoint.filter(|s| !s.is_empty()).unwrap_or(&default_ep);
        let mut builder = services::Azblob::default()
            .container(container)
            .account_name(account)
            .endpoint(resolved_ep)
            .root(prefix);
        if let Some(key) = creds.secret_key.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.account_key(key);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_b2(
        bucket: &str,
        bucket_id: &str,
        prefix: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::B2::default()
            .bucket(bucket)
            .bucket_id(bucket_id)
            .root(prefix);
        if let Some(id) = creds.access_key.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.application_key_id(id);
        }
        if let Some(key) = creds.secret_key.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.application_key(key);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_oss(
        bucket: &str,
        endpoint: &str,
        prefix: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::Oss::default()
            .bucket(bucket)
            .endpoint(endpoint)
            .root(prefix);
        if let Some(ak) = creds.access_key.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.access_key_id(ak);
        }
        if let Some(sk) = creds.secret_key.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.access_key_secret(sk);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_cos(
        bucket: &str,
        endpoint: &str,
        prefix: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::Cos::default()
            .bucket(bucket)
            .endpoint(endpoint)
            .root(prefix);
        if let Some(id) = creds.access_key.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.secret_id(id);
        }
        if let Some(key) = creds.secret_key.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.secret_key(key);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_pcloud(
        endpoint: &str,
        username: &str,
        root: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::Pcloud::default()
            .endpoint(endpoint)
            .username(username)
            .root(root);
        if let Some(pass) = creds.password.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.password(pass);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_yandex(
        root: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::YandexDisk::default().root(root);
        if let Some(token) = creds.token.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.access_token(token);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_koofr(
        endpoint: &str,
        email: &str,
        root: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::Koofr::default()
            .endpoint(endpoint)
            .email(email)
            .root(root);
        if let Some(pass) = creds.password.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.password(pass);
        }
        Ok(Operator::new(builder)?.finish())
    }

    fn build_webdav(
        endpoint: &str,
        username: Option<&str>,
        root: &str,
        creds: &CloudCredentials,
    ) -> Result<Operator, Box<dyn std::error::Error>> {
        let mut builder = services::Webdav::default().endpoint(endpoint).root(root);
        if let Some(user) = username.filter(|s| !s.is_empty()) {
            builder = builder.username(user);
        }
        if let Some(pass) = creds.password.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.password(pass);
        }
        Ok(Operator::new(builder)?.finish())
    }
}
