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
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("Failed to initialize cloud runtime: {error}"))?;

        let operator = Self::build_operator(settings, creds)?;
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

    pub fn pull(&self, account_name: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let path = Self::vault_filename(account_name);
        self.runtime.block_on(async {
            match self.operator.stat(&path).await {
                Ok(meta) => {
                    if meta.content_length() > MAX_DUMP_BYTES {
                        return Err("Remote vault file exceeds the maximum allowed size.".into());
                    }
                }
                Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
                Err(err) => return Err(format!("Failed to stat remote vault: {err}").into()),
            }

            match self.operator.read(&path).await {
                Ok(buf) => Ok(Some(buf.to_vec())),
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
                Err(err) => Err(format!("Failed to download vault from cloud: {err}").into()),
            }
        })
    }

    pub fn push(&self, account_name: &str, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let main_path = Self::vault_filename(account_name);
        let bak_path = Self::backup_filename(account_name);
        let tmp_path = Self::temp_filename(account_name);

        self.runtime.block_on(async {
            self.operator
                .write(&tmp_path, bytes.to_vec())
                .await
                .map_err(|err| format!("Failed to write temporary cloud object: {err}"))?;

            let outcome = self.publish(&main_path, &bak_path, bytes).await;

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
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.operator.read(main_path).await {
            Ok(existing) => {
                self.operator
                    .write(bak_path, existing)
                    .await
                    .map_err(|err| {
                        format!("Failed to write backup of the cloud vault, upload aborted: {err}")
                    })?;
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "Failed to read the current cloud vault, upload aborted: {err}"
                )
                .into());
            }
        }

        self.operator
            .write(main_path, bytes.to_vec())
            .await
            .map_err(|err| format!("Failed to publish vault to cloud: {err}"))?;
        Ok(())
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
