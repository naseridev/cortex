use crate::{
    cloud::{
        config::{CloudConfig, CredentialStorage},
        provider::{CloudCredentials, ProviderSettings},
    },
    domain::validation::Validation,
    ui::{cli::CloudProvider, prompt::UserPrompt},
};

pub fn execute(provider: CloudProvider) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = CloudConfig::load()?;
    let (remote_name, settings, creds) = configure_provider(provider)?;
    Validation::check_account_name(&remote_name)?;
    let kind = settings.kind();
    let storage = config.add_remote(&remote_name, settings, &creds)?;
    println!("Configured {kind} cloud remote '{remote_name}'.");
    if storage == CredentialStorage::Passphrase {
        println!(
            "Warning: the system keyring is unavailable, so the cloud credentials were encrypted with a separate passphrase."
        );
        println!(
            "You will be asked for that passphrase on every cloud operation for remote '{remote_name}'."
        );
    }
    Ok(())
}

fn configure_provider(
    provider: CloudProvider,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    match provider {
        CloudProvider::Gdrive {
            name,
            root,
            client_id,
        } => configure_oauth(OAuth::Gdrive, name, root, client_id),
        CloudProvider::Dropbox {
            name,
            root,
            client_id,
        } => configure_oauth(OAuth::Dropbox, name, root, client_id),
        CloudProvider::Onedrive {
            name,
            root,
            client_id,
        } => configure_oauth(OAuth::Onedrive, name, root, client_id),
        CloudProvider::Nextcloud {
            url,
            username,
            root,
            name,
        } => configure_nextcloud(&url, username, root.as_deref(), name),
        CloudProvider::S3 {
            bucket,
            region,
            endpoint,
            prefix,
            name,
        } => configure_s3(&bucket, &region, endpoint, prefix.as_deref(), name),
        CloudProvider::Gcs {
            bucket,
            endpoint,
            prefix,
            name,
        } => configure_gcs(&bucket, endpoint, prefix.as_deref(), name),
        CloudProvider::Azblob {
            container,
            account,
            endpoint,
            prefix,
            name,
        } => configure_azblob(&container, &account, endpoint, prefix.as_deref(), name),
        CloudProvider::B2 {
            bucket,
            bucket_id,
            prefix,
            name,
        } => configure_b2(&bucket, &bucket_id, prefix.as_deref(), name),
        CloudProvider::Oss {
            bucket,
            endpoint,
            prefix,
            name,
        } => configure_oss(&bucket, &endpoint, prefix.as_deref(), name),
        CloudProvider::Cos {
            bucket,
            endpoint,
            prefix,
            name,
        } => configure_cos(&bucket, &endpoint, prefix.as_deref(), name),
        CloudProvider::Pcloud {
            endpoint,
            username,
            root,
            name,
        } => configure_pcloud(&endpoint, username, root.as_deref(), name),
        CloudProvider::Yandex { root, name } => configure_yandex(root.as_deref(), name),
        CloudProvider::Koofr {
            endpoint,
            email,
            root,
            name,
        } => configure_koofr(&endpoint, email, root.as_deref(), name),
        CloudProvider::Webdav {
            url,
            username,
            root,
            name,
        } => configure_webdav(&url, username, root.as_deref(), name),
        CloudProvider::Local { path, name } => configure_local(&path, name),
    }
}

type ConfiguredRemote = (String, ProviderSettings, CloudCredentials);

#[derive(Clone, Copy)]
enum OAuth {
    Gdrive,
    Dropbox,
    Onedrive,
}

impl OAuth {
    fn alias(self) -> &'static str {
        match self {
            Self::Gdrive => "gdrive",
            Self::Dropbox => "dropbox",
            Self::Onedrive => "onedrive",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Gdrive => "Google Drive",
            Self::Dropbox => "Dropbox",
            Self::Onedrive => "OneDrive",
        }
    }

    fn settings(self, root: String) -> ProviderSettings {
        match self {
            Self::Gdrive => ProviderSettings::Gdrive { root },
            Self::Dropbox => ProviderSettings::Dropbox { root },
            Self::Onedrive => ProviderSettings::Onedrive { root },
        }
    }
}

fn configure_oauth(
    backend: OAuth,
    name: Option<String>,
    root: Option<String>,
    client_id: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let alias = name.unwrap_or_else(|| backend.alias().to_string());
    Validation::check_account_name(&alias)?;
    let label = backend.label();
    let token = UserPrompt::token(&format!("{label} access token: "))?;
    let refresh = UserPrompt::optional_token(&format!("{label} refresh token (optional): "))?;
    let clean_client_id = client_id
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty());
    let client_secret = if clean_client_id.is_some() {
        UserPrompt::optional_token(&format!("{label} client secret (optional): "))?
            .map(|secret| secret.as_str().to_string())
    } else {
        None
    };
    let root = root.unwrap_or_default();
    let settings = backend.settings(ProviderSettings::normalize_root(
        Some(root.as_str()),
        "/cortex",
    ));
    let creds = CloudCredentials::with_oauth(
        token.as_str().to_string(),
        refresh.map(|v| v.as_str().to_string()),
        clean_client_id,
        client_secret,
    );
    Ok((alias, settings, creds))
}

fn configure_nextcloud(
    url: &str,
    username: Option<String>,
    root: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_url = require_non_empty(url, "Nextcloud URL")?;
    let alias = name.unwrap_or_else(|| "nextcloud".to_string());
    Validation::check_account_name(&alias)?;
    let resolved_user = match username
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
    {
        Some(u) => u,
        None => require_non_empty(&UserPrompt::text("Nextcloud username: ")?, "Username")?,
    };
    let password = UserPrompt::password("Nextcloud app password: ")?;
    let settings = ProviderSettings::Nextcloud {
        url: clean_url,
        username: resolved_user,
        root: ProviderSettings::normalize_root(root, "/cortex"),
    };
    let creds = CloudCredentials::with_password(Some(password.as_str().to_string()));
    Ok((alias, settings, creds))
}

fn configure_s3(
    bucket: &str,
    region: &str,
    endpoint: Option<String>,
    prefix: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_bucket = require_non_empty(bucket, "S3 bucket")?;
    let clean_region = require_non_empty(region, "S3 region")?;
    let alias = name.unwrap_or_else(|| "s3".to_string());
    Validation::check_account_name(&alias)?;
    let access_key = require_non_empty(&UserPrompt::text("S3 Access Key ID: ")?, "Access Key ID")?;
    let secret_key = UserPrompt::password("S3 Secret Access Key: ")?;
    let settings = ProviderSettings::S3 {
        bucket: clean_bucket,
        region: clean_region,
        endpoint: endpoint
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty()),
        prefix: ProviderSettings::normalize_root(prefix, "/cortex"),
    };
    let creds = CloudCredentials::with_keys(access_key, secret_key.as_str().to_string());
    Ok((alias, settings, creds))
}

fn configure_gcs(
    bucket: &str,
    endpoint: Option<String>,
    prefix: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_bucket = require_non_empty(bucket, "GCS bucket")?;
    let alias = name.unwrap_or_else(|| "gcs".to_string());
    Validation::check_account_name(&alias)?;
    let token = UserPrompt::token("GCS OAuth2 token: ")?;
    let settings = ProviderSettings::Gcs {
        bucket: clean_bucket,
        endpoint: endpoint
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty()),
        prefix: ProviderSettings::normalize_root(prefix, "/cortex"),
    };
    let creds = CloudCredentials::with_token(token.as_str().to_string());
    Ok((alias, settings, creds))
}

fn configure_azblob(
    container: &str,
    account: &str,
    endpoint: Option<String>,
    prefix: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_container = require_non_empty(container, "Azure container")?;
    let clean_account = require_non_empty(account, "Azure storage account")?;
    let alias = name.unwrap_or_else(|| "azblob".to_string());
    Validation::check_account_name(&alias)?;
    let account_key = UserPrompt::password("Azure Storage Account Key: ")?;
    let settings = ProviderSettings::Azblob {
        container: clean_container,
        account: clean_account,
        endpoint: endpoint
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty()),
        prefix: ProviderSettings::normalize_root(prefix, "/cortex"),
    };
    let creds = CloudCredentials::with_secret_key(account_key.as_str().to_string());
    Ok((alias, settings, creds))
}

fn configure_b2(
    bucket: &str,
    bucket_id: &str,
    prefix: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_bucket = require_non_empty(bucket, "B2 bucket")?;
    let clean_id = require_non_empty(bucket_id, "B2 bucket ID")?;
    let alias = name.unwrap_or_else(|| "b2".to_string());
    Validation::check_account_name(&alias)?;
    let key_id = require_non_empty(
        &UserPrompt::text("B2 Application Key ID: ")?,
        "Application Key ID",
    )?;
    let app_key = UserPrompt::password("B2 Application Key: ")?;
    let settings = ProviderSettings::B2 {
        bucket: clean_bucket,
        bucket_id: clean_id,
        prefix: ProviderSettings::normalize_root(prefix, "/cortex"),
    };
    let creds = CloudCredentials::with_keys(key_id, app_key.as_str().to_string());
    Ok((alias, settings, creds))
}

fn configure_oss(
    bucket: &str,
    endpoint: &str,
    prefix: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_bucket = require_non_empty(bucket, "OSS bucket")?;
    let clean_endpoint = require_non_empty(endpoint, "OSS endpoint")?;
    let alias = name.unwrap_or_else(|| "oss".to_string());
    Validation::check_account_name(&alias)?;
    let access_key = require_non_empty(&UserPrompt::text("OSS Access Key ID: ")?, "Access Key ID")?;
    let secret_key = UserPrompt::password("OSS Access Key Secret: ")?;
    let settings = ProviderSettings::Oss {
        bucket: clean_bucket,
        endpoint: clean_endpoint,
        prefix: ProviderSettings::normalize_root(prefix, "/cortex"),
    };
    let creds = CloudCredentials::with_keys(access_key, secret_key.as_str().to_string());
    Ok((alias, settings, creds))
}

fn configure_cos(
    bucket: &str,
    endpoint: &str,
    prefix: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_bucket = require_non_empty(bucket, "COS bucket")?;
    let clean_endpoint = require_non_empty(endpoint, "COS endpoint")?;
    let alias = name.unwrap_or_else(|| "cos".to_string());
    Validation::check_account_name(&alias)?;
    let secret_id = require_non_empty(&UserPrompt::text("COS Secret ID: ")?, "Secret ID")?;
    let secret_key = UserPrompt::password("COS Secret Key: ")?;
    let settings = ProviderSettings::Cos {
        bucket: clean_bucket,
        endpoint: clean_endpoint,
        prefix: ProviderSettings::normalize_root(prefix, "/cortex"),
    };
    let creds = CloudCredentials::with_keys(secret_id, secret_key.as_str().to_string());
    Ok((alias, settings, creds))
}

fn configure_pcloud(
    endpoint: &str,
    username: Option<String>,
    root: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_endpoint = require_non_empty(endpoint, "pCloud endpoint")?;
    let alias = name.unwrap_or_else(|| "pcloud".to_string());
    Validation::check_account_name(&alias)?;
    let resolved_user = match username
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
    {
        Some(u) => u,
        None => require_non_empty(&UserPrompt::text("pCloud username/email: ")?, "Username")?,
    };
    let password = UserPrompt::password("pCloud password: ")?;
    let settings = ProviderSettings::Pcloud {
        endpoint: clean_endpoint,
        username: resolved_user,
        root: ProviderSettings::normalize_root(root, "/cortex"),
    };
    let creds = CloudCredentials::with_password(Some(password.as_str().to_string()));
    Ok((alias, settings, creds))
}

fn configure_yandex(
    root: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let alias = name.unwrap_or_else(|| "yandex".to_string());
    Validation::check_account_name(&alias)?;
    let token = UserPrompt::token("Yandex Disk OAuth token: ")?;
    let settings = ProviderSettings::Yandex {
        root: ProviderSettings::normalize_root(root, "/cortex"),
    };
    let creds = CloudCredentials::with_token(token.as_str().to_string());
    Ok((alias, settings, creds))
}

fn configure_koofr(
    endpoint: &str,
    email: Option<String>,
    root: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_endpoint = require_non_empty(endpoint, "Koofr endpoint")?;
    let alias = name.unwrap_or_else(|| "koofr".to_string());
    Validation::check_account_name(&alias)?;
    let resolved_email = match email
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
    {
        Some(e) => e,
        None => require_non_empty(&UserPrompt::text("Koofr email: ")?, "Email")?,
    };
    let password = UserPrompt::password("Koofr app password: ")?;
    let settings = ProviderSettings::Koofr {
        endpoint: clean_endpoint,
        email: resolved_email,
        root: ProviderSettings::normalize_root(root, "/cortex"),
    };
    let creds = CloudCredentials::with_password(Some(password.as_str().to_string()));
    Ok((alias, settings, creds))
}

fn configure_webdav(
    url: &str,
    username: Option<String>,
    root: Option<&str>,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_url = require_non_empty(url, "WebDAV URL")?;
    let alias = name.unwrap_or_else(|| "webdav".to_string());
    Validation::check_account_name(&alias)?;
    let clean_user = username
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    let password = if clean_user.is_some() {
        Some(UserPrompt::password("WebDAV password: ")?)
    } else {
        UserPrompt::optional_password("WebDAV password (optional): ")?
    };
    let settings = ProviderSettings::Webdav {
        endpoint: clean_url,
        username: clean_user,
        root: ProviderSettings::normalize_root(root, "/cortex"),
    };
    let creds = CloudCredentials::with_password(password.map(|p| p.as_str().to_string()));
    Ok((alias, settings, creds))
}

fn configure_local(
    path: &str,
    name: Option<String>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let clean_path = require_non_empty(path, "Local directory path")?;
    let alias = name.unwrap_or_else(|| "local".to_string());
    Validation::check_account_name(&alias)?;
    let settings = ProviderSettings::Local { root: clean_path };
    Ok((alias, settings, CloudCredentials::default()))
}

fn require_non_empty(input: &str, label: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} cannot be empty.").into());
    }
    Ok(trimmed.to_string())
}
