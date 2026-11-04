use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum ProviderSettings {
    Gdrive {
        root: String,
    },
    Dropbox {
        root: String,
    },
    Onedrive {
        root: String,
    },
    Nextcloud {
        url: String,
        username: String,
        root: String,
    },
    S3 {
        bucket: String,
        region: String,
        endpoint: Option<String>,
        prefix: String,
    },
    Gcs {
        bucket: String,
        endpoint: Option<String>,
        prefix: String,
    },
    Azblob {
        container: String,
        account: String,
        endpoint: Option<String>,
        prefix: String,
    },
    B2 {
        bucket: String,
        bucket_id: String,
        prefix: String,
    },
    Oss {
        bucket: String,
        endpoint: String,
        prefix: String,
    },
    Cos {
        bucket: String,
        endpoint: String,
        prefix: String,
    },
    Pcloud {
        endpoint: String,
        username: String,
        root: String,
    },
    Yandex {
        root: String,
    },
    Koofr {
        endpoint: String,
        email: String,
        root: String,
    },
    Webdav {
        endpoint: String,
        username: Option<String>,
        root: String,
    },
    Local {
        root: String,
    },
}

impl ProviderSettings {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Gdrive { .. } => "gdrive",
            Self::Dropbox { .. } => "dropbox",
            Self::Onedrive { .. } => "onedrive",
            Self::Nextcloud { .. } => "nextcloud",
            Self::S3 { .. } => "s3",
            Self::Gcs { .. } => "gcs",
            Self::Azblob { .. } => "azblob",
            Self::B2 { .. } => "b2",
            Self::Oss { .. } => "oss",
            Self::Cos { .. } => "cos",
            Self::Pcloud { .. } => "pcloud",
            Self::Yandex { .. } => "yandex",
            Self::Koofr { .. } => "koofr",
            Self::Webdav { .. } => "webdav",
            Self::Local { .. } => "local",
        }
    }

    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Gdrive { root } => format!("gdrive (root: {root})"),
            Self::Dropbox { root } => format!("dropbox (root: {root})"),
            Self::Onedrive { root } => format!("onedrive (root: {root})"),
            Self::Nextcloud {
                url,
                username,
                root,
            } => format!("nextcloud {url}{root} (user: {username})"),
            Self::S3 {
                bucket,
                region,
                endpoint,
                prefix,
            } => match endpoint {
                Some(ep) => format!("s3://{bucket}{prefix} (region: {region}, endpoint: {ep})"),
                None => format!("s3://{bucket}{prefix} (region: {region})"),
            },
            Self::Gcs {
                bucket,
                endpoint,
                prefix,
            } => match endpoint {
                Some(ep) => format!("gcs://{bucket}{prefix} (endpoint: {ep})"),
                None => format!("gcs://{bucket}{prefix}"),
            },
            Self::Azblob {
                container,
                account,
                prefix,
                ..
            } => format!("azblob://{account}/{container}{prefix}"),
            Self::B2 { bucket, prefix, .. } => format!("b2://{bucket}{prefix}"),
            Self::Oss {
                bucket,
                endpoint,
                prefix,
            } => format!("oss://{bucket}{prefix} (endpoint: {endpoint})"),
            Self::Cos {
                bucket,
                endpoint,
                prefix,
            } => format!("cos://{bucket}{prefix} (endpoint: {endpoint})"),
            Self::Pcloud {
                endpoint,
                username,
                root,
            } => format!("pcloud {endpoint}{root} (user: {username})"),
            Self::Yandex { root } => format!("yandex (root: {root})"),
            Self::Koofr {
                endpoint,
                email,
                root,
            } => format!("koofr {endpoint}{root} (email: {email})"),
            Self::Webdav {
                endpoint,
                username,
                root,
            } => match username {
                Some(user) => format!("webdav {endpoint}{root} (user: {user})"),
                None => format!("webdav {endpoint}{root}"),
            },
            Self::Local { root } => format!("local ({root})"),
        }
    }

    #[must_use]
    pub fn normalize_root(raw: Option<&str>, default_root: &str) -> String {
        let chosen = raw
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(default_root);

        if chosen.starts_with('/') {
            chosen.to_string()
        } else {
            format!("/{chosen}")
        }
    }

    #[must_use]
    pub fn nextcloud_dav_endpoint(base_url: &str, username: &str) -> String {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.contains("/remote.php/dav") || trimmed.contains("/remote.php/webdav") {
            trimmed.to_string()
        } else {
            format!("{trimmed}/remote.php/dav/files/{username}")
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct CloudCredentials {
    pub token: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub password: Option<String>,
}

impl CloudCredentials {
    #[must_use]
    pub fn with_token(token: String) -> Self {
        let mut creds = Self::default();
        creds.token = Some(token);
        creds
    }

    #[must_use]
    pub fn with_oauth(
        token: String,
        refresh_token: Option<String>,
        client_id: Option<String>,
        client_secret: Option<String>,
    ) -> Self {
        let mut creds = Self::default();
        creds.token = Some(token);
        creds.refresh_token = refresh_token;
        creds.client_id = client_id;
        creds.client_secret = client_secret;
        creds
    }

    #[must_use]
    pub fn with_keys(access_key: String, secret_key: String) -> Self {
        let mut creds = Self::default();
        creds.access_key = Some(access_key);
        creds.secret_key = Some(secret_key);
        creds
    }

    #[must_use]
    pub fn with_secret_key(secret_key: String) -> Self {
        let mut creds = Self::default();
        creds.secret_key = Some(secret_key);
        creds
    }

    #[must_use]
    pub fn with_password(password: Option<String>) -> Self {
        let mut creds = Self::default();
        creds.password = password;
        creds
    }
}

impl Drop for CloudCredentials {
    fn drop(&mut self) {
        if let Some(value) = self.token.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.refresh_token.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.client_id.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.client_secret.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.access_key.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.secret_key.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.password.as_mut() {
            value.zeroize();
        }
    }
}
