use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

pub struct Platform;

impl Platform {
    pub fn create_private_file(path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();

        options.write(true).create_new(true);
        Self::set_private_creation_mode(&mut options);

        let file = options.open(path)?;

        if let Err(error) = Self::restrict_to_owner(path) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(error);
        }

        Ok(file)
    }

    #[cfg(unix)]
    fn set_private_creation_mode(options: &mut OpenOptions) {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    #[cfg(not(unix))]
    fn set_private_creation_mode(_options: &mut OpenOptions) {}

    #[cfg(all(unix, target_os = "macos"))]
    pub fn config_dir() -> Option<PathBuf> {
        std::env::home_dir().map(|home| home.join("Library/Application Support"))
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    pub fn config_dir() -> Option<PathBuf> {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| std::env::home_dir().map(|home| home.join(".config")))
    }

    #[cfg(windows)]
    pub fn config_dir() -> Option<PathBuf> {
        std::env::var_os("APPDATA")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }

    #[cfg(not(any(unix, windows)))]
    pub fn config_dir() -> Option<PathBuf> {
        None
    }

    #[cfg(unix)]
    pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o700 } else { 0o600 };

        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    #[cfg(windows)]
    pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
        use std::process::{Command, Stdio};

        let user =
            std::env::var("USERNAME").map_err(|_| io::Error::other("USERNAME is not set"))?;
        let account = match std::env::var("USERDOMAIN") {
            Ok(domain) if !domain.is_empty() => format!("{domain}\\{user}"),
            _ => user,
        };

        let rights = if path.is_dir() { "(OI)(CI)F" } else { "F" };
        let status = Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{account}:{rights}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Failed to restrict permissions on {}",
                path.display()
            )))
        }
    }

    #[cfg(not(any(unix, windows)))]
    pub fn restrict_to_owner(_path: &Path) -> io::Result<()> {
        Ok(())
    }
}
