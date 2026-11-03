#[cfg(unix)]
mod unix {
    use cortex::modules::platform::Platform;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn mode_of(path: &std::path::Path) -> Result<u32, Box<dyn std::error::Error>> {
        Ok(fs::metadata(path)?.permissions().mode() & 0o777)
    }

    #[test]
    fn private_files_are_created_owner_only_and_never_overwritten()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("secret.bin");

        drop(Platform::create_private_file(&path)?);
        assert_eq!(mode_of(&path)?, 0o600);

        let second = Platform::create_private_file(&path);
        assert!(second.is_err());
        Ok(())
    }

    #[test]
    fn restrict_to_owner_sets_owner_only_modes_for_files_and_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let file = dir.path().join("open.txt");
        fs::write(&file, b"data")?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644))?;

        Platform::restrict_to_owner(&file)?;
        assert_eq!(mode_of(&file)?, 0o600);

        let folder = dir.path().join("folder");
        fs::create_dir(&folder)?;
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o755))?;

        Platform::restrict_to_owner(&folder)?;
        assert_eq!(mode_of(&folder)?, 0o700);
        Ok(())
    }
}
