use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

pub fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    restrict_to_owner(&mut options);
    options.open(path)
}

#[cfg(unix)]
fn restrict_to_owner(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn restrict_to_owner(_options: &mut OpenOptions) {}
