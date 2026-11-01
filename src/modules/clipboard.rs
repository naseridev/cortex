use arboard::Clipboard;
use std::{thread, time::Duration};

pub fn copy_then_clear(text: &str, seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
    let mut clipboard = Clipboard::new().map_err(|error| {
        format!("Clipboard is not available: {error}. Use --show to print the password instead.")
    })?;
    clipboard
        .set_text(text)
        .map_err(|error| format!("Failed to copy the password: {error}"))?;
    println!("Password copied to the clipboard. It will be cleared in {seconds} seconds.");
    thread::sleep(Duration::from_secs(seconds));
    if let Ok(current) = clipboard.get_text()
        && current == text
    {
        clipboard
            .set_text("")
            .map_err(|error| format!("Failed to clear the clipboard: {error}"))?;
    }
    Ok(())
}
