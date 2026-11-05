use arboard::Clipboard;
use std::{sync::mpsc, time::Duration};
use zeroize::Zeroize;

pub struct PasswordClipboard;

impl PasswordClipboard {
    pub fn copy_then_clear(text: &str, seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut clipboard = Clipboard::new().map_err(|error| {
            format!(
                "Clipboard is not available: {error}. Use --show to print the password instead."
            )
        })?;

        clipboard
            .set_text(text)
            .map_err(|error| format!("Failed to copy the password: {error}"))?;

        let (interrupt_sender, interrupt_receiver) = mpsc::channel();
        ctrlc::set_handler(move || {
            let _ = interrupt_sender.send(());
        })
        .map_err(|error| format!("Failed to install the Ctrl+C handler: {error}"))?;

        println!(
            "Password copied to the clipboard. It will be cleared in {seconds} seconds. Press Ctrl+C to clear it now and exit."
        );
        let _ = interrupt_receiver.recv_timeout(Duration::from_secs(seconds));

        if let Ok(mut current) = clipboard.get_text() {
            let matches = current == text;
            current.zeroize();
            if matches {
                clipboard
                    .set_text("")
                    .map_err(|error| format!("Failed to clear the clipboard: {error}"))?;
            }
        }

        Ok(())
    }
}
