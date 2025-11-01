use copypasta::{ClipboardContext, ClipboardProvider};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

pub struct Clipboard;

impl Clipboard {
    pub fn copy(text: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx = ClipboardContext::new()
            .map_err(|e| format!("Failed to initialize clipboard: {}", e))?;
        ctx.set_contents(text.to_owned())
            .map_err(|e| format!("Failed to copy to clipboard: {}", e))?;

        Ok(())
    }

    pub fn clear(seconds: u64, original_password: &str) -> bool {
        let password_copy = original_password.to_string();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_clone = Arc::clone(&cancelled);

        ctrlc::set_handler(move || {
            cancelled_clone.store(true, Ordering::SeqCst);
        })
        .ok();

        for _ in 0..seconds {
            if cancelled.load(Ordering::SeqCst) {
                if let Ok(mut ctx) = ClipboardContext::new() {
                    let _ = ctx.set_contents(" ".to_owned());
                }
                return false;
            }
            thread::sleep(Duration::from_secs(1));
        }

        if let Ok(mut ctx) = ClipboardContext::new() {
            if let Ok(current_clipboard) = ctx.get_contents() {
                if current_clipboard == password_copy {
                    if ctx.set_contents(" ".to_owned()).is_ok() {
                        return true;
                    }
                }
            }
        }

        false
    }
}
