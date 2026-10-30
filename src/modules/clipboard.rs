use copypasta::{ClipboardContext, ClipboardProvider};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;
use zeroize::Zeroize;

pub struct Clipboard;

impl Clipboard {
    pub fn copy(text: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx =
            ClipboardContext::new().map_err(|e| format!("Failed to initialize clipboard: {e}"))?;
        ctx.set_contents(text.to_owned())
            .map_err(|e| format!("Failed to copy to clipboard: {e}"))?;

        Ok(())
    }

    #[must_use]
    pub fn clear(seconds: u64, original_password: &str) -> bool {
        let mut password_copy = original_password.to_string();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_clone = Arc::clone(&cancelled);

        ctrlc::set_handler(move || {
            cancelled_clone.store(true, Ordering::SeqCst);
        })
        .ok();

        let total_ticks = seconds.saturating_mul(10);
        for _ in 0..total_ticks {
            if cancelled.load(Ordering::SeqCst) {
                if let Ok(mut ctx) = ClipboardContext::new() {
                    let _ = ctx.set_contents(String::new());
                }
                password_copy.zeroize();
                return true;
            }
            thread::sleep(Duration::from_millis(100));
        }

        let mut cleared = false;
        if let Ok(mut ctx) = ClipboardContext::new() {
            if let Ok(mut current_clipboard) = ctx.get_contents() {
                if current_clipboard == password_copy {
                    cleared = ctx.set_contents(String::new()).is_ok();
                } else {
                    cleared = true;
                }
                current_clipboard.zeroize();
            } else {
                cleared = ctx.set_contents(String::new()).is_ok();
            }
        }

        password_copy.zeroize();
        cleared
    }
}
