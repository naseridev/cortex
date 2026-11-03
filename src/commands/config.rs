pub mod set_timeout;
pub mod show;

use crate::ui::cli::ConfigAction;

pub fn run(action: Option<ConfigAction>) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        Some(ConfigAction::SetTimeout { seconds }) => set_timeout::execute(seconds),
        Some(ConfigAction::Show) | None => show::execute(),
    }
}

fn describe_timeout(seconds: u64) -> String {
    format!("{seconds} seconds ({} minutes)", seconds / 60)
}
