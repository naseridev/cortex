pub mod create;
pub mod delete;
pub mod edit;
pub mod find;
pub mod get;
pub mod list;
pub mod lock;
pub mod tag;

use crate::ui::cli::VaultAction;

pub fn run(action: VaultAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        VaultAction::Create { name, tags } => create::execute(&name, tags),
        VaultAction::Get { name, show } => get::execute(&name, show),
        VaultAction::Edit { name, tags } => edit::execute(&name, tags),
        VaultAction::Delete { name } => delete::execute(&name),
        VaultAction::List { show_tags } => list::execute(show_tags),
        VaultAction::Find {
            pattern,
            ignore_case,
            names_only,
        } => find::execute(&pattern, ignore_case, names_only),
        VaultAction::Tag { action } => tag::run(action),
        VaultAction::Lock => lock::execute(),
    }
}
