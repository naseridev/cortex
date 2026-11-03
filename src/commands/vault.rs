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
        VaultAction::Create { name, tags } => create::Create::execute(&name, tags),
        VaultAction::Get { name, show } => get::Get::execute(&name, show),
        VaultAction::Edit { name, tags } => edit::Edit::execute(&name, tags),
        VaultAction::Delete { name } => delete::Delete::execute(&name),
        VaultAction::List { show_tags } => list::List::execute(show_tags),
        VaultAction::Find {
            pattern,
            ignore_case,
            names_only,
        } => find::Find::execute(&pattern, ignore_case, names_only),
        VaultAction::Tag { action } => tag::run(action),
        VaultAction::Lock => lock::Lock::execute(),
    }
}
