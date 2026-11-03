pub mod create;
pub mod delete;
pub mod edit;
pub mod list;
pub mod reset;
pub mod switch;

use crate::ui::{cli::AccountAction, prompt::UserPrompt};

pub fn run(action: AccountAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        AccountAction::Create { name } => create::execute(name),
        AccountAction::List => list::execute(),
        AccountAction::Edit { name, new_name } => edit::execute(name, new_name),
        AccountAction::Delete { name } => delete::execute(name),
        AccountAction::Switch { name } => switch::execute(name),
        AccountAction::Reset { name } => reset::execute(name),
    }
}

fn resolve_name(
    provided: Option<String>,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match provided {
        Some(name) => Ok(name.trim().to_string()),
        None => UserPrompt::text(prompt),
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_name;

    #[test]
    fn provided_name_is_trimmed_without_prompting() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            resolve_name(Some("  work  ".to_string()), "Account name: ")?,
            "work"
        );
        Ok(())
    }
}
