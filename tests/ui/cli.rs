use clap::{CommandFactory, Parser};
use cortex::ui::cli::{AccountAction, Cli, Commands, McpAction, TagAction, VaultAction};

fn parse(input: &[&str]) -> Result<Commands, clap::Error> {
    let mut words = vec!["cortex"];
    words.extend_from_slice(input);
    Cli::try_parse_from(words).map(|cli| cli.command)
}

#[test]
fn clap_definitions_are_internally_consistent() {
    Cli::command().debug_assert();
}

#[test]
fn pass_command_uses_documented_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Pass {
        length,
        count,
        uppercase,
        lowercase,
        digits,
        special,
    } = parse(&["pass"])?
    else {
        return Err("expected the pass command".into());
    };
    assert_eq!((length, count), (16, 1));
    assert!(!uppercase && !lowercase && !digits && !special);
    Ok(())
}

#[test]
fn pass_command_parses_short_flags_and_values() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Pass {
        length,
        count,
        uppercase,
        lowercase,
        digits,
        special,
    } = parse(&["pass", "-l", "24", "-c", "5", "-u", "-w", "-d", "-s"])?
    else {
        return Err("expected the pass command".into());
    };
    assert_eq!((length, count), (24, 5));
    assert!(uppercase && lowercase && digits && special);
    Ok(())
}

#[test]
fn vault_find_parses_pattern_and_flags() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Vault {
        action:
            VaultAction::Find {
                pattern,
                ignore_case,
                names_only,
            },
    } = parse(&["vault", "find", "^git", "-i", "-n"])?
    else {
        return Err("expected vault find".into());
    };
    assert_eq!(pattern, "^git");
    assert!(ignore_case);
    assert!(names_only);
    Ok(())
}

#[test]
fn vault_create_accepts_comma_separated_tags() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Vault {
        action: VaultAction::Create { name, tags },
    } = parse(&["vault", "create", "github", "-t", "work,dev"])?
    else {
        return Err("expected vault create".into());
    };
    assert_eq!(name, "github");
    assert_eq!(tags.as_deref(), Some("work,dev"));
    Ok(())
}

#[test]
fn vault_get_show_flag_is_optional() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Vault {
        action: VaultAction::Get { show, .. },
    } = parse(&["vault", "get", "bank"])?
    else {
        return Err("expected vault get".into());
    };
    assert!(!show);
    Ok(())
}

#[test]
fn tag_add_parses_entry_and_tags() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Vault {
        action: VaultAction::Tag {
            action: TagAction::Add { name, tags },
        },
    } = parse(&["vault", "tag", "add", "bank", "finance,urgent"])?
    else {
        return Err("expected vault tag add".into());
    };
    assert_eq!(name, "bank");
    assert_eq!(tags, "finance,urgent");
    Ok(())
}

#[test]
fn account_import_parses_overwrite_flag() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Account {
        action: AccountAction::Import { file, overwrite },
    } = parse(&["account", "import", "backup.csv", "--overwrite"])?
    else {
        return Err("expected account import".into());
    };
    assert_eq!(file, "backup.csv");
    assert!(overwrite);
    Ok(())
}

#[test]
fn account_edit_arguments_are_optional() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Account {
        action: AccountAction::Edit { name, new_name },
    } = parse(&["account", "edit"])?
    else {
        return Err("expected account edit".into());
    };
    assert!(name.is_none());
    assert!(new_name.is_none());
    Ok(())
}

#[test]
fn mcp_permission_mode_is_optional_for_viewing() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Mcp {
        action: McpAction::Permission { mode },
    } = parse(&["mcp", "permission"])?
    else {
        return Err("expected mcp permission".into());
    };
    assert!(mode.is_none());
    Ok(())
}

#[test]
fn mcp_remove_parses_purge_flag() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Mcp {
        action: McpAction::Remove { purge_accounts },
    } = parse(&["mcp", "remove", "--purge-accounts"])?
    else {
        return Err("expected mcp remove".into());
    };
    assert!(purge_accounts);
    Ok(())
}

#[test]
fn malformed_invocations_are_rejected() {
    assert!(parse(&["vault", "get"]).is_err());
    assert!(parse(&["pass", "--unknown"]).is_err());
    assert!(parse(&["pass", "-l", "not-a-number"]).is_err());
    assert!(parse(&["bogus"]).is_err());
}
