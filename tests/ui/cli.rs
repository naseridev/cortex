use clap::{CommandFactory, Parser};
use cortex::ui::cli::{AccountAction, Cli, Commands, McpAction, TagAction, VaultAction};

fn parse(args: &[&str]) -> Result<Commands, clap::Error> {
    let mut argv = vec!["cortex"];
    argv.extend_from_slice(args);
    Cli::try_parse_from(argv).map(|cli| cli.command)
}

#[test]
fn clap_definitions_are_internally_consistent() {
    Cli::command().debug_assert();
}

#[test]
fn pass_command_uses_documented_defaults() -> Result<(), clap::Error> {
    let Commands::Pass {
        length,
        count,
        uppercase,
        lowercase,
        digits,
        special,
    } = parse(&["pass"])?
    else {
        panic!("expected the pass command");
    };
    assert_eq!((length, count), (16, 1));
    assert!(!uppercase && !lowercase && !digits && !special);
    Ok(())
}

#[test]
fn pass_command_parses_short_flags_and_values() -> Result<(), clap::Error> {
    let Commands::Pass {
        length,
        count,
        uppercase,
        lowercase,
        digits,
        special,
    } = parse(&["pass", "-l", "24", "-c", "5", "-u", "-w", "-d", "-s"])?
    else {
        panic!("expected the pass command");
    };
    assert_eq!((length, count), (24, 5));
    assert!(uppercase && lowercase && digits && special);
    Ok(())
}

#[test]
fn vault_find_parses_pattern_and_flags() -> Result<(), clap::Error> {
    let Commands::Vault {
        action:
            VaultAction::Find {
                pattern,
                ignore_case,
                names_only,
            },
    } = parse(&["vault", "find", "^git", "-i", "-n"])?
    else {
        panic!("expected vault find");
    };
    assert_eq!(pattern, "^git");
    assert!(ignore_case);
    assert!(names_only);
    Ok(())
}

#[test]
fn vault_create_accepts_comma_separated_tags() -> Result<(), clap::Error> {
    let Commands::Vault {
        action: VaultAction::Create { name, tags },
    } = parse(&["vault", "create", "github", "-t", "work,dev"])?
    else {
        panic!("expected vault create");
    };
    assert_eq!(name, "github");
    assert_eq!(tags.as_deref(), Some("work,dev"));
    Ok(())
}

#[test]
fn vault_get_show_flag_is_optional() -> Result<(), clap::Error> {
    let Commands::Vault {
        action: VaultAction::Get { show, .. },
    } = parse(&["vault", "get", "bank"])?
    else {
        panic!("expected vault get");
    };
    assert!(!show);
    Ok(())
}

#[test]
fn tag_add_parses_entry_and_tags() -> Result<(), clap::Error> {
    let Commands::Vault {
        action: VaultAction::Tag {
            action: TagAction::Add { name, tags },
        },
    } = parse(&["vault", "tag", "add", "bank", "finance,urgent"])?
    else {
        panic!("expected vault tag add");
    };
    assert_eq!(name, "bank");
    assert_eq!(tags, "finance,urgent");
    Ok(())
}

#[test]
fn account_import_parses_overwrite_flag() -> Result<(), clap::Error> {
    let Commands::Account {
        action: AccountAction::Import { file, overwrite },
    } = parse(&["account", "import", "backup.csv", "--overwrite"])?
    else {
        panic!("expected account import");
    };
    assert_eq!(file, "backup.csv");
    assert!(overwrite);
    Ok(())
}

#[test]
fn account_edit_arguments_are_optional() -> Result<(), clap::Error> {
    let Commands::Account {
        action: AccountAction::Edit { name, new_name },
    } = parse(&["account", "edit"])?
    else {
        panic!("expected account edit");
    };
    assert!(name.is_none());
    assert!(new_name.is_none());
    Ok(())
}

#[test]
fn mcp_permission_mode_is_optional_for_viewing() -> Result<(), clap::Error> {
    let Commands::Mcp {
        action: McpAction::Permission { mode },
    } = parse(&["mcp", "permission"])?
    else {
        panic!("expected mcp permission");
    };
    assert!(mode.is_none());
    Ok(())
}

#[test]
fn mcp_remove_parses_purge_flag() -> Result<(), clap::Error> {
    let Commands::Mcp {
        action: McpAction::Remove { purge_accounts },
    } = parse(&["mcp", "remove", "--purge-accounts"])?
    else {
        panic!("expected mcp remove");
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
