use clap::{CommandFactory, Parser};
use cortex::ui::cli::{
    AccountAction, Cli, CloudAction, CloudProvider, Commands, TagAction, VaultAction,
};

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
fn cloud_providers_parse_all_supported_backends() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Cloud {
        action:
            CloudAction::Add {
                provider: CloudProvider::Nextcloud { url, username, .. },
            },
    } = parse(&[
        "cloud",
        "add",
        "nextcloud",
        "--url",
        "https://cloud.example.com",
        "-u",
        "alice",
    ])?
    else {
        return Err("expected cloud add nextcloud".into());
    };
    assert_eq!(url, "https://cloud.example.com");
    assert_eq!(username.as_deref(), Some("alice"));

    let Commands::Cloud {
        action:
            CloudAction::Add {
                provider: CloudProvider::Gdrive { name, .. },
            },
    } = parse(&["cloud", "add", "gdrive"])?
    else {
        return Err("expected cloud add gdrive".into());
    };
    assert!(name.is_none());

    let Commands::Cloud {
        action:
            CloudAction::Add {
                provider: CloudProvider::Dropbox { name, .. },
            },
    } = parse(&["cloud", "add", "dropbox", "-n", "dbx"])?
    else {
        return Err("expected cloud add dropbox".into());
    };
    assert_eq!(name.as_deref(), Some("dbx"));

    let Commands::Cloud {
        action:
            CloudAction::Add {
                provider: CloudProvider::Onedrive { name, .. },
            },
    } = parse(&["cloud", "add", "onedrive"])?
    else {
        return Err("expected cloud add onedrive".into());
    };
    assert!(name.is_none());

    let Commands::Cloud {
        action:
            CloudAction::Add {
                provider: CloudProvider::S3 { bucket, region, .. },
            },
    } = parse(&["cloud", "add", "s3", "--bucket", "vaults"])?
    else {
        return Err("expected cloud add s3".into());
    };
    assert_eq!(bucket, "vaults");
    assert_eq!(region, "us-east-1");

    let Commands::Cloud {
        action:
            CloudAction::Add {
                provider: CloudProvider::Webdav { url, .. },
            },
    } = parse(&["cloud", "add", "webdav", "--url", "https://dav.example.com"])?
    else {
        return Err("expected cloud add webdav".into());
    };
    assert_eq!(url, "https://dav.example.com");

    Ok(())
}

#[test]
fn cloud_sync_parses_optional_remote_and_account() -> Result<(), Box<dyn std::error::Error>> {
    let Commands::Cloud {
        action: CloudAction::Sync { remote, account },
    } = parse(&["cloud", "sync", "-r", "nextcloud", "-a", "work"])?
    else {
        return Err("expected cloud sync".into());
    };
    assert_eq!(remote.as_deref(), Some("nextcloud"));
    assert_eq!(account.as_deref(), Some("work"));
    Ok(())
}

#[test]
fn malformed_invocations_are_rejected() {
    assert!(parse(&["vault", "get"]).is_err());
    assert!(parse(&["pass", "--unknown"]).is_err());
    assert!(parse(&["pass", "-l", "not-a-number"]).is_err());
    assert!(parse(&["bogus"]).is_err());
}
