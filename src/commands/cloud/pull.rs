use super::resolve_account;
use crate::{
    cloud::{
        client::CloudClient,
        config::{CloudConfig, SyncRecord},
        engine::SyncEngine,
    },
    core::{accounts::Accounts, crypto::Crypto, dump::Dump, storage::Storage, time::Time},
    modules::{security::Security, session::Session},
    ui::prompt::UserPrompt,
};

pub fn execute(
    remote_name: Option<&str>,
    account: Option<String>,
    overwrite: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = CloudConfig::load()?;
    let remote = config.resolve_remote(remote_name)?.clone();
    let account_name = resolve_account(account)?;

    let client = CloudClient::connect(&remote)?;
    let Some(remote_bytes) = client.pull(&account_name)? else {
        return Err(format!(
            "No vault found for account '{account_name}' on remote '{}'.",
            remote.name
        )
        .into());
    };

    let dump_file = Dump::decode(&remote_bytes)?;
    let password = UserPrompt::password(&format!(
        "Master password for cloud vault '{account_name}': "
    ))?;
    let crypto = Crypto::open(&password, &dump_file.salt)?;
    let snapshot = Storage::read_dump(&dump_file, &crypto)?;

    let local_exists = Accounts::exists(&account_name)?;
    if local_exists && !overwrite {
        Security::confirmation(&format!(
            "This will replace local account '{account_name}' with the cloud version ({} entries).",
            snapshot.user_count()
        ))?;
    }

    let storage = Storage::open_account(&account_name)?;
    storage.replace_with_dump(&snapshot)?;
    storage.bind_integrity(&crypto);
    storage.verify_integrity()?;
    drop(storage);

    if !local_exists {
        Accounts::register(&account_name)?;
    }

    if Accounts::active()?.as_deref() == Some(account_name.as_str()) {
        Session::clear_session()?;
    }

    let remote_hash = SyncEngine::digest(&remote_bytes);
    config.record_sync(
        &remote.name,
        &account_name,
        SyncRecord {
            last_sync_timestamp: Time::current_timestamp(),
            last_synced_hash: remote_hash,
            entry_count: snapshot.user_count(),
        },
    )?;

    if local_exists {
        println!(
            "Updated local account '{account_name}' ({} entries) from '{}'.",
            snapshot.user_count(),
            remote.name
        );
    } else {
        println!(
            "Imported and registered account '{account_name}' ({} entries) from '{}'.",
            snapshot.user_count(),
            remote.name
        );
    }

    Ok(())
}
