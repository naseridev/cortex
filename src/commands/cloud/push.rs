use super::resolve_account;
use crate::{
    cloud::{
        client::CloudClient,
        config::{CloudConfig, SyncRecord},
        engine::SyncEngine,
    },
    core::time::Time,
    modules::gateway::Gateway,
};

pub fn execute(
    remote_name: Option<&str>,
    account: Option<String>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = CloudConfig::load()?;
    let remote = config.resolve_remote(remote_name)?.clone();
    let account_name = resolve_account(account)?;

    let (storage, crypto) = Gateway::login_account(&account_name)?;
    let local_entries = storage.list_entries()?;
    let dump_bytes = storage.encode_dump(&crypto)?;
    let local_hash = SyncEngine::digest(&dump_bytes);

    let client = CloudClient::connect(&remote)?;

    if !force && let Some(remote_bytes) = client.pull(&account_name)? {
        let remote_hash = SyncEngine::digest(&remote_bytes);
        if remote_hash == local_hash {
            println!(
                "Account '{account_name}' on remote '{}' is already up to date.",
                remote.name
            );
            return Ok(());
        }

        if let Some(record) = remote.accounts.get(&account_name)
            && record.last_synced_hash != remote_hash
            && record.last_synced_hash != [0u8; 32]
        {
            return Err(
                "Remote vault has changed since last sync. Run 'cortex cloud sync' to merge changes or pass --force to overwrite."
                    .into(),
            );
        }
    }

    client.push(&account_name, &dump_bytes)?;

    config.record_sync(
        &remote.name,
        &account_name,
        SyncRecord {
            last_sync_timestamp: Time::current_timestamp(),
            last_synced_hash: local_hash,
            entry_count: local_entries.len(),
        },
    )?;

    println!(
        "Uploaded vault for account '{account_name}' ({} entries) to '{}'.",
        local_entries.len(),
        remote.name
    );

    Ok(())
}
