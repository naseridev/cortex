use super::resolve_account;
use crate::{
    cloud::{client::CloudClient, config::CloudConfig, engine::SyncEngine},
    core::accounts::Accounts,
};

pub fn execute(
    remote_name: Option<&str>,
    account: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = CloudConfig::load()?;
    let remote = config.resolve_remote(remote_name)?;
    let account_name = resolve_account(account)?;

    let local_exists = Accounts::exists(&account_name)?;
    let client = CloudClient::connect(remote)?;
    let remote_blob = client.pull(&account_name)?;

    println!("\nCloud Sync Status:");
    println!("  Remote: {} ({})", remote.name, remote.settings.summary());
    println!("  Account: {account_name}");
    println!(
        "  Local vault: {}",
        if local_exists { "present" } else { "missing" }
    );
    println!(
        "  Remote vault: {}",
        if remote_blob.is_some() {
            "present"
        } else {
            "missing"
        }
    );

    if let Some(record) = remote.accounts.get(&account_name) {
        println!("  Last sync timestamp: {}", record.last_sync_timestamp);
        println!("  Last synced entries: {}", record.entry_count);

        if let Some(bytes) = &remote_blob {
            let remote_hash = SyncEngine::digest(bytes);
            if remote_hash == record.last_synced_hash {
                println!("  Remote state: unchanged since last sync");
            } else {
                println!("  Remote state: modified since last sync");
            }
        }
    } else {
        println!("  Last sync: never");
    }

    Ok(())
}
