use crate::core::gateway::Gateway;

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let (storage, crypto) = Gateway::login()?;
    let path = storage.create_dump(&crypto)?;

    println!("Dump saved to: {}", path.display());
    println!(
        "The dump is encrypted. Restoring it later requires the master password that is active now."
    );

    Ok(())
}
