use crate::{
    core::{time::Time, types::PasswordEntry},
    modules::gateway::Gateway,
    utils::security::Security,
};
use std::{fs::File, io::BufWriter, path::PathBuf};

pub struct Export;

impl Export {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        let warning_message = "This will export all passwords in plain text format.";
        Security::confirmation(warning_message)?;

        let filename = format!("cortex_export_{:x}.dat", Time::current_timestamp());
        let output_path = PathBuf::from(&filename);

        let file = File::create(&output_path)?;
        let mut writer = BufWriter::with_capacity(64 * 1024, file);

        let process_entry =
            |name: &str, entry: &PasswordEntry| -> Result<String, Box<dyn std::error::Error>> {
                let decrypted_bytes = crypto.decrypt_entry(entry)?;
                let password = String::from_utf8(decrypted_bytes)?;
                let description = crypto.decrypt_description(entry)?;

                let mut output = format!("Name: {}\nPassword: {}", name, password);

                if let Some(desc) = description {
                    output.push_str(&format!("\nDescription: {}", desc));
                }

                output.push('\n');
                Ok(output)
            };

        let (processed, failed) = storage.export_entries(&mut writer, process_entry)?;

        if failed > 0 {
            eprintln!(
                "Export completed with {} successful and {} failed entries",
                processed - failed,
                failed
            );
        } else {
            eprintln!("Export completed successfully with {} entries", processed);
        }

        if processed - failed > 0 {
            println!("Export completed to {}", output_path.display());
        } else {
            let _ = std::fs::remove_file(&output_path);
        }

        Ok(())
    }
}
