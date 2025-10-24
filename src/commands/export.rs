use crate::{
    core::{time::Time, types::PasswordEntry},
    modules::gateway::Gateway,
    utils::security::Security,
};
use serde::Serialize;
use std::{fs::File, io::BufWriter, path::PathBuf};

#[derive(Serialize)]
struct ExportData {
    version: String,
    timestamp: u64,
    entries: Vec<ExportEntry>,
}

#[derive(Serialize)]
struct ExportEntry {
    name: String,
    password: String,
    description: Option<String>,
}

pub struct Export;

impl Export {
    pub fn new(template: bool) -> Result<(), Box<dyn std::error::Error>> {
        if template {
            return Self::export_template();
        }

        let (storage, crypto) = Gateway::login()?;
        let warning_message = "This will export all passwords in plain text JSON format.";
        Security::confirmation(warning_message)?;

        let filename = format!("cortex_export_{:x}.json", Time::current_timestamp());
        let output_path = PathBuf::from(&filename);
        let file = File::create(&output_path)?;
        let writer = BufWriter::with_capacity(64 * 1024, file);

        let mut entries = Vec::new();
        let mut processed = 0;
        let mut failed = 0;

        for item in storage.db.iter() {
            let (key, value) = match item {
                Ok((k, v)) => (k, v),
                Err(_) => continue,
            };

            let key_str = String::from_utf8_lossy(&key);
            if key_str.starts_with("__") {
                continue;
            }

            processed += 1;

            match bincode::deserialize::<PasswordEntry>(&value) {
                Ok(entry) => match crypto.decrypt_entry(&entry) {
                    Ok(decrypted_bytes) => match String::from_utf8(decrypted_bytes) {
                        Ok(password) => {
                            let description = crypto.decrypt_description(&entry).ok().flatten();
                            entries.push(ExportEntry {
                                name: key_str.to_string(),
                                password,
                                description,
                            });
                        }
                        Err(_) => failed += 1,
                    },
                    Err(_) => failed += 1,
                },
                Err(_) => failed += 1,
            }
        }

        let export_data = ExportData {
            version: "2.0.0".to_string(),
            timestamp: Time::current_timestamp(),
            entries,
        };

        serde_json::to_writer_pretty(writer, &export_data)?;

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
            std::fs::remove_file(&output_path)?;
        }

        Ok(())
    }

    fn export_template() -> Result<(), Box<dyn std::error::Error>> {
        let filename = "cortex_template.json";
        let output_path = PathBuf::from(filename);
        let file = File::create(&output_path)?;
        let writer = BufWriter::new(file);

        let sample_entries = vec![
            ExportEntry {
                name: "github".to_string(),
                password: "MySecurePassword123!".to_string(),
                description: Some("GitHub account credentials".to_string()),
            },
            ExportEntry {
                name: "gmail".to_string(),
                password: "AnotherPassword456@".to_string(),
                description: Some("Personal email account".to_string()),
            },
            ExportEntry {
                name: "work-vpn".to_string(),
                password: "VpnPass789#".to_string(),
                description: None,
            },
        ];

        let template_data = ExportData {
            version: "2.0.0".to_string(),
            timestamp: Time::current_timestamp(),
            entries: sample_entries,
        };

        serde_json::to_writer_pretty(writer, &template_data)?;
        println!("Template exported to {}", output_path.display());
        println!("\nYou can use this template structure to import passwords.");

        Ok(())
    }
}
