use crate::{
    core::{time::Time, types::PasswordEntry},
    modules::gateway::Gateway,
    utils::security::Security,
};
use serde::Serialize;
use std::{fs::File, io::BufWriter, io::Write, path::PathBuf};

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
    tags: Vec<String>,
}

pub struct Export;

impl Export {
    pub fn new(template: bool) -> Result<(), Box<dyn std::error::Error>> {
        if template {
            return Self::export_template();
        }

        let (storage, crypto) = Gateway::login()?;

        println!("\nThis will export ALL passwords in PLAIN TEXT format!");
        println!("Anyone with access to this file can read your passwords.");

        let warning_message = "I understand this exports passwords in plain text";
        Security::confirmation(warning_message)?;

        let filename = format!("cortex_export_{:x}.json", Time::current_timestamp());
        let output_path = PathBuf::from(&filename);
        let file = File::create(&output_path)?;
        let mut writer = BufWriter::with_capacity(64 * 1024, file);

        let mut entries = Vec::new();
        let mut processed = 0;
        let mut failed = 0;

        for item in storage.db.iter().filter_map(Result::ok) {
            let (key, value) = item;

            let key_str = String::from_utf8_lossy(&key);
            if key_str.starts_with("__") {
                continue;
            }

            processed += 1;
            let name = key_str.to_string();

            match bincode::deserialize::<PasswordEntry>(&value) {
                Ok(entry) => match crypto.decrypt_entry(&entry) {
                    Ok(decrypted_bytes) => match String::from_utf8(decrypted_bytes) {
                        Ok(password) => {
                            let description = crypto.decrypt_description(&entry).ok().flatten();
                            let tags = crypto.decrypt_tags(&entry).unwrap_or_default();
                            entries.push(ExportEntry {
                                name,
                                password,
                                description,
                                tags,
                            });
                        }
                        Err(_) => {
                            eprintln!("Failed to decode password for: {}", name);
                            failed += 1;
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to decrypt entry '{}': {}", name, e);
                        failed += 1;
                    }
                },
                Err(e) => {
                    eprintln!("Failed to deserialize entry '{}': {}", name, e);
                    failed += 1;
                }
            }
        }

        let export_data = ExportData {
            version: "2.1.0".to_string(),
            timestamp: Time::current_timestamp(),
            entries,
        };

        serde_json::to_writer_pretty(&mut writer, &export_data)?;
        writer.flush()?;

        #[cfg(unix)]
        {
            use std::fs;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600))?;
        }

        if failed > 0 {
            eprintln!(
                "\nExport completed with {} successful and {} failed entries",
                processed - failed,
                failed
            );
        } else {
            eprintln!("\nExport completed successfully with {} entries", processed);
        }

        if processed - failed > 0 {
            println!("\nExport saved to: {}", output_path.display());
            println!("\nREMEMBER: This file contains UNENCRYPTED passwords!");
            println!("Secure or delete it immediately after use.");
        } else {
            std::fs::remove_file(&output_path)?;
            println!("No entries were successfully exported.");
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
                name: "heisenberg".to_string(),
                password: "1AmTh3D4ng3r!".to_string(),
                description: Some("Say my name - I am the one who knocks".to_string()),
                tags: vec!["work".to_string(), "critical".to_string()],
            },
            ExportEntry {
                name: "los-pollos".to_string(),
                password: "Gustu5Fr!ng2024".to_string(),
                description: Some("A man provides for his family".to_string()),
                tags: vec!["business".to_string(), "finance".to_string()],
            },
            ExportEntry {
                name: "saul-goodman".to_string(),
                password: "B3tt3rC4llS4ul!".to_string(),
                description: Some(
                    "Did you know you have rights? Constitution says you do".to_string(),
                ),
                tags: vec!["legal".to_string(), "contacts".to_string()],
            },
        ];

        let template_data = ExportData {
            version: "2.1.0".to_string(),
            timestamp: Time::current_timestamp(),
            entries: sample_entries,
        };

        serde_json::to_writer_pretty(writer, &template_data)?;
        println!("Template exported to {}", output_path.display());
        println!("\nYou can use this template structure to import passwords.");

        Ok(())
    }
}
