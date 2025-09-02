use crate::{
    core::{crypto::Crypto, storage::Storage, time::Time, types::PasswordEntry},
    ui::prompt::UserPrompt,
    utils::security::Security,
};
use std::{fs::File, io::BufWriter, path::PathBuf, process};

pub struct Export;

impl Export {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        if !Storage::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;

        let crypto = Crypto::new(&master_password);
        let storage = Storage::new()?;

        let result = match storage.get_init_marker()? {
            Some(entry) => crypto.verify_test_data(&entry),
            None => false,
        };

        if !result {
            return Err("Authentication failed".into());
        }

        let (puzzle, answer) = Security::generate_math_puzzle();

        println!();
        println!("WARNING: This will export all passwords in plain text format.");
        println!("Solve this equation to confirm: {}", puzzle);
        println!();

        let user_answer = UserPrompt::text("Answer: ")?;
        let user_num: i64 = user_answer.as_str().parse().map_err(|_| "Invalid number")?;

        if user_num != answer {
            println!("Wrong answer. Export cancelled.");
            return Ok(());
        }

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
