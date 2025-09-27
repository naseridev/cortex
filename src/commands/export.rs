use crate::{
    core::{crypto::Crypto, storage::Storage, time::Time, types::PasswordEntry},
    modules::validation::Validation,
    ui::prompt::UserPrompt,
    utils::security::Security,
};
use std::{fs::File, io::BufWriter, path::PathBuf};

pub struct Export;

impl Export {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        Validation::storage_existence_probe()?;

        let mut failure = 0;

        let (storage, crypto) = loop {
            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::new(&master_password);
            let storage_attempt = Storage::new()?;

            let is_correct = match storage_attempt.get_init_marker()? {
                Some(entry) => crypto.verify_test_data(&entry),
                None => false,
            };

            if is_correct {
                break (storage_attempt, crypto);
            } else if failure > 1 {
                return Err("Authentication failed".into());
            } else {
                eprintln!("Sorry, try again.\n");
                failure += 1;
            }
        };

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
