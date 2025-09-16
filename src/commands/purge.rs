use crate::{
    core::{crypto::Crypto, storage::Storage},
    ui::prompt::UserPrompt,
    utils::security::Security,
};
use std::process;

pub struct Purge;

impl Purge {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        if !Storage::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let mut failure = 0;

        let storage = loop {
            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::new(&master_password);
            let storage_attempt = Storage::new()?;

            let is_correct = match storage_attempt.get_init_marker()? {
                Some(entry) => crypto.verify_test_data(&entry),
                None => false,
            };

            if is_correct {
                break storage_attempt;
            } else if failure > 1 {
                return Err("Authentication failed".into());
            } else {
                eprintln!("Sorry, try again.\n");
                failure += 1;
            }
        };

        println!();
        println!("WARNING: This will permanently delete all stored passwords!");
        println!();

        let (puzzle, answer) = Security::generate_math_puzzle();
        println!("Solve this equation to confirm: {}", puzzle);

        let user_answer = UserPrompt::text("Answer: ")?;
        let user_num: i64 = user_answer.as_str().parse().map_err(|_| "Invalid number")?;

        if user_num != answer {
            println!("Wrong answer. Destruction cancelled.");
            return Ok(());
        }

        let _ = storage.purge_database();
        println!("Database purged.");

        Ok(())
    }
}
