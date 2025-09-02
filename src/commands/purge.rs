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
