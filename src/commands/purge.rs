use crate::{
    core::{crypto::Crypto, storage::Storage},
    modules::validation::Validation,
    ui::prompt::UserPrompt,
    utils::confirmation::Confirmation,
};

pub struct Purge;

impl Purge {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        Validation::storage_existence_probe()?;

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

        let warning_message = "This will permanently delete all stored passwords!";
        let purge_confirmation = Confirmation::require_math_puzzle(warning_message)?;

        if !purge_confirmation {
            println!("Wrong answer. Destruction cancelled.");
            return Ok(());
        }

        storage.purge_database()?;
        println!("Database purged.");

        Ok(())
    }
}
