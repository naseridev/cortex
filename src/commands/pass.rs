use crate::modules::password::Password;
use std::process;

pub struct Pass;

impl Pass {
    pub fn new(
        length: usize,
        count: usize,
        uppercase: bool,
        lowercase: bool,
        digits: bool,
        special: bool,
        no_ambiguous: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if length < 4 {
            eprintln!("Error: Password length must be at least 4 characters.");
            process::exit(1);
        }

        if length > 128 {
            eprintln!("Error: Password length too long (max 128 chars).");
            process::exit(1);
        }

        if count < 1 || count > 50 {
            eprintln!("Error: Count must be between 1 and 50.");
            process::exit(1);
        }

        if !uppercase && !lowercase && !digits && !special {
            eprintln!("Error: At least one character type must be enabled.");
            process::exit(1);
        }

        for i in 1..=count {
            match Password::generate(length, uppercase, lowercase, digits, special, no_ambiguous) {
                Ok(password) => {
                    if count > 1 {
                        println!("{}: {}", i, password);
                    } else {
                        println!("{}", password);
                    }
                }
                Err(e) => {
                    eprintln!("Error generating password: {}", e);
                    process::exit(1);
                }
            }
        }

        Ok(())
    }
}
