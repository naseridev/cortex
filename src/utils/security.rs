use std::process;

use rand::{RngCore, rngs::OsRng};

use crate::ui::prompt::UserPrompt;

pub struct Security;

impl Security {
    pub fn generate_math_puzzle() -> (String, i64) {
        let mut rng = OsRng;

        loop {
            let a = (rng.next_u32() % 91 + 10) as i64;
            let b = (rng.next_u32() % 46 + 5) as i64;
            let c = (rng.next_u32() % 38 + 3) as i64;

            let ops = ["+", "-", "*"];
            let op1 = ops[(rng.next_u32() as usize) % ops.len()];
            let op2 = ops[(rng.next_u32() as usize) % ops.len()];

            let intermediate = match op1 {
                "+" => a + b,
                "-" => a - b,
                "*" => a * b,
                _ => unreachable!(),
            };

            if intermediate <= 0 {
                continue;
            }

            let answer = match op2 {
                "+" => intermediate + c,
                "-" => intermediate - c,
                "*" => intermediate * c,
                _ => unreachable!(),
            };

            if answer > 0 {
                return (format!("({} {} {}) {} {}", a, op1, b, op2, c), answer);
            }
        }
    }

    pub fn confirmation(warning_message: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!();
        println!("WARNING: {}", warning_message);
        println!();

        let (puzzle, answer) = Self::generate_math_puzzle();
        println!("Solve this equation to confirm: {}", puzzle);

        let user_answer = UserPrompt::text("Answer: ")?;
        let user_num: i64 = user_answer.as_str().parse().map_err(|_| "Invalid number")?;

        if user_num != answer {
            println!("Wrong answer. Destruction cancelled.");
            process::exit(1);
        }

        Ok(())
    }
}
