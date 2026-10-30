use crate::ui::prompt::UserPrompt;
use rand::{Rng, rngs::OsRng};

pub struct Security;

impl Security {
    pub fn generate_math_puzzle() -> (String, i64) {
        let mut rng = OsRng;
        let ops = ["+", "-", "*"];

        loop {
            let a = rng.gen_range(10..=100);
            let b = rng.gen_range(5..=50);
            let c = rng.gen_range(3..=40);

            let op1 = ops[rng.gen_range(0..ops.len())];
            let op2 = ops[rng.gen_range(0..ops.len())];

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
            return Err("Wrong answer. Operation cancelled.".into());
        }

        Ok(())
    }
}
