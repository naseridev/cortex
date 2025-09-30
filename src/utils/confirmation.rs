use crate::{ui::prompt::UserPrompt, utils::security::Security};

pub struct Confirmation;

impl Confirmation {
    pub fn require_math_puzzle(warning_message: &str) -> Result<bool, Box<dyn std::error::Error>> {
        println!();
        println!("WARNING: {}", warning_message);
        println!();

        let (puzzle, answer) = Security::generate_math_puzzle();
        println!("Solve this equation to confirm: {}", puzzle);

        let user_answer = UserPrompt::text("Answer: ")?;
        let user_num: i64 = user_answer.as_str().parse().map_err(|_| "Invalid number")?;

        Ok(user_num == answer)
    }
}
