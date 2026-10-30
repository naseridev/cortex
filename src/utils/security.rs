use crate::ui::prompt::UserPrompt;
use rand::{Rng, rngs::OsRng};

const PUZZLE_ATTEMPTS: u32 = 64;

#[derive(Clone, Copy)]
enum Operator {
    Add,
    Subtract,
    Multiply,
}

impl Operator {
    fn random(rng: &mut OsRng) -> Self {
        match rng.gen_range(0..3) {
            0 => Self::Add,
            1 => Self::Subtract,
            _ => Self::Multiply,
        }
    }

    fn symbol(self) -> char {
        match self {
            Self::Add => '+',
            Self::Subtract => '-',
            Self::Multiply => '*',
        }
    }

    fn apply(self, lhs: i64, rhs: i64) -> Option<i64> {
        match self {
            Self::Add => lhs.checked_add(rhs),
            Self::Subtract => lhs.checked_sub(rhs),
            Self::Multiply => lhs.checked_mul(rhs),
        }
    }
}

pub struct Security;

impl Security {
    pub fn generate_math_puzzle() -> Result<(String, i64), Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        for _ in 0..PUZZLE_ATTEMPTS {
            if let Some(puzzle) = Self::try_math_puzzle(&mut rng) {
                return Ok(puzzle);
            }
        }
        Err("Could not generate a confirmation puzzle".into())
    }

    fn try_math_puzzle(rng: &mut OsRng) -> Option<(String, i64)> {
        let a: i64 = rng.gen_range(10..=100);
        let b: i64 = rng.gen_range(5..=50);
        let c: i64 = rng.gen_range(3..=40);
        let first = Operator::random(rng);
        let second = Operator::random(rng);

        let intermediate = first.apply(a, b)?;
        if intermediate <= 0 {
            return None;
        }

        let answer = second.apply(intermediate, c)?;
        if answer <= 0 {
            return None;
        }

        let expression = format!("({a} {} {b}) {} {c}", first.symbol(), second.symbol());
        Some((expression, answer))
    }

    pub fn confirmation(warning_message: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!();
        println!("WARNING: {warning_message}");
        println!();

        let (puzzle, answer) = Self::generate_math_puzzle()?;
        println!("Solve this equation to confirm: {puzzle}");

        let user_answer = UserPrompt::text("Answer: ")?;
        let user_number: i64 = user_answer.parse().map_err(|_| "Invalid number")?;

        if user_number != answer {
            return Err("Wrong answer. Operation cancelled.".into());
        }

        Ok(())
    }
}
