use crate::ui::prompt::UserPrompt;
use rand::{RngExt, rngs::ThreadRng};

const PUZZLE_ATTEMPTS: u32 = 64;

#[derive(Clone, Copy)]
enum Operator {
    Add,
    Subtract,
    Multiply,
}

impl Operator {
    fn random(rng: &mut ThreadRng) -> Self {
        match rng.random_range(0..3) {
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

pub struct Confirmation;

impl Confirmation {
    pub fn math_puzzle() -> Result<(String, i64), Box<dyn std::error::Error>> {
        let mut rng = rand::rng();
        (0..PUZZLE_ATTEMPTS)
            .find_map(|_| Self::try_math_puzzle(&mut rng))
            .ok_or_else(|| "Could not generate a confirmation puzzle".into())
    }

    fn try_math_puzzle(rng: &mut ThreadRng) -> Option<(String, i64)> {
        let a: i64 = rng.random_range(10..=100);
        let b: i64 = rng.random_range(5..=50);
        let c: i64 = rng.random_range(3..=40);
        let first = Operator::random(rng);
        let second = Operator::random(rng);

        let intermediate = first.apply(a, b).filter(|value| *value > 0)?;
        let answer = second.apply(intermediate, c).filter(|value| *value > 0)?;

        let expression = format!("({a} {} {b}) {} {c}", first.symbol(), second.symbol());
        Some((expression, answer))
    }

    pub fn require(warning: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!();
        println!("WARNING: {warning}");
        println!();

        let (puzzle, answer) = Self::math_puzzle()?;
        println!("Solve this equation to confirm: {puzzle}");

        let response = UserPrompt::text("Answer: ")?;
        let number: i64 = response.parse().map_err(|_| "Invalid number")?;

        if number != answer {
            return Err("Wrong answer. Operation cancelled.".into());
        }

        Ok(())
    }
}
