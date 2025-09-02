use rand::{RngCore, rngs::OsRng};

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
}
