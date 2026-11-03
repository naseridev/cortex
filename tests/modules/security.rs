use cortex::modules::security::Security;

fn apply(operator: &str, left: i64, right: i64) -> Option<i64> {
    match operator {
        "+" => left.checked_add(right),
        "-" => left.checked_sub(right),
        "*" => left.checked_mul(right),
        _ => None,
    }
}

#[test]
fn math_puzzles_have_a_consistent_expression_and_answer() -> Result<(), Box<dyn std::error::Error>>
{
    for _ in 0..200 {
        let (expression, answer) = Security::generate_math_puzzle()?;
        let tokens: Vec<&str> = expression.split_whitespace().collect();
        let [left_token, first, right_token, second, last_token] = tokens.as_slice() else {
            return Err(format!("unexpected expression {expression}").into());
        };

        let a: i64 = left_token.trim_start_matches('(').parse()?;
        let b: i64 = right_token.trim_end_matches(')').parse()?;
        let c: i64 = last_token.parse()?;

        let intermediate = apply(first, a, b).ok_or("intermediate overflow")?;
        assert!(intermediate > 0, "{expression}");
        assert_eq!(apply(second, intermediate, c), Some(answer), "{expression}");
        assert!(answer > 0, "{expression}");
    }
    Ok(())
}
