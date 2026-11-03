use cortex::modules::security::Security;

fn apply(operator: &str, left: i64, right: i64) -> i64 {
    match operator {
        "+" => left + right,
        "-" => left - right,
        "*" => left * right,
        other => panic!("unexpected operator {other}"),
    }
}

#[test]
fn math_puzzles_have_a_consistent_expression_and_answer() -> Result<(), Box<dyn std::error::Error>>
{
    for _ in 0..200 {
        let (expression, answer) = Security::generate_math_puzzle()?;
        let tokens: Vec<&str> = expression.split_whitespace().collect();
        assert_eq!(tokens.len(), 5, "{expression}");

        let a: i64 = tokens[0].trim_start_matches('(').parse()?;
        let first = tokens[1];
        let b: i64 = tokens[2].trim_end_matches(')').parse()?;
        let second = tokens[3];
        let c: i64 = tokens[4].parse()?;

        let intermediate = apply(first, a, b);
        assert!(intermediate > 0, "{expression}");
        assert_eq!(apply(second, intermediate, c), answer, "{expression}");
        assert!(answer > 0, "{expression}");
    }
    Ok(())
}
