pub type TestResult = Result<(), Box<dyn std::error::Error>>;

pub fn failure<T, E>(result: Result<T, E>) -> Result<E, &'static str> {
    match result {
        Ok(_) => Err("expected the operation to fail"),
        Err(error) => Ok(error),
    }
}
