#![forbid(unsafe_code)]

fn main() {
    let status = task_status();
    println!("{status}");
}

fn task_status() -> &'static str {
    "xtask is not implemented yet"
}

#[cfg(test)]
mod tests {
    #[test]
    fn task_binary_compiles() {
        assert_eq!(super::task_status(), "xtask is not implemented yet");
    }
}
