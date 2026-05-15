fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 3 {
        unsafe { runasti::runasti(args.get(1).unwrap_or(&"powershell".to_string())) }
            .unwrap_or_else(|e| eprintln!("{}", e));
    } else {
        eprintln!("Argument length error");
    }
}
