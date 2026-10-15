// No console window for release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--selftest") {
        std::process::exit(ark0_wallet_lib::selftest_cli(args.get(2).map(String::as_str)));
    }
    ark0_wallet_lib::run()
}
