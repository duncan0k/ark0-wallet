mod api;
mod app;
mod chain;
mod confirm;
mod keys;
mod mldsa;
mod p2mr;
mod proof;
mod sources;
pub mod selftest;
mod store;
mod tx;
mod vault;
mod wallet;

use tauri::Manager;

#[tauri::command(async)]
fn selftest() -> selftest::Report {
    selftest::run()
}

/// `--selftest [path]` on the desktop binary: run the self-test without a window, write the report to
/// path (or stdout) as JSON, and exit 0 when every check passed. Release builds on Windows have no
/// console, so there the report has to go to a file.
pub fn selftest_cli(path: Option<&str>) -> i32 {
    let report = selftest::run();
    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
    match path {
        Some(p) => {
            if let Err(e) = std::fs::write(p, json + "\n") {
                eprintln!("cannot write {p}: {e}");
                return 2;
            }
        }
        None => println!("{json}"),
    }
    if report.ok {
        0
    } else {
        1
    }
}

#[cfg(target_os = "android")]
fn android_log(text: &str) {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};
    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }
    let tag = CString::new("PQW").expect("no NUL in the tag");
    // logcat cuts long lines at about 4 KB.
    for chunk in text.as_bytes().chunks(3000) {
        if let Ok(line) = CString::new(chunk) {
            // SAFETY: both pointers are valid NUL-terminated strings for the duration of the call.
            unsafe {
                __android_log_write(4, tag.as_ptr(), line.as_ptr());
            }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            app.manage(app::AppState::new(dir));
            app::start_idle_lock(app.handle().clone());
            // On Android the self-test result goes to logcat as well, where the emulator test reads it.
            #[cfg(target_os = "android")]
            {
                let report = selftest::run();
                android_log(&format!("PQW_SELFTEST {}", serde_json::to_string(&report).unwrap_or_default()));
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            selftest,
            app::app_info,
            app::wallet_status,
            app::new_phrase,
            app::confirm_phrase,
            app::create_wallet,
            app::check_recovery,
            app::restore_wallet,
            app::bip39_words,
            app::unlock,
            app::lock,
            app::touch,
            app::reveal_recovery,
            app::change_password,
            app::delete_wallet,
            app::forget_wallet,
            app::overview,
            app::plan_send,
            app::confirm_send,
            app::activity,
            app::drill_check,
            app::settings_get,
            app::settings_set,
            app::qr_svg,
            app::open_page,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the application");
}
