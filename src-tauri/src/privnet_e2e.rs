//! The privnet build against a private network (tools/privnet/README.md): one step of the checks per run,
//! through the wallet's command layer. Without ARK0_PRIVNET_STEP the test does nothing.
//!
//! ARK0_PRIVNET_CONFIG the network's file; ARK0_PRIVNET_WALLET_DIR the wallet's data directory;
//! ARK0_PRIVNET_STEP and ARK0_PRIVNET_ARGS (JSON) the step; ARK0_PRIVNET_OUT where its answers go, as JSON.
//! The wallet is made from fixed words on the first step, as the create flow makes it (with "restore" in the
//! arguments restored from them; with "legacy", from a web-wallet backup code), and unlocked from its vault
//! on every later one.
use super::*;
use serde_json::{json, Value};

const PASSWORD: &str = "privnet wallet password";
const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn run<T: Serialize>(future: impl Future<Output = Res<T>>) -> Value {
    match tauri::async_runtime::block_on(future) {
        Ok(v) => json!({"ok": v}),
        Err(f) => json!({"error": f.code}),
    }
}

fn now_json<T: Serialize>(result: Res<T>) -> Value {
    match result {
        Ok(v) => json!({"ok": v}),
        Err(f) => json!({"error": f.code}),
    }
}

fn open(state: &AppState, args: &Value) -> Value {
    if vault::exists(&state.vault_path()) {
        return json!({"unlock": now_json(unlock_wallet(state, PASSWORD.into()).map(|_| ()))});
    }
    let text = match args.get("legacy") {
        // A web wallet's backup code: a legacy seed, which has no pq2 keys.
        Some(_) => crate::keys::Secret::Legacy { seed: crate::keys::SecretBytes(Zeroizing::new([0x5a; 32])) }.recovery_text().to_string(),
        None => WORDS.to_string(),
    };
    if args.get("legacy").is_some() || args.get("restore").is_some() {
        return json!({"restore": now_json(restore_wallet_from_text(state, text.clone(), PASSWORD.into()).map(|_| ())), "from": text});
    }
    // Otherwise made as the create flow makes a wallet (its words confirmed), here from fixed words: no other
    // copy has handed out addresses, so no scan is needed.
    let secret = crate::keys::Secret::from_phrase(WORDS).expect("the fixed words");
    *guard(&state.new_wallet) = Some(NewWallet { secret, confirmed: true });
    json!({"create": now_json(create_confirmed_wallet(state, PASSWORD.into()).map(|_| ())), "from": text})
}

fn path_of(args: &Value) -> Option<Path> {
    match args.get("path").and_then(Value::as_str) {
        Some("mldsa44") => Some(Path::Mldsa44),
        Some("slhdsa128s") => Some(Path::Slhdsa128s),
        _ => None,
    }
}

fn plan(state: &AppState, args: &Value) -> Res<SendPlan> {
    let s = |k: &str| args.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    tauri::async_runtime::block_on(plan_pq2_payment(state, s("from"), s("to"), s("amount"), path_of(args), None))
}

fn confirm(state: &AppState, id: &str) -> Value {
    run(send_plan(state, id, Some("en"), |_| std::future::ready(true)))
}

/// A person's pause between reading a plan and confirming it (ARK0_PRIVNET_PACE seconds, 0 by default): the
/// site lets one visitor look up 20 addresses at once and one a second after that, and a plan and its
/// confirmation together come close to it.
fn review() {
    let seconds: u64 = std::env::var("ARK0_PRIVNET_PACE").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    std::thread::sleep(Duration::from_secs(seconds));
}

fn step(state: &AppState, name: &str, args: &Value) -> Value {
    match name {
        "overview" => run(overview_of(state)),
        "activity" => run(activity_of(state)),
        // A recovery scan, timed.
        "scan" => {
            let started = Instant::now();
            let result = run(scan_pq2(state, false));
            json!({"scan": result, "seconds": started.elapsed().as_secs_f64()})
        }
        // A new receiving address, after the scan a restored wallet needs (when it does).
        "address" => {
            let scan = match state.book() {
                Ok(b) if b.scan_needed => Some(run(scan_pq2(state, false))),
                _ => None,
            };
            json!({"scan": scan, "address": run(new_pq2_address(state))})
        }
        // A plan only: what the review offers.
        "plan" => now_json(plan(state, args)),
        // A plan, confirmed at once.
        "send" => match plan(state, args) {
            Ok(view) => {
                let id = view.id.clone();
                review();
                json!({"plan": view, "send": confirm(state, &id)})
            }
            Err(f) => json!({"plan": {"error": f.code}}),
        },
        // A spend through the ML-DSA-44 leaf, signed and held right before it is recorded and sent, until the
        // harness has spent the drill tripwire (ARK0_PRIVNET_SIGNAL: "<dir>", with held-ready and held-go in it);
        // then sent as the wallet sends it, and the plan the wallet offers after it, confirmed.
        "held" => {
            let view = match plan(state, args) {
                Ok(v) => v,
                Err(f) => return json!({"plan": {"error": f.code}}),
            };
            let signal = std::path::PathBuf::from(var("ARK0_PRIVNET_SIGNAL"));
            *guard(&state.before_commit) = Some(Box::new(move |_: &AppState| {
                std::fs::write(signal.join("held-ready"), b"signed\n").expect("the signal directory");
                let started = Instant::now();
                while !signal.join("held-go").exists() {
                    assert!(started.elapsed() < Duration::from_secs(3600), "no held-go within an hour");
                    std::thread::sleep(Duration::from_millis(200));
                }
            }));
            let id = view.id.clone();
            review();
            let sent = tauri::async_runtime::block_on(send_plan(state, &id, Some("en"), |_| std::future::ready(true)));
            let records: Vec<Sent> = store::load(&state.sent_path());
            let mut out = json!({"plan": view, "send": now_json(sent.as_ref().map(|r| r).map_err(|f| Failure::new(&f.code))), "records": records});
            match &sent {
                Ok(SendResult { rebuilt: Some(rebuilt), .. }) => {
                    review();
                    out["rebuilt_send"] = confirm(state, &rebuilt.id);
                }
                // No rebuild came with the refusal (send_plan keeps no reason): the same request again at
                // once, to see why.
                Ok(SendResult { rebuilt: None, txid, .. }) => {
                    out["rebuild_at_once"] = run(rebuild_plan(state, txid));
                    *guard(&state.pending) = None;
                }
                Err(_) => {}
            }
            out
        }
        // The rebuild the wallet offers for a recorded payment (`txid`), as the activity view asks for it, and
        // with "confirm" in the arguments, confirmed.
        "rebuild" => {
            let txid = args.get("txid").and_then(Value::as_str).unwrap_or_default();
            match tauri::async_runtime::block_on(rebuild_plan(state, txid)) {
                Ok(view) if args.get("confirm").is_some() => {
                    let id = view.id.clone();
                    review();
                    json!({"plan": view, "send": confirm(state, &id)})
                }
                other => json!({"plan": now_json(other)}),
            }
        }
        other => json!({"error": format!("no step {other}")}),
    }
}

#[test]
fn privnet_e2e() {
    let Ok(name) = std::env::var("ARK0_PRIVNET_STEP") else {
        eprintln!("privnet_e2e: no ARK0_PRIVNET_STEP, nothing to do (tools/privnet/README.md)");
        return;
    };
    crate::net::load().expect("the private network's file");
    let args: Value = serde_json::from_str(&std::env::var("ARK0_PRIVNET_ARGS").unwrap_or_else(|_| "{}".into())).expect("ARK0_PRIVNET_ARGS: JSON");
    let state = AppState::new(var("ARK0_PRIVNET_WALLET_DIR").into()).expect("the wallet's directory");
    let opened = open(&state, &args);
    let answer = step(&state, &name, &args);
    let out = json!({"step": name, "args": args, "open": opened, "answer": answer});
    std::fs::write(var("ARK0_PRIVNET_OUT"), serde_json::to_vec_pretty(&out).unwrap()).expect("ARK0_PRIVNET_OUT");
}
