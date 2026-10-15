//! The network's API: the thin JSON service the Ark-0 web wallet uses (wallet.ark0.si). It sees addresses
//! and signed transactions, never a key. Every answer is checked for shape here, as api.ts checks it.
//!
//! TLS is rustls with the ring provider and the Mozilla root store, the same on every platform.
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_BASE: &str = "https://wallet.ark0.si";
const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiError {
    /// No answer: the network, DNS, TLS or a timeout.
    Unreachable,
    /// An answer that is not what the API gives.
    Malformed,
    /// Too many requests; try again shortly.
    Limit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Coin {
    /// Display order.
    pub txid: String,
    pub vout: u32,
    pub sats: u64,
    pub height: u32,
}

impl Coin {
    pub fn outpoint(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Incoming {
    pub txid: String,
    pub vout: u32,
    pub sats: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Coins {
    /// Confirmed and not spent by a transaction in the mempool.
    pub spendable: Vec<Coin>,
    /// Confirmed, and spent by a transaction still waiting for a block.
    pub pending: Vec<Coin>,
    /// The mempool transaction spending a pending coin, by outpoint, when the API named it.
    pub spent_by: HashMap<String, String>,
    /// Payments to the address waiting for a block: shown, never spent.
    pub incoming: Vec<Incoming>,
    /// False when the API could not look through the whole mempool.
    pub incoming_complete: bool,
    /// The API lists at most a few hundred outputs of an address.
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TxStatus {
    Confirmed { confirmations: u32 },
    Mempool,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BroadcastResult {
    Sent { txid: String },
    /// The node refused it, with its reason.
    Rejected { reason: String },
    /// The node never saw it: "request", "limit" or "unavailable".
    Failed { error: String },
    /// No answer that says what happened: the node may or may not have it.
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CheckResult {
    /// The node would take it into its mempool.
    Allowed { vsize: u64, fee: u64 },
    /// The node refused it, in its own words.
    Rejected { reason: String },
    Failed { error: String },
}

/// The most any output can hold: 21 million coins.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
/// The API lists a few hundred outputs of an address at most; a far longer list is not its answer.
const MAX_LISTED: usize = 10_000;
/// The largest answer read; the API's are a few kilobytes, a long list of outputs a few hundred.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// A response's body, read in pieces and refused once it outgrows any answer the API gives.
async fn body_of(mut response: reqwest::Response) -> Result<Vec<u8>, ApiError> {
    if response.content_length().is_some_and(|n| n > MAX_BODY_BYTES as u64) {
        return Err(ApiError::Malformed);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::Unreachable)? {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(ApiError::Malformed);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// A node's reason for refusing a transaction is one line (a rule's name, or a script error with its
/// detail); a longer one is cut, so that no answer can fill the record of payments.
const MAX_REASON_CHARS: usize = 500;

fn reason_of(body: &Value) -> String {
    body.get("reason").and_then(Value::as_str).unwrap_or("").chars().take(MAX_REASON_CHARS).collect()
}

pub fn is_txid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn u32_of(v: &Value) -> Option<u32> {
    v.as_u64().and_then(|n| u32::try_from(n).ok())
}

fn proof_from(status: u16, body: Value) -> Result<Option<Value>, ApiError> {
    match status {
        200 if body.is_object() => Ok(Some(body)),
        404 if matches!(body.get("error").and_then(Value::as_str), Some("not_confirmed" | "not_found")) => Ok(None),
        _ => Err(ApiError::Malformed),
    }
}

/// The coins of an address, from /api/utxos's answer.
fn coins_from(status: u16, body: &Value) -> Result<Coins, ApiError> {
    let utxos = body.get("utxos").and_then(Value::as_array).filter(|_| status == 200).ok_or(ApiError::Malformed)?;
    if utxos.len() > MAX_LISTED {
        return Err(ApiError::Malformed);
    }
    let mut coins = Coins::default();
    // An answer naming one coin twice would make a transaction spend it twice: it is not used at all.
    let mut listed = std::collections::HashSet::new();
    for u in utxos {
        let txid = u.get("txid").and_then(Value::as_str).filter(|t| is_txid(t)).ok_or(ApiError::Malformed)?;
        let (vout, sats, height) = (
            u.get("vout").and_then(u32_of).ok_or(ApiError::Malformed)?,
            u.get("sats").and_then(Value::as_u64).filter(|s| *s <= MAX_MONEY).ok_or(ApiError::Malformed)?,
            u.get("height").and_then(u32_of).ok_or(ApiError::Malformed)?,
        );
        let coin = Coin { txid: txid.to_string(), vout, sats, height };
        if !listed.insert(coin.outpoint()) {
            return Err(ApiError::Malformed);
        }
        if u.get("spent_in_mempool").and_then(Value::as_bool).ok_or(ApiError::Malformed)? {
            if let Some(by) = u.get("spent_by").and_then(Value::as_str).filter(|t| is_txid(t)) {
                coins.spent_by.insert(coin.outpoint(), by.to_string());
            }
            coins.pending.push(coin);
        } else {
            coins.spendable.push(coin);
        }
    }
    // Payments on their way are for display only: a malformed one is skipped and the list marked
    // incomplete; one already listed as confirmed counts once, as confirmed.
    let unconfirmed = body.get("unconfirmed").and_then(Value::as_array);
    coins.incoming_complete = body.get("unconfirmed_complete").and_then(Value::as_bool) == Some(true) && unconfirmed.is_some();
    let mut seen: std::collections::HashSet<String> = coins.spendable.iter().chain(&coins.pending).map(Coin::outpoint).collect();
    if unconfirmed.is_some_and(|list| list.len() > MAX_LISTED) {
        coins.incoming_complete = false;
    }
    for u in unconfirmed.into_iter().flatten().take(MAX_LISTED) {
        let parsed = (|| {
            Some(Incoming {
                txid: u.get("txid")?.as_str().filter(|t| is_txid(t))?.to_string(),
                vout: u32_of(u.get("vout")?)?,
                sats: u.get("sats")?.as_u64().filter(|s| *s <= MAX_MONEY)?,
            })
        })();
        match parsed {
            Some(i) if seen.insert(format!("{}:{}", i.txid, i.vout)) => coins.incoming.push(i),
            Some(_) => {}
            None => coins.incoming_complete = false,
        }
    }
    coins.truncated = body.get("truncated").and_then(Value::as_bool) == Some(true);
    // No address can hold more than all the money there is; the wallet's sums stay far from overflowing.
    let total = coins.spendable.iter().chain(&coins.pending).map(|c| c.sats).chain(coins.incoming.iter().map(|i| i.sats))
        .try_fold(0u64, |sum, sats| sum.checked_add(sats).filter(|s| *s <= MAX_MONEY));
    if total.is_none() {
        return Err(ApiError::Malformed);
    }
    Ok(coins)
}

/// TLS with ring and the Mozilla roots: reqwest is built without a crypto provider of its own.
fn tls_config() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

pub struct Api {
    base: String,
    client: reqwest::Client,
}

impl Api {
    pub fn new(base: &str) -> Self {
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config())
            .timeout(TIMEOUT)
            .user_agent(concat!("ark0-wallet/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("an HTTP client");
        Api { base: base.trim_end_matches('/').to_string(), client }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    async fn get(&self, path: &str) -> Result<(u16, Value), ApiError> {
        let response = self.client.get(format!("{}{path}", self.base)).send().await.map_err(|_| ApiError::Unreachable)?;
        let status = response.status().as_u16();
        let body: Value = serde_json::from_slice(&body_of(response).await?).map_err(|_| ApiError::Malformed)?;
        if status == 429 {
            return Err(ApiError::Limit);
        }
        Ok((status, body))
    }

    /// Posts carry the API's own origin: the service takes posts only from its pages (a browser rule
    /// against other sites posting through a visitor), and this client is not a browser page of another
    /// site. A dedicated way in for clients is a change on the service's side.
    async fn post(&self, path: &str, body: Value) -> Result<(u16, Value), ApiError> {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .header("Origin", &self.base)
            .json(&body)
            .send()
            .await
            .map_err(|_| ApiError::Unreachable)?;
        let status = response.status().as_u16();
        let body = body_of(response).await.ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
        Ok((status, body))
    }

    pub async fn state(&self) -> Result<Value, ApiError> {
        let (status, body) = self.get("/api/state").await?;
        if status != 200 {
            return Err(ApiError::Malformed);
        }
        // The structure is left to chain::check: a state that parses but names no network must stop the other answer from passing.
        Ok(body)
    }

    pub async fn coins(&self, address: &str) -> Result<Coins, ApiError> {
        let (status, body) = self.get(&format!("/api/utxos?address={address}")).await?;
        coins_from(status, &body)
    }

    pub async fn tx_status(&self, txid: &str) -> Result<TxStatus, ApiError> {
        if !is_txid(txid) {
            return Err(ApiError::Malformed);
        }
        let (status, body) = self.get(&format!("/api/tx?txid={txid}")).await?;
        if status != 200 {
            return Err(ApiError::Malformed);
        }
        match body.get("status").and_then(Value::as_str) {
            Some("confirmed") => match body.get("confirmations").and_then(u32_of) {
                Some(n) if n > 0 => Ok(TxStatus::Confirmed { confirmations: n }),
                _ => Err(ApiError::Malformed),
            },
            Some("mempool") => Ok(TxStatus::Mempool),
            Some("unknown") => Ok(TxStatus::Unknown),
            _ => Err(ApiError::Malformed),
        }
    }

    pub async fn proof(&self, txid: &str) -> Result<Option<Value>, ApiError> {
        if !is_txid(txid) {
            return Err(ApiError::Malformed);
        }
        let (status, body) = self.get(&format!("/api/proof?txid={txid}")).await?;
        proof_from(status, body)
    }

    /// Broadcast `hex`, whose txid is `txid`: a success must name that transaction.
    pub async fn broadcast(&self, hex: &str, txid: &str) -> BroadcastResult {
        let (status, body) = match self.post("/api/broadcast", json!({ "hex": hex })).await {
            Ok(answer) => answer,
            Err(_) => return BroadcastResult::Unknown,
        };
        let error = body.get("error").and_then(Value::as_str).unwrap_or("");
        match status {
            200 if body.get("txid").and_then(Value::as_str) == Some(txid) => BroadcastResult::Sent { txid: txid.to_string() },
            422 if error == "rejected" => BroadcastResult::Rejected { reason: reason_of(&body) },
            400 if error == "request" => BroadcastResult::Failed { error: error.into() },
            429 if error == "limit" => BroadcastResult::Failed { error: error.into() },
            503 if error == "unavailable" => BroadcastResult::Failed { error: error.into() },
            _ => BroadcastResult::Unknown,
        }
    }

    /// Has the node check `hex` (testmempoolaccept) without passing it on.
    pub async fn check(&self, hex: &str) -> CheckResult {
        let (status, body) = match self.post("/api/check", json!({ "hex": hex })).await {
            Ok(answer) => answer,
            Err(_) => return CheckResult::Failed { error: "unavailable".into() },
        };
        let allowed = body.get("allowed").and_then(Value::as_bool);
        if status == 200 && allowed == Some(true) {
            if let (Some(vsize), Some(fee)) = (body.get("vsize").and_then(Value::as_u64), body.get("fee").and_then(Value::as_u64)) {
                return CheckResult::Allowed { vsize, fee };
            }
        }
        if (status == 200 && allowed == Some(false)) || (status == 422 && body.get("error").and_then(Value::as_str) == Some("rejected")) {
            return CheckResult::Rejected { reason: reason_of(&body) };
        }
        if status == 429 {
            return CheckResult::Failed { error: "limit".into() };
        }
        CheckResult::Failed { error: "unavailable".into() }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    pub(crate) fn response(status: u16, body: &str) -> String {
        format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    }

    pub(crate) fn serve(responses: Vec<String>) -> (Api, JoinHandle<Vec<String>>) {
        serve_with(responses, || {})
    }

    /// An API at a socket that listens but never answers: a request to it is a connection left waiting in
    /// the listener's queue, so a test can tell that none was made.
    pub(crate) fn idle() -> (Api, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        (loopback(&listener), listener)
    }

    /// An API for a local test socket, not through any system proxy the build host may set.
    fn loopback(listener: &TcpListener) -> Api {
        let mut api = Api::new(&format!("http://{}", listener.local_addr().unwrap()));
        api.client = reqwest::Client::builder().use_preconfigured_tls(tls_config()).no_proxy().timeout(TIMEOUT).build().unwrap();
        api
    }

    pub(crate) fn serve_with(responses: Vec<String>, before_reply: impl Fn() + Send + 'static) -> (Api, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = loopback(&listener);
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
                        Err(e) => panic!("HTTP test did not receive its request: {e}"),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(request.len() < 8192);
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                let request = String::from_utf8(request).unwrap();
                let length = request.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
                }).unwrap_or(0);
                assert!(length <= MAX_BODY_BYTES);
                // Read the whole POST body: otherwise a reset when the connection closes can overtake the answer already written.
                socket.read_exact(&mut vec![0; length]).unwrap();
                requests.push(request);
                before_reply();
                socket.write_all(response.as_bytes()).unwrap();
            }
            requests
        });
        (api, server)
    }

    #[test]
    fn proof_endpoint_uses_the_shared_body_limit_and_http_errors() {
        let txid = "a".repeat(64);
        let body = json!({"txid": txid, "height": 20_000, "tip": 20_000, "blocks": []});
        let (api, server) = serve(vec![
            response(200, &body.to_string()),
            response(404, r#"{"error":"not_confirmed"}"#),
            response(404, r#"{"error":"not_found"}"#),
            response(404, r#"{"error":"other"}"#),
            response(429, r#"{"error":"limit"}"#),
            response(500, "{}"), response(200, "[]"), response(200, "invalid JSON"),
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{{}}", MAX_BODY_BYTES + 1),
        ]);
        let results = tauri::async_runtime::block_on(async {
            let mut results = Vec::new();
            for _ in 0..9 { results.push(api.proof(&txid).await); }
            results
        });
        let requests = server.join().unwrap();
        assert_eq!(results[0], Ok(Some(body)));
        assert_eq!(results[1], Ok(None));
        assert_eq!(results[2], Ok(None));
        assert_eq!(results[3], Err(ApiError::Malformed));
        assert_eq!(results[4], Err(ApiError::Limit));
        for result in &results[5..] { assert_eq!(result, &Err(ApiError::Malformed)); }
        assert!(requests.iter().all(|r| r.starts_with(&format!("GET /api/proof?txid={txid} HTTP/1.1\r\n"))));
        assert_eq!(tauri::async_runtime::block_on(api.proof("invalid&txid=other")), Err(ApiError::Malformed));
        assert_eq!(tauri::async_runtime::block_on(api.proof(&"a".repeat(65))), Err(ApiError::Malformed));
    }

    pub(crate) fn utxo(txid: char, vout: u32, sats: u64) -> Value {
        json!({ "txid": txid.to_string().repeat(64), "vout": vout, "sats": sats, "height": 10, "spent_in_mempool": false })
    }

    #[test]
    fn answers_that_could_misplan_a_spend_are_refused() {
        let ok = coins_from(200, &json!({ "utxos": [utxo('a', 0, 1_000), utxo('a', 1, 2_000)] })).unwrap();
        assert_eq!(ok.spendable.len(), 2);
        // The same coin twice would be spent twice in one transaction.
        assert_eq!(coins_from(200, &json!({ "utxos": [utxo('a', 0, 1_000), utxo('a', 0, 1_000)] })), Err(ApiError::Malformed));
        // More than there can be in any output.
        assert_eq!(coins_from(200, &json!({ "utxos": [utxo('a', 0, MAX_MONEY + 1)] })), Err(ApiError::Malformed));
        let many: Vec<Value> = (0..=MAX_LISTED as u32).map(|v| utxo('b', v, 1)).collect();
        assert_eq!(coins_from(200, &json!({ "utxos": many })), Err(ApiError::Malformed));
        assert_eq!(coins_from(500, &json!({ "utxos": [] })), Err(ApiError::Malformed));
        // Together more than all the money there is.
        assert_eq!(coins_from(200, &json!({ "utxos": [utxo('a', 0, MAX_MONEY), utxo('a', 1, 1)] })), Err(ApiError::Malformed));
        // A refusal's reason is kept to one line's length.
        assert_eq!(reason_of(&json!({ "reason": "x".repeat(10_000) })).len(), MAX_REASON_CHARS);
        // A coin whose mempool state is missing is not taken as unspent.
        let mut unclear = utxo('c', 0, 1_000);
        unclear.as_object_mut().unwrap().remove("spent_in_mempool");
        assert_eq!(coins_from(200, &json!({ "utxos": [unclear] })), Err(ApiError::Malformed));
    }
}
