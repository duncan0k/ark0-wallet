//! Two independently hosted APIs: what can be spent needs both, what may already have been paid needs either.
use crate::api::{Api, ApiError, BroadcastResult, CheckResult, Coin, Coins, TxStatus};
use crate::chain::{self, Chain, ChainProblem};
use crate::proof;
use std::collections::{HashMap, HashSet};
use std::future::{poll_fn, Future};
use std::task::Poll;

pub const SECOND_BASE: &str = "https://wallet2.ark0.si";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub one_source: bool,
    pub disagree: bool,
}

impl Flags {
    pub fn take<T>(&mut self, answer: Answer<T>) -> T {
        self.one_source |= answer.flags.one_source;
        self.disagree |= answer.flags.disagree;
        answer.value
    }
}

// A failed query keeps its flags, so a refresh of an old payment does not lose the one-node warning.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer<T> {
    pub value: T,
    pub flags: Flags,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    Api(ApiError),
    Chain(ChainProblem),
}

// Both are polled in the same task: no extra runtime, no request left running in the background.
async fn together<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let (mut a, mut b) = (std::pin::pin!(a), std::pin::pin!(b));
    let (mut left, mut right) = (None, None);
    poll_fn(|cx| {
        if left.is_none() {
            if let Poll::Ready(value) = a.as_mut().poll(cx) { left = Some(value); }
        }
        if right.is_none() {
            if let Poll::Ready(value) = b.as_mut().poll(cx) { right = Some(value); }
        }
        if left.is_some() && right.is_some() {
            Poll::Ready((left.take().expect("left answered"), right.take().expect("right answered")))
        } else {
            Poll::Pending
        }
    }).await
}

fn combine<T, E>(left: Result<T, E>, right: Result<T, E>, merge: impl FnOnce(T, T) -> (T, bool)) -> Answer<Result<T, E>> {
    let mut flags = Flags::default();
    let value = match (left, right) {
        (Ok(a), Ok(b)) => {
            let (value, disagree) = merge(a, b);
            flags.disagree = disagree;
            Ok(value)
        }
        (Ok(value), Err(_)) | (Err(_), Ok(value)) => {
            flags.one_source = true;
            Ok(value)
        }
        (Err(error), Err(_)) => Err(error),
    };
    Answer { value, flags }
}

fn merge_chain(mut a: Chain, mut b: Chain) -> (Chain, bool) {
    if a.tip > b.tip { std::mem::swap(&mut a, &mut b); }
    let wires = |c: &Chain| c.tripwires.iter().map(|t| (t.outpoint.clone(), t.unspent)).collect::<HashMap<_, _>>();
    let disagree = b.tip - a.tip > 6 || a.ec_disabled != b.ec_disabled || wires(&a) != wires(&b);
    // The mixed address opens only when both know the tripwire state; if either sees it pulled, the ML-DSA-44 leaf is used.
    a.ec_disabled = match (a.ec_disabled, b.ec_disabled) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    };
    a.tripwire_tip = a.tripwire_tip.zip(b.tripwire_tip).map(|(x, y)| x.min(y));
    a.mixed_allowed &= b.mixed_allowed;
    let mut positions = a.tripwires.iter().enumerate().map(|(i, t)| (t.outpoint.clone(), i)).collect::<HashMap<_, _>>();
    for wire in b.tripwires {
        match positions.get(&wire.outpoint) {
            Some(&i) => a.tripwires[i].unspent &= wire.unspent,
            None => {
                positions.insert(wire.outpoint.clone(), a.tripwires.len());
                a.tripwires.push(wire);
            }
        }
    }
    (a, disagree)
}

fn amounts(coins: &[Coin]) -> HashMap<String, u64> {
    coins.iter().map(|c| (c.outpoint(), c.sats)).collect()
}

fn union<T>(mut left: Vec<T>, right: Vec<T>, key: impl Fn(&T) -> String) -> Vec<T> {
    let mut seen: HashSet<String> = left.iter().map(&key).collect();
    left.extend(right.into_iter().filter(|item| seen.insert(key(item))));
    left
}

fn merge_coins(mut a: Coins, b: Coins) -> (Coins, bool) {
    let other = amounts(&b.spendable);
    let incoming = |c: &Coins| c.incoming.iter().map(|i| (format!("{}:{}", i.txid, i.vout), i.sats)).collect::<HashMap<_, _>>();
    let disagree = amounts(&a.spendable) != other || amounts(&a.pending) != amounts(&b.pending)
        || incoming(&a) != incoming(&b) || a.spent_by != b.spent_by
        || a.truncated != b.truncated || a.incoming_complete != b.incoming_complete;
    a.spendable.retain(|c| other.get(&c.outpoint()) == Some(&c.sats));
    a.pending = union(a.pending, b.pending, Coin::outpoint);
    a.incoming = union(a.incoming, b.incoming, |i| format!("{}:{}", i.txid, i.vout));
    for (outpoint, txid) in b.spent_by { a.spent_by.entry(outpoint).or_insert(txid); }
    a.incoming_complete &= b.incoming_complete;
    a.truncated |= b.truncated;
    (a, disagree)
}

fn merge_status(a: TxStatus, b: TxStatus) -> (TxStatus, bool) {
    let disagree = a != b;
    let rank = |s: &TxStatus| match s {
        TxStatus::Confirmed { confirmations } => (2, *confirmations),
        TxStatus::Mempool => (1, 0),
        TxStatus::Unknown => (0, 0),
    };
    (if rank(&a) >= rank(&b) { a } else { b }, disagree)
}

fn merge_broadcast(a: BroadcastResult, b: BroadcastResult) -> BroadcastResult {
    use BroadcastResult::*;
    match (a, b) {
        (sent @ Sent { .. }, _) | (_, sent @ Sent { .. }) => sent,
        (rejected @ Rejected { .. }, Rejected { .. } | Failed { .. })
        | (Failed { .. }, rejected @ Rejected { .. }) => rejected,
        (failed @ Failed { .. }, Failed { .. }) => failed,
        _ => Unknown,
    }
}

async fn checked_state(api: &Api) -> Result<Chain, StateError> {
    let state = api.state().await.map_err(StateError::Api)?;
    chain::check(&state).map_err(StateError::Chain)
}

pub struct Sources {
    first: Api,
    second: Api,
    // Tests may use a chain signed with a test key; real builds always use the deployed key.
    #[cfg(test)]
    verify_proof: fn(&str, &serde_json::Value) -> Result<u32, proof::ProofError>,
}

impl Default for Sources {
    fn default() -> Self {
        Sources::new(Api::new(crate::api::DEFAULT_BASE), Api::new(SECOND_BASE))
    }
}

impl Sources {
    pub fn new(first: Api, second: Api) -> Self {
        Sources {
            first, second,
            #[cfg(test)]
            verify_proof: proof::verify,
        }
    }

    pub fn bases(&self) -> String {
        format!("{}, {}", self.first.base(), self.second.base())
    }

    pub async fn state(&self) -> Answer<Result<Chain, StateError>> {
        let (a, b) = together(checked_state(&self.first), checked_state(&self.second)).await;
        // An answer naming the wrong network cannot be covered by the other, healthy one.
        for answer in [&a, &b] {
            if let Err(StateError::Chain(problem)) = answer {
                return Answer { value: Err(StateError::Chain(*problem)), flags: Flags::default() };
            }
        }
        combine(a, b, merge_chain)
    }

    pub async fn coins(&self, address: &str) -> Answer<Result<Coins, ApiError>> {
        let (a, b) = together(self.first.coins(address), self.second.coins(address)).await;
        combine(a, b, merge_coins)
    }

    pub async fn tx_status(&self, txid: &str) -> Answer<Result<TxStatus, ApiError>> {
        let (a, b) = together(self.first.tx_status(txid), self.second.tx_status(txid)).await;
        // Unknown only when both say unknown: it must not wipe out a payment not yet settled.
        if matches!((&a, &b), (Ok(TxStatus::Unknown), Err(_)) | (Err(_), Ok(TxStatus::Unknown))) {
            let error = a.err().or_else(|| b.err()).expect("one source failed");
            return Answer { value: Err(error), flags: Flags { one_source: true, disagree: false } };
        }
        combine(a, b, merge_status)
    }

    pub async fn proof(&self, txid: &str) -> Answer<Result<u32, ApiError>> {
        let mut best = None;
        let mut flags = Flags::default();
        for (index, api) in [&self.first, &self.second].into_iter().enumerate() {
            if let Ok(Some(answer)) = api.proof(txid).await {
                #[cfg(not(test))]
                let verified = proof::verify(txid, &answer);
                #[cfg(test)]
                let verified = (self.verify_proof)(txid, &answer);
                if let Ok(blocks) = verified {
                    if best.is_none_or(|count| blocks > count) {
                        best = Some(blocks);
                        flags.one_source = index != 0;
                    }
                    if blocks >= proof::REQUIRED_BLOCKS { break; }
                }
            }
        }
        Answer { value: best.ok_or(ApiError::Malformed), flags }
    }

    pub async fn broadcast(&self, hex: &str, txid: &str) -> Answer<BroadcastResult> {
        let (a, b) = together(self.first.broadcast(hex, txid), self.second.broadcast(hex, txid)).await;
        let answered = |r: &BroadcastResult| matches!(r, BroadcastResult::Sent { .. } | BroadcastResult::Rejected { .. });
        let flags = Flags { one_source: answered(&a) != answered(&b), disagree: answered(&a) && answered(&b) && a != b };
        Answer { value: merge_broadcast(a, b), flags }
    }

    pub async fn check(&self, hex: &str) -> Answer<CheckResult> {
        let first = self.first.check(hex).await;
        if !matches!(first, CheckResult::Failed { .. }) {
            return Answer { value: first, flags: Flags::default() };
        }
        let second = self.second.check(hex).await;
        let flags = Flags { one_source: !matches!(second, CheckResult::Failed { .. }), disagree: false };
        Answer { value: second, flags }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::api::tests::{response, serve, serve_with, utxo};
    use crate::chain::tests::state;
    use crate::p2mr::Path;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};
    use tauri::async_runtime::block_on;

    pub(crate) fn down() -> Api {
        let (api, server) = serve(vec![]);
        server.join().unwrap();
        api
    }

    pub(crate) fn synthetic_sources(first: Api, second: Api) -> Sources {
        Sources { verify_proof: proof::tests::verify_synthetic, ..Sources::new(first, second) }
    }

    pub(crate) fn coins(utxos: Vec<Value>) -> String {
        json!({"utxos": utxos, "unconfirmed": [], "unconfirmed_complete": true, "truncated": false}).to_string()
    }

    #[test]
    fn reads_and_broadcasts_wait_for_both_requests_before_either_reply() {
        let txid = "a".repeat(64);
        for operation in 0..4 {
            let count = Arc::new(AtomicUsize::new(0));
            let gate = |count: Arc<AtomicUsize>| move || {
                count.fetch_add(1, Ordering::SeqCst);
                let deadline = Instant::now() + Duration::from_secs(5);
                while count.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(1));
                }
                assert_eq!(count.load(Ordering::SeqCst), 2, "both requests must be in flight");
            };
            let body = match operation {
                0 => state(40_000, false).to_string(),
                1 => coins(vec![]),
                2 => json!({"status": "mempool"}).to_string(),
                _ => json!({"txid": txid}).to_string(),
            };
            let (a, first) = serve_with(vec![response(200, &body)], gate(count.clone()));
            let (b, second) = serve_with(vec![response(200, &body)], gate(count));
            let sources = Sources::new(a, b);
            block_on(async {
                match operation {
                    0 => { sources.state().await.value.unwrap(); }
                    1 => { sources.coins("tb1ztest").await.value.unwrap(); }
                    2 => { sources.tx_status(&txid).await.value.unwrap(); }
                    _ => { assert!(matches!(sources.broadcast("00", &txid).await.value, BroadcastResult::Sent { .. })); }
                }
            });
            assert_eq!(first.join().unwrap().len(), 1);
            assert_eq!(second.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn lower_tip_controls_activation_and_six_blocks_is_the_boundary() {
        for (a, b, disagree) in [(30_006, 30_012, false), (30_013, 30_006, true), (8_605, 8_612, true)] {
            let (left, first) = serve(vec![response(200, &state(a, false).to_string())]);
            let (right, second) = serve(vec![response(200, &state(b, false).to_string())]);
            let answer = block_on(Sources::new(left, right).state());
            first.join().unwrap();
            second.join().unwrap();
            assert_eq!(answer.flags, Flags { one_source: false, disagree });
            let chain = answer.value.unwrap();
            assert_eq!(chain.tip, a.min(b));
            assert_eq!(chain.tripwire_tip, Some(a.min(b)));
            assert_eq!(chain.mldsa44_allowed, a.min(b) >= 8_606);
            assert_eq!(chain.mixed_allowed, a.min(b) >= 30_006);
        }
    }

    #[test]
    fn either_tripwire_wins_and_unknown_never_opens_the_mixed_address() {
        for reverse in [false, true] {
            for unknown in [false, true] {
                let a = state(40_000, true);
                let mut b = state(40_000, false);
                if unknown { b.as_object_mut().unwrap().remove("tripwire"); }
                let (a, b) = if reverse { (b, a) } else { (a, b) };
                let (left, first) = serve(vec![response(200, &a.to_string())]);
                let (right, second) = serve(vec![response(200, &b.to_string())]);
                let answer = block_on(Sources::new(left, right).state());
                first.join().unwrap();
                second.join().unwrap();
                assert!(answer.flags.disagree && !answer.flags.one_source);
                let chain = answer.value.unwrap();
                assert_eq!(chain.ec_disabled, Some(true));
                assert_eq!(chain.mixed_path(), Some(Path::Mldsa44));
                assert_eq!(chain.mixed_allowed, !unknown);
                assert!(!chain.tripwires[0].unspent);
            }
        }
    }

    #[test]
    fn tripwire_merge_keeps_the_union_and_either_missing_state_in_both_orders() {
        let wire = |c: char, status| json!({"outpoint": format!("{}:0", c.to_string().repeat(64)), "state": status});
        let mut a = state(40_000, false);
        let mut b = state(40_001, true);
        a["tripwire"]["tripwires"] = json!([wire('a', "unspent"), wire('b', "unspent")]);
        b["tripwire"]["tripwires"] = json!([wire('b', "missing"), wire('c', "unspent")]);
        for reverse in [false, true] {
            let (a, b) = if reverse { (&b, &a) } else { (&a, &b) };
            let (chain, disagree) = merge_chain(chain::check(a).unwrap(), chain::check(b).unwrap());
            assert!(disagree);
            assert_eq!((chain.tip, chain.tripwire_tip, chain.ec_disabled), (40_000, Some(40_000), Some(true)));
            assert!(chain.mixed_allowed);
            assert_eq!(chain.tripwires.len(), 3);
            let wires = chain.tripwires.iter().map(|t| (t.outpoint.clone(), t.unspent)).collect::<HashMap<_, _>>();
            assert_eq!(wires, HashMap::from([
                (format!("{}:0", "a".repeat(64)), true),
                (format!("{}:0", "b".repeat(64)), false),
                (format!("{}:0", "c".repeat(64)), true),
            ]));
        }
        let mut b = a.clone();
        b["tripwire"]["tripwires"].as_array_mut().unwrap().reverse();
        let (chain, disagree) = merge_chain(chain::check(&a).unwrap(), chain::check(&b).unwrap());
        assert!(!disagree);
        assert_eq!(chain.tripwires, chain::check(&a).unwrap().tripwires);
    }

    #[test]
    fn a_wrong_or_malformed_chain_is_fatal_even_with_a_good_peer() {
        let good = state(40_000, false);
        let mut wrong = good.clone();
        wrong["signet_challenge"] = json!("51");
        let mut inactive = good.clone();
        inactive["deployments"]["p2mr"]["active"] = json!(false);
        let mut heights = good.clone();
        heights["deployments"]["p2mr_mldsa44"]["height"] = json!(1);
        for (bad, expected) in [(json!({}), ChainProblem::WrongChain), (json!([]), ChainProblem::WrongChain),
            (wrong, ChainProblem::WrongChain), (heights, ChainProblem::WrongChain), (inactive, ChainProblem::P2mrInactive)] {
            for reverse in [false, true] {
                let (a, b) = if reverse { (&good, &bad) } else { (&bad, &good) };
                let (left, first) = serve(vec![response(200, &a.to_string())]);
                let (right, second) = serve(vec![response(200, &b.to_string())]);
                let answer = block_on(Sources::new(left, right).state());
                first.join().unwrap();
                second.join().unwrap();
                assert_eq!(answer.value, Err(StateError::Chain(expected)));
            }
        }
    }

    #[test]
    fn amounts_must_match_and_pending_and_incoming_are_unions() {
        let pending = |c, sats, by| {
            let mut u = utxo(c, 0, sats);
            u["spent_in_mempool"] = json!(true);
            u["spent_by"] = json!(by);
            u
        };
        let incoming = |c: char, sats| json!({"txid": c.to_string().repeat(64), "vout": 0, "sats": sats});
        let a = json!({"utxos": [utxo('a', 0, 1000), utxo('b', 0, 2000), utxo('c', 0, 3000),
            pending('d', 4000, "f".repeat(64)), utxo('e', 0, 5000)],
            "unconfirmed": [incoming('1', 100), incoming('2', 200)], "unconfirmed_complete": true});
        let b = json!({"utxos": [utxo('a', 0, 1000), utxo('b', 0, 2001),
            pending('d', 4000, "f".repeat(64)), pending('e', 5000, "1".repeat(64)), pending('f', 6000, "2".repeat(64))],
            "unconfirmed": [incoming('2', 200), incoming('3', 300)], "unconfirmed_complete": false, "truncated": true});
        for reverse in [false, true] {
            let (a, b) = if reverse { (&b, &a) } else { (&a, &b) };
            let (left, first) = serve(vec![response(200, &a.to_string())]);
            let (right, second) = serve(vec![response(200, &b.to_string())]);
            let answer = block_on(Sources::new(left, right).coins("tb1ztest"));
            first.join().unwrap();
            second.join().unwrap();
            assert_eq!(answer.flags, Flags { one_source: false, disagree: true });
            let found = answer.value.unwrap();
            assert_eq!(found.spendable, vec![Coin { txid: "a".repeat(64), vout: 0, sats: 1000, height: 10 }]);
            assert_eq!(found.pending.len(), 3);
            assert_eq!(found.pending.iter().map(|c| c.sats).sum::<u64>(), 15_000);
            assert_eq!(found.spent_by.len(), 3);
            assert_eq!(found.incoming.len(), 3);
            assert_eq!(found.incoming.iter().map(|i| i.sats).sum::<u64>(), 600);
            assert!(found.truncated && !found.incoming_complete);
        }
    }

    #[test]
    fn list_order_is_not_disagreement_and_flags_belong_to_one_operation() {
        let a = coins(vec![utxo('a', 0, 1000), utxo('b', 0, 2000)]);
        let b = coins(vec![utxo('b', 0, 2000), utxo('a', 0, 1000)]);
        let (left, first) = serve(vec![response(200, &a), response(200, &a)]);
        let (right, second) = serve(vec![response(500, "{}"), response(200, &b)]);
        let sources = Sources::new(left, right);
        let (failed, agreed) = block_on(async { (sources.coins("x").await, sources.coins("x").await) });
        first.join().unwrap();
        second.join().unwrap();
        assert!(failed.value.is_ok() && failed.flags.one_source);
        assert_eq!(agreed.flags, Flags::default());
        assert_eq!(agreed.value.unwrap().spendable.len(), 2);
    }

    #[test]
    fn statuses_choose_the_furthest_and_unknown_requires_two_answers() {
        let bodies = [json!({"status": "unknown"}), json!({"status": "mempool"}),
            json!({"status": "confirmed", "confirmations": 2}), json!({"status": "confirmed", "confirmations": 10})];
        let statuses = [TxStatus::Unknown, TxStatus::Mempool, TxStatus::Confirmed { confirmations: 2 }, TxStatus::Confirmed { confirmations: 10 }];
        let mut left = Vec::new();
        let mut right = Vec::new();
        for a in &bodies {
            for b in &bodies {
                left.push(response(200, &a.to_string()));
                right.push(response(200, &b.to_string()));
            }
        }
        left.push(response(200, &bodies[0].to_string()));
        right.push(response(500, "{}"));
        left.push(response(500, "{}"));
        right.push(response(200, &bodies[0].to_string()));
        let (a, first) = serve(left);
        let (b, second) = serve(right);
        let sources = Sources::new(a, b);
        let answers = block_on(async {
            let mut answers = Vec::new();
            for _ in 0..18 { answers.push(sources.tx_status(&"a".repeat(64)).await); }
            answers
        });
        first.join().unwrap();
        second.join().unwrap();
        for a in 0..4 {
            for b in 0..4 {
                assert_eq!(answers[a * 4 + b].value, Ok(statuses[a.max(b)].clone()));
                assert_eq!(answers[a * 4 + b].flags, Flags { one_source: false, disagree: a != b });
            }
        }
        for answer in &answers[16..] { assert!(answer.value.is_err() && answer.flags.one_source); }
    }

    #[test]
    fn one_node_down_is_used_in_either_position_and_two_down_fail() {
        for reverse in [false, true] {
            let txid = "a".repeat(64);
            let (live, server) = serve(vec![response(200, &state(40_000, false).to_string()),
                response(200, &coins(vec![utxo('a', 0, 1000)])), response(200, r#"{"status":"mempool"}"#),
                response(200, &json!({"txid": txid}).to_string()), response(200, r#"{"allowed":true,"vsize":100,"fee":200}"#)]);
            let sources = if reverse { Sources::new(down(), live) } else { Sources::new(live, down()) };
            let (state, coins, status, broadcast, check) = block_on(async {
                (sources.state().await, sources.coins("x").await, sources.tx_status(&txid).await,
                    sources.broadcast("00", &txid).await, sources.check("00").await)
            });
            server.join().unwrap();
            assert!(state.value.is_ok() && state.flags.one_source);
            assert_eq!(coins.value.unwrap().spendable.len(), 1);
            assert!(coins.flags.one_source);
            assert_eq!(status.value, Ok(TxStatus::Mempool));
            assert!(status.flags.one_source);
            assert!(matches!(broadcast.value, BroadcastResult::Sent { .. }) && broadcast.flags.one_source);
            assert!(matches!(check.value, CheckResult::Allowed { .. }));
            assert_eq!(check.flags.one_source, reverse);
        }
        let sources = Sources::new(down(), down());
        block_on(async {
            assert!(sources.state().await.value.is_err());
            assert!(sources.coins("x").await.value.is_err());
            assert!(sources.tx_status(&"a".repeat(64)).await.value.is_err());
            assert!(sources.proof(&"a".repeat(64)).await.value.is_err());
            assert_eq!(sources.broadcast("00", &"a".repeat(64)).await.value, BroadcastResult::Unknown);
            assert!(matches!(sources.check("00").await.value, CheckResult::Failed { .. }));
        });
    }

    #[test]
    fn malformed_and_http_errors_are_failures_and_do_not_mask_bad_chains() {
        for bad in [response(200, "not JSON"), response(500, "{}"), response(429, r#"{"error":"limit"}"#)] {
            let (a, first) = serve(vec![bad.clone(), bad.clone(), bad]);
            let (b, second) = serve(vec![response(200, &state(40_000, false).to_string()),
                response(200, &coins(vec![])), response(200, r#"{"status":"confirmed","confirmations":2}"#)]);
            let sources = Sources::new(a, b);
            let (state, coins, status) = block_on(async {
                (sources.state().await, sources.coins("x").await, sources.tx_status(&"a".repeat(64)).await)
            });
            first.join().unwrap();
            second.join().unwrap();
            assert!(state.value.is_ok() && state.flags.one_source);
            assert!(coins.value.is_ok() && coins.flags.one_source);
            assert!(status.value.is_ok() && status.flags.one_source);
        }
        let (bad, server) = serve(vec![response(200, "{}")]);
        let answer = block_on(Sources::new(down(), bad).state());
        server.join().unwrap();
        assert_eq!(answer.value, Err(StateError::Chain(ChainProblem::WrongChain)));
        let (a, first) = serve(vec![response(200, "{}"), response(200, "{}")]);
        let (b, second) = serve(vec![response(200, &coins(vec![])), response(200, r#"{"status":"mempool"}"#)]);
        let sources = Sources::new(a, b);
        let (coins, status) = block_on(async { (sources.coins("x").await, sources.tx_status(&"a".repeat(64)).await) });
        first.join().unwrap();
        second.join().unwrap();
        assert!(coins.value.is_ok() && coins.flags.one_source);
        assert!(status.value.is_ok() && status.flags.one_source);
    }

    #[test]
    fn every_broadcast_combination_and_both_origins() {
        let txid = "a".repeat(64);
        let responses = [response(200, &json!({"txid": txid}).to_string()),
            response(422, r#"{"error":"rejected","reason":"bad-input"}"#), response(503, r#"{"error":"unavailable"}"#), response(500, "{}")];
        let mut left = Vec::new();
        let mut right = Vec::new();
        for a in &responses {
            for b in &responses { left.push(a.clone()); right.push(b.clone()); }
        }
        let (a, first) = serve(left);
        let (b, second) = serve(right);
        let (first_base, second_base) = (a.base().to_string(), b.base().to_string());
        let sources = Sources::new(a, b);
        let answers = block_on(async {
            let mut answers = Vec::new();
            for _ in 0..16 { answers.push(sources.broadcast("00", &txid).await.value); }
            answers
        });
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        // Rows and columns are sent, rejected, failed, unknown; an unknown outcome never becomes a certain refusal.
        let expected = [[0, 0, 0, 0], [0, 1, 1, 3], [0, 1, 2, 3], [0, 3, 3, 3]];
        for (i, answer) in answers.iter().enumerate() {
            let kind = match answer {
                BroadcastResult::Sent { txid: sent } => { assert_eq!(sent, &txid); 0 }
                BroadcastResult::Rejected { reason } => { assert_eq!(reason, "bad-input"); 1 }
                BroadcastResult::Failed { error } => { assert_eq!(error, "unavailable"); 2 }
                BroadcastResult::Unknown => 3,
            };
            assert_eq!(kind, expected[i / 4][i % 4], "broadcast pair {i}");
        }
        for (requests, base) in [(first, first_base), (second, second_base)] {
            assert_eq!(requests.len(), 16);
            for request in requests {
                assert!(request.starts_with("POST /api/broadcast HTTP/1.1\r\n"));
                assert!(request.to_lowercase().contains(&format!("\r\norigin: {base}\r\n")));
            }
        }
    }

    #[test]
    fn check_uses_the_second_only_after_a_failure() {
        let allowed = response(200, r#"{"allowed":true,"vsize":100,"fee":200}"#);
        let rejected = response(200, r#"{"allowed":false,"reason":"bad-input"}"#);
        let (a, first) = serve(vec![allowed.clone(), rejected.clone(), response(500, "{}"), response(200, "{}"), response(500, "{}")]);
        let (b, second) = serve(vec![allowed, rejected, response(429, r#"{"error":"limit"}"#)]);
        let sources = Sources::new(a, b);
        let answers = block_on(async {
            let mut answers = Vec::new();
            for _ in 0..5 { answers.push(sources.check("00").await); }
            answers
        });
        assert_eq!(first.join().unwrap().len(), 5);
        assert_eq!(second.join().unwrap().len(), 3);
        assert_eq!(answers[0].value, CheckResult::Allowed { vsize: 100, fee: 200 });
        assert_eq!(answers[1].value, CheckResult::Rejected { reason: "bad-input".into() });
        assert!(!answers[0].flags.one_source && !answers[1].flags.one_source);
        assert_eq!(answers[2].value, answers[0].value);
        assert_eq!(answers[3].value, answers[1].value);
        assert!(answers[2].flags.one_source && answers[3].flags.one_source);
        assert_eq!(answers[4].value, CheckResult::Failed { error: "limit".into() });
    }

    #[test]
    fn proof_keeps_the_longest_verified_answer_and_stops_at_six_blocks() {
        let full = proof::tests::chain(proof::REQUIRED_BLOCKS);
        let txid = full["txid"].as_str().unwrap();
        let shortened = |count: u32| {
            let mut answer = full.clone();
            answer["tip"] = json!(answer["height"].as_u64().unwrap() + u64::from(count) - 1);
            answer["blocks"].as_array_mut().unwrap().truncate(count as usize);
            answer
        };
        for (a, b, expected, fallback) in [(1, 6, 6, true), (1, 5, 5, true), (5, 1, 5, false), (5, 5, 5, false)] {
            let (left, first) = serve(vec![response(200, &shortened(a).to_string())]);
            let (right, second) = serve(vec![response(200, &shortened(b).to_string())]);
            let answer = block_on(synthetic_sources(left, right).proof(txid));
            assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (1, 1));
            assert_eq!(answer.value, Ok(expected));
            assert_eq!(answer.flags, Flags { one_source: fallback, disagree: false });
        }
        // A full proof from the first API: the second is never asked (its socket listens, nothing connects).
        let (left, first) = serve(vec![response(200, &shortened(proof::REQUIRED_BLOCKS).to_string())]);
        let (right, listener) = crate::api::tests::idle();
        let answer = block_on(synthetic_sources(left, right).proof(txid));
        assert_eq!(first.join().unwrap().len(), 1);
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
        assert_eq!(answer.value, Ok(proof::REQUIRED_BLOCKS));
        assert_eq!(answer.flags, Flags::default());
        let mut bad = full.clone();
        bad["blocks"][0]["coinbase_branch"] = json!(["ab".repeat(32)]);
        for reply in [response(200, &bad.to_string()), response(404, r#"{"error":"not_found"}"#), response(500, "{}")] {
            let (left, first) = serve(vec![response(200, &shortened(5).to_string())]);
            let (right, second) = serve(vec![reply]);
            let answer = block_on(synthetic_sources(left, right).proof(txid));
            assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (1, 1));
            assert_eq!(answer.value, Ok(5));
            assert_eq!(answer.flags, Flags::default());
        }
    }

    #[test]
    fn proof_falls_back_on_absence_errors_and_invalid_proofs() {
        let proof = proof::tests::real_proof();
        let txid = proof["txid"].as_str().unwrap();
        let good = response(200, &proof.to_string());
        let mut bad = proof.clone();
        bad["blocks"][0]["coinbase_branch"] = json!(["ab".repeat(32)]);
        let (a, first) = serve(vec![good.clone(), response(200, &bad.to_string()), response(200, "{}"),
            response(404, r#"{"error":"not_found"}"#), response(500, "{}"), response(200, "not JSON"), response(200, "{}")]);
        let mut fallbacks = vec![good; 6];
        fallbacks.push(response(404, r#"{"error":"not_confirmed"}"#));
        let (b, second) = serve(fallbacks);
        let sources = Sources::new(a, b);
        let answers = block_on(async {
            let mut answers = Vec::new();
            for _ in 0..7 { answers.push(sources.proof(txid).await); }
            answers
        });
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_eq!((first.len(), second.len()), (7, 7));
        for (i, answer) in answers[..6].iter().enumerate() {
            assert_eq!(answer.value, Ok(1));
            assert_eq!(answer.flags.one_source, i != 0);
        }
        assert!(answers[6].value.is_err());
        assert!(first.iter().chain(&second).all(|r| r.starts_with(&format!("GET /api/proof?txid={txid} HTTP/1.1\r\n"))));
    }
}
