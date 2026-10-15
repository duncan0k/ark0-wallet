//! Spends: coin selection, the fee, signing, and the checks a signed transaction passes before it is
//! broadcast. The rules are the web wallet's (spend.ts): version 2, every input at nSequence 0xfffffffd,
//! nLockTime from the chain (chain.rs), 2 sat/vB, at most 100,000 bytes, SIGHASH_DEFAULT, every signature
//! checked here before the transaction leaves.
use crate::api::Coin;
use crate::keys::{KeyError, Keys};
use crate::p2mr::{Destination, Kind, Leaf, Path, Template, MLDSA44_KEY_VERSION, MLDSA44_SIGNATURE_CHUNKS, SCHNORR_KEY_VERSION};
use crate::tx::{display_hex, mldsa44_witness, schnorr_witness, script_path_sighash, OutPoint, Sizes, Transaction, TxIn, TxOut, SEQUENCE};
use serde::Serialize;

/// Ark-0 has no fee market; the joining guide pays 2 as well.
pub const FEE_RATE: u64 = 2;
/// The largest transaction built, serialized, and the most the broadcast API takes.
pub const MAX_TX_BYTES: usize = 100_000;
/// Change smaller than this is left to the fee instead.
pub const CHANGE_DUST: u64 = 330;

/// One of the wallet's addresses, with the leaf its spends take.
#[derive(Clone, Debug)]
pub struct Account {
    pub template: Template,
    pub path: Path,
}

impl Account {
    pub fn new(template: Template, path: Path) -> Option<Account> {
        template.leaf(path)?;
        Some(Account { template, path })
    }

    pub fn kind(&self) -> Kind {
        self.template.kind
    }

    pub fn leaf(&self) -> &Leaf {
        self.template.leaf(self.path).expect("checked in new")
    }

    fn spent_output(&self, coin: &Coin) -> TxOut {
        TxOut { sats: coin.sats, script_pubkey: self.template.script_pubkey.clone() }
    }

    /// Witness elements of the sizes the real ones will have.
    fn placeholder_witness(&self) -> Vec<Vec<u8>> {
        let leaf = self.leaf();
        let mut w: Vec<Vec<u8>> = match self.path {
            Path::Schnorr => vec![vec![0; 64]],
            Path::Mldsa44 => MLDSA44_SIGNATURE_CHUNKS.iter().map(|&n| vec![0; n]).collect(),
        };
        w.push(leaf.script.clone());
        w.push(leaf.control_block.clone());
        w
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Amount {
    Sats(u64),
    /// Everything the coins hold, less the fee.
    All,
}

#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    /// The coins spent, largest first.
    pub coins: Vec<Coin>,
    /// The destination first, then the change if there is any.
    pub outputs: Vec<(u64, Vec<u8>)>,
    pub send: u64,
    pub change: u64,
    pub fee: u64,
    pub sizes: Sizes,
    /// Coins of a "send everything" that did not fit in one transaction.
    pub left: usize,
    pub lock_time: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanError {
    NoCoins,
    /// The coins do not cover the amount and the fee.
    Insufficient,
    /// The coins needed do not fit in one transaction.
    TooLarge,
    /// The amount, or all there is less the fee, is below the destination's dust limit.
    BelowDust,
}

pub fn unsigned_transaction(coins: &[Coin], outputs: &[(u64, Vec<u8>)], lock_time: u32) -> Transaction {
    Transaction {
        version: 2,
        lock_time,
        inputs: coins
            .iter()
            .map(|c| TxIn { prevout: OutPoint::from_display(&c.txid, c.vout).expect("a checked txid"), sequence: SEQUENCE, witness: vec![] })
            .collect(),
        outputs: outputs.iter().map(|(sats, spk)| TxOut { sats: *sats, script_pubkey: spk.clone() }).collect(),
    }
}

/// Sizes of the transaction once signed.
pub fn measure(account: &Account, coins: &[Coin], outputs: &[(u64, Vec<u8>)], lock_time: u32) -> Sizes {
    let mut tx = unsigned_transaction(coins, outputs, lock_time);
    for input in &mut tx.inputs {
        input.witness = account.placeholder_witness();
    }
    tx.sizes()
}

fn fee_of(sizes: &Sizes) -> u64 {
    sizes.vsize as u64 * FEE_RATE
}

/// Coins for a spend from one account, largest first, and the outputs (planSpend in spend.ts). The coins
/// of `coins` that are also in `required` are all spent, before any other.
pub fn plan_spend(
    account: &Account,
    coins: &[Coin],
    required: &[Coin],
    destination: &Destination,
    amount: Amount,
    lock_time: u32,
) -> Result<Plan, PlanError> {
    let mut sorted = coins.to_vec();
    sorted.sort_by(|a, b| b.sats.cmp(&a.sats).then_with(|| a.txid.cmp(&b.txid)).then_with(|| a.vout.cmp(&b.vout)));
    sorted.sort_by_key(|c| !required.contains(c));
    let must = sorted.iter().take_while(|c| required.contains(c)).count();
    if sorted.is_empty() {
        return Err(PlanError::NoCoins);
    }
    let pay = |sats: u64| (sats, destination.script_pubkey.clone());
    let back = |sats: u64| (sats, account.template.script_pubkey.clone());
    let mut chosen: Vec<Coin> = Vec::new();
    let mut total: u64 = 0;
    let plan = |chosen: &[Coin], outputs: Vec<(u64, Vec<u8>)>, send, change, fee, sizes, left| Plan {
        coins: chosen.to_vec(),
        outputs,
        send,
        change,
        fee,
        sizes,
        left,
        lock_time,
    };

    match amount {
        Amount::All => {
            for coin in &sorted {
                let mut trial = chosen.clone();
                trial.push(coin.clone());
                if measure(account, &trial, &[pay(0)], lock_time).size > MAX_TX_BYTES {
                    break;
                }
                chosen = trial;
                total += coin.sats;
            }
            if chosen.is_empty() || chosen.len() < must {
                return Err(PlanError::TooLarge);
            }
            let sizes = measure(account, &chosen, &[pay(0)], lock_time);
            let fee = fee_of(&sizes);
            let send = total.checked_sub(fee).filter(|s| *s >= destination.dust).ok_or(PlanError::BelowDust)?;
            Ok(plan(&chosen, vec![pay(send)], send, 0, fee, sizes, sorted.len() - chosen.len()))
        }
        Amount::Sats(amount) => {
            if amount < destination.dust {
                return Err(PlanError::BelowDust);
            }
            for coin in &sorted {
                chosen.push(coin.clone());
                total += coin.sats;
                let split = measure(account, &chosen, &[pay(amount), back(0)], lock_time);
                if split.size > MAX_TX_BYTES {
                    return Err(PlanError::TooLarge);
                }
                if chosen.len() < must {
                    continue;
                }
                let split_fee = fee_of(&split);
                if let Some(change) = total.checked_sub(amount + split_fee).filter(|c| *c >= CHANGE_DUST) {
                    return Ok(plan(&chosen, vec![pay(amount), back(change)], amount, change, split_fee, split, 0));
                }
                let whole = measure(account, &chosen, &[pay(amount)], lock_time);
                if total >= amount && total - amount >= fee_of(&whole) {
                    return Ok(plan(&chosen, vec![pay(amount)], amount, 0, total - amount, whole, 0));
                }
            }
            Err(PlanError::Insufficient)
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Signed {
    pub hex: String,
    /// Display order.
    pub txid: String,
    pub sizes: Sizes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignError {
    Key(KeyError),
    /// The signed transaction is not the size its fee was set for, or the fee is not the plan's.
    Mismatch,
}

/// Signs every input of `tx` (which spends `coins` of `account`) with `sign`, given the path and the
/// message; the witness goes in place.
fn sign_inputs<F>(tx: &mut Transaction, account: &Account, coins: &[Coin], mut sign: F) -> Result<(), KeyError>
where
    F: FnMut(Path, &[u8; 32]) -> Result<Vec<u8>, KeyError>,
{
    let spent: Vec<TxOut> = coins.iter().map(|c| account.spent_output(c)).collect();
    let leaf = account.leaf();
    let key_version = match account.path {
        Path::Schnorr => SCHNORR_KEY_VERSION,
        Path::Mldsa44 => MLDSA44_KEY_VERSION,
    };
    let messages: Vec<[u8; 32]> = (0..tx.inputs.len()).map(|i| script_path_sighash(tx, i, &spent, &leaf.hash, key_version)).collect();
    for (input, message) in tx.inputs.iter_mut().zip(messages) {
        let signature = sign(account.path, &message)?;
        input.witness = match account.path {
            Path::Schnorr => schnorr_witness(&signature.try_into().map_err(|_| KeyError::NoKey)?, leaf),
            Path::Mldsa44 => mldsa44_witness(&signature, leaf),
        };
    }
    Ok(())
}

fn finish(plan: &Plan, tx: Transaction) -> Result<Signed, SignError> {
    let sizes = tx.sizes();
    let spent: u64 = plan.coins.iter().map(|c| c.sats).sum();
    let paid: u64 = tx.outputs.iter().map(|o| o.sats).sum();
    if sizes != plan.sizes || sizes.size > MAX_TX_BYTES || spent.checked_sub(paid) != Some(plan.fee) || plan.fee < fee_of(&sizes) {
        return Err(SignError::Mismatch);
    }
    Ok(Signed { hex: hex::encode(tx.encode(true)), txid: display_hex(&tx.txid()), sizes })
}

/// Signs a plan with fresh randomness and checks the result against it.
pub fn sign_plan(plan: &Plan, account: &Account, keys: &Keys) -> Result<Signed, SignError> {
    let mut tx = unsigned_transaction(&plan.coins, &plan.outputs, plan.lock_time);
    let kind = account.kind();
    sign_inputs(&mut tx, account, &plan.coins, |path, message| match path {
        Path::Schnorr => keys.sign_schnorr(kind, message).map(|s| s.to_vec()),
        Path::Mldsa44 => keys.sign_mldsa44(kind, message).map(|s| s.to_vec()),
    })
    .map_err(SignError::Key)?;
    finish(plan, tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Secret, SecretBytes};
    use crate::p2mr::tests::{h, vectors};
    use crate::p2mr::{parse_destination, Template};
    use zeroize::Zeroizing;

    fn keys_of(seed_hex: &str) -> Keys {
        let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
        Keys::from_secret(&Secret::Legacy { seed: SecretBytes(Zeroizing::new(seed)) }).unwrap()
    }

    fn account(keys: &Keys, kind: &str, signature: &str) -> Account {
        let path = if signature == "schnorr" { Path::Schnorr } else { Path::Mldsa44 };
        let kind = match kind {
            "schnorr" => Kind::Schnorr,
            "mldsa44" => Kind::Mldsa44,
            _ => Kind::Mixed,
        };
        Account::new(keys.template(kind), path).unwrap()
    }

    /// Every spend of the vectors, signed deterministically, input by input with its own account.
    #[test]
    fn signed_transactions_match_the_reference() {
        let v = vectors();
        let aux: [u8; 32] = h(&v["constants"]["schnorr_aux"]).try_into().unwrap();
        for s in v["spends"].as_array().unwrap() {
            let keys = keys_of(s["seed"].as_str().unwrap());
            let inputs = s["inputs"].as_array().unwrap();
            let coins: Vec<Coin> = inputs
                .iter()
                .map(|i| Coin { txid: i["txid"].as_str().unwrap().into(), vout: i["vout"].as_u64().unwrap() as u32, sats: i["sats"].as_u64().unwrap(), height: 1 })
                .collect();
            let accounts: Vec<Account> = inputs.iter().map(|i| account(&keys, i["account"].as_str().unwrap(), i["signature"].as_str().unwrap())).collect();
            let outputs: Vec<(u64, Vec<u8>)> =
                s["outputs"].as_array().unwrap().iter().map(|o| (o["sats"].as_u64().unwrap(), h(&o["script_pubkey"]))).collect();
            let mut tx = unsigned_transaction(&coins, &outputs, s["lock_time"].as_u64().unwrap() as u32);
            assert_eq!(hex::encode(tx.encode(true)), s["unsigned_hex"].as_str().unwrap());
            // Inputs from different accounts: each signed with the spent outputs of all of them.
            let spent: Vec<TxOut> = coins.iter().zip(&accounts).map(|(c, a)| a.spent_output(c)).collect();
            for (i, a) in accounts.iter().enumerate() {
                let key_version = if a.path == Path::Schnorr { SCHNORR_KEY_VERSION } else { MLDSA44_KEY_VERSION };
                let message = script_path_sighash(&tx, i, &spent, &a.leaf().hash, key_version);
                assert_eq!(hex::encode(message), s["sighashes"][i].as_str().unwrap(), "{} input {i}", s["description"]);
                tx.inputs[i].witness = match a.path {
                    Path::Schnorr => schnorr_witness(&keys.sign_schnorr_with(a.kind(), &message, &aux).unwrap(), a.leaf()),
                    Path::Mldsa44 => mldsa44_witness(&keys.sign_mldsa44_deterministic(a.kind(), &message), a.leaf()),
                };
            }
            assert_eq!(hex::encode(tx.encode(true)), s["signed_hex"].as_str().unwrap(), "{}", s["description"]);
            assert_eq!(display_hex(&tx.txid()), s["txid"].as_str().unwrap());
            assert_eq!(display_hex(&tx.wtxid()), s["wtxid"].as_str().unwrap());
            let sizes = tx.sizes();
            assert_eq!((sizes.size, sizes.base, sizes.weight, sizes.vsize), (
                s["size"].as_u64().unwrap() as usize,
                s["base_size"].as_u64().unwrap() as usize,
                s["weight"].as_u64().unwrap() as usize,
                s["vsize"].as_u64().unwrap() as usize,
            ));
            // The placeholder witness measures the same as the real one.
            if accounts.iter().all(|a| a.path == accounts[0].path && a.kind() == accounts[0].kind()) {
                assert_eq!(measure(&accounts[0], &coins, &outputs, tx.lock_time), sizes);
            }
        }
    }

    fn coins(sats: &[u64]) -> Vec<Coin> {
        sats.iter().enumerate().map(|(i, &s)| Coin { txid: format!("{:064x}", i + 1), vout: 0, sats: s, height: 1 }).collect()
    }

    #[test]
    fn plans_and_signs_like_the_web_wallet() {
        let keys = keys_of(&"11".repeat(32));
        let from = Account::new(keys.template(Kind::Mldsa44), Path::Mldsa44).unwrap();
        let to = parse_destination(&Template::schnorr(&[3u8; 32]).address).unwrap();
        // Change when it is worth keeping.
        let p = plan_spend(&from, &coins(&[50_000, 20_000]), &[], &to, Amount::Sats(10_000), 30000).unwrap();
        assert_eq!((p.coins.len(), p.outputs.len()), (1, 2));
        assert_eq!(p.fee, p.sizes.vsize as u64 * FEE_RATE);
        assert_eq!(p.send + p.change + p.fee, 50_000);
        let signed = sign_plan(&p, &from, &keys).unwrap();
        assert_eq!(signed.sizes, p.sizes);
        // Change below the dust limit goes to the fee.
        let p = plan_spend(&from, &coins(&[13_000]), &[], &to, Amount::Sats(10_800), 30000).unwrap();
        assert_eq!((p.outputs.len(), p.change), (1, 0));
        assert_eq!(p.fee, 13_000 - 10_800);
        // Everything.
        let p = plan_spend(&from, &coins(&[5_000, 7_000]), &[], &to, Amount::All, 30000).unwrap();
        assert_eq!((p.coins.len(), p.left, p.send + p.fee), (2, 0, 12_000));
        assert!(sign_plan(&p, &from, &keys).is_ok());
        // Refusals.
        assert_eq!(plan_spend(&from, &[], &[], &to, Amount::All, 30000).err(), Some(PlanError::NoCoins));
        assert_eq!(plan_spend(&from, &coins(&[1_000]), &[], &to, Amount::Sats(100), 30000).err(), Some(PlanError::BelowDust));
        assert_eq!(plan_spend(&from, &coins(&[1_000]), &[], &to, Amount::Sats(900), 30000).err(), Some(PlanError::Insufficient));
        assert_eq!(plan_spend(&from, &coins(&[2_000]), &[], &to, Amount::All, 30000).err(), Some(PlanError::BelowDust));
    }

    #[test]
    fn required_coins_are_spent_first() {
        let keys = keys_of(&"33".repeat(32));
        let from = Account::new(keys.template(Kind::Schnorr), Path::Schnorr).unwrap();
        let to = parse_destination(&Template::schnorr(&[5u8; 32]).address).unwrap();
        let all = coins(&[50_000, 20_000, 9_000]);
        // The smallest coin is required: it goes first, and the largest covers the rest.
        let p = plan_spend(&from, &all, &all[2..], &to, Amount::Sats(10_000), 0).unwrap();
        assert_eq!(p.coins, vec![all[2].clone(), all[0].clone()]);
        // Two required coins are both spent, though the first covers the amount alone.
        let p = plan_spend(&from, &all, &all[1..], &to, Amount::Sats(1_000), 0).unwrap();
        assert_eq!(p.coins, vec![all[1].clone(), all[2].clone()]);
        // A required coin that is not among the coins requires nothing.
        let elsewhere = Coin { txid: "ff".repeat(32), vout: 0, sats: 1_000, height: 1 };
        let p = plan_spend(&from, &all, &[elsewhere], &to, Amount::Sats(10_000), 0).unwrap();
        assert_eq!(p.coins, vec![all[0].clone()]);
    }

    #[test]
    fn a_tampered_plan_is_not_signed() {
        let keys = keys_of(&"22".repeat(32));
        let from = Account::new(keys.template(Kind::Schnorr), Path::Schnorr).unwrap();
        let to = parse_destination(&Template::schnorr(&[4u8; 32]).address).unwrap();
        let mut p = plan_spend(&from, &coins(&[50_000]), &[], &to, Amount::Sats(10_000), 0).unwrap();
        p.fee += 1;
        assert_eq!(sign_plan(&p, &from, &keys).err(), Some(SignError::Mismatch));
    }
}
