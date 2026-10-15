//! What the node behind the API says about the chain, and what the wallet may do on it.
//!
//! No address is handed out until the node is on Ark-0 (its signet challenge) with P2MR active: a `tb1z`
//! prefix alone says nothing about the rules the node enforces, and where they are not enforced a witness
//! version 2 output is anyone's. The ML-DSA-44 address waits six blocks past M1's height, the mixed one six
//! past M3's, and the mixed one also waits until the drill tripwire's state is known: it decides which of
//! the two leaves a spend can use. These are the web wallet's rules (chain.ts, p2mr-ts).
use crate::keys::ARK0_CHALLENGE;
use crate::p2mr::{Path, TRIPWIRED_LEAF_VERSION};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;

/// Blocks past an activation height before its addresses are handed out: room for a reorganization.
pub const MARGIN: u32 = 6;
// The network has two tripwires: leave room, but take no list of any length from an API.
const MAX_TRIPWIRES: usize = 16;
/// Ark-0's buried deployments: P2MR from block 1, OP_CHECKMLDSA44 (M1) from 8,600, the 0xe0 leaves and
/// the drill's tripwire (M3) from 30,000. They belong to the network the wallet is built for, like its
/// challenge: an API that reports other heights is not describing it, and cannot open an address or set
/// a lock time before the network does.
pub const P2MR_HEIGHT: u32 = 1;
pub const MLDSA44_HEIGHT: u32 = 8_600;
pub const TRIPWIRE_HEIGHT: u32 = 30_000;

/// M2 ??????????????? ML-DSA-44 ???
pub const PQBLOCK_HEIGHT: u32 = 20_000;
pub const PQBLOCK_KEY: &str = concat!(
    "b92b2c1f1eca027e10bcb4f379c98691585d9d9479cbf2c76a1ba1c10fcc4692",
    "9a4b2ad4a17e065f0948a95ccf4e33b9aa8598ac2db4c8e8b8683528e6dde8b9",
    "121f466d53b924fa926a81ba5ee4439d42ddca021c49dd708189ec800c7a0c97",
    "ed7ff61ea8b63b2ada6725a9d5742c612a95fa2b4d47ec12568c1a7dbb853cae",
    "82c67132869102e8e807d9010dab70bf4479bd97de88698393f52b388569bba6",
    "7324ccec2301cd82cfde4baf1ae6772e51d87cfd1f28377573540b7f21bcccc3",
    "0d48a8325f58b5ad64d1e97fc948a5ed491a5ebfd7c9273b16afae6228af4663",
    "c4fae55749ee4b30cd5e8b63bfed6ee81b5e9703d9cd5df3c1042c9217ce54cd",
    "d174ff3df75030cbc4cb949ba5ff85c8890a9d97db9329bf43178a5d7c0ddefa",
    "35df0cafa587cab73d6d16e072931df07ac5d7a93c067de13b5f1e018d0e3079",
    "7c1308688b97a0ad11759915c4c27a0d46df710fb365f5e63801f1b3ba61776a",
    "3f4887e96a904ae0bab70225ff1fd8c089d3fc4fa36f9c63568d1891ed9706f5",
    "0b9345a4ff892d6e42631f283d92ab37a59c10e7923c193ba138b02fe013ff43",
    "a7ddbe31f9e66cc07875f13dd279d8874a7821dc0c50fb1be4a2862ba4a1b1ac",
    "43d7cfcccba701f8e2e5fd820c23a8f4cdfa0334deacc74e518686025d721440",
    "368551e527617472ba07995e1dba85d0a5edb9d76893321f20193f9f3dbbe5ef",
    "c2ec488ca3fd85bfde0976d72d4974874e972976df8b7e3c93a1b0c0a3f7b65b",
    "74975537faf97f5118cbbbb057eda8be2d07bf872b1ca92b401b0e83aed98d49",
    "c1e2dafb9d4fba5e2134048895b8b3af408043f487203bcd4e73bbb51a9eb991",
    "01e4299ba95a71b533f1736836acfb39bbd4360aa4fac599f0f436559e44ba83",
    "0f3f398052afa84bfe52d9b501163a81bcfdbe55a0da2998dfe28605fb48e751",
    "865251e004d13f09f59044ca12d8276813ac07ea02b1015ecbce907de6a03bf2",
    "e2a3d26d8c55cac17717e9b6480de4a8fc278601b25e1700d0454446b61f722f",
    "edff052e90fa189df0316b03dad33c78d5a940d9f0e1c83f06f3f8a49a005e42",
    "73fcd4dc586151a92ae716004d27bd25373a4fa3cfcd6789087587dfba504927",
    "425dd159e378e32a52b3d94f59c8a7073c84c170a80348df9f99503d76fa87b9",
    "989b21e81a95b657ad1909ff11751ebcd9abd2ccd7fb94d1ecc4fdf46fd98641",
    "33fa79bb87562decdba3383b414524cb2a6839b55c7424209b61736160504b3c",
    "c9f9cd3313baf2d96341b84c9cbd71c5271ba7b089ab05abd30ad20a50d311c4",
    "8dca40fcdeb0590ace32b5eed15a37854ed9d60b12343c9d0281ee48d8ec2a3a",
    "f4d2e5ca335481b880ec513735c0d06126e406b5ed8efb74400c5fdfb88a6f24",
    "8dd223e054a3e477687fa944cf395d1adf1a77862a029684c1544c4f09473e5d",
    "f21077d25c843223839ecf98b86c37cdec05c7f18e7d7683af3f803b9f24dd7d",
    "032876f57d41ce2ef425ea8b1c4baee134eefca561c537e0b6706839a079fcd5",
    "780cd3e6728724f22a35b6971057e09a1b5b9dae4b8ca3e8f87dad31d06d5285",
    "3d037e2a33d4997f65a6cef50bc6c2e4e28b1476c09f61206046436a684a47d5",
    "28ceb5305e9180d8274a04b1810e39d09cc72663897e2e73ed0afd0377fe428e",
    "46e3b4bcdc720d96e9f513ef62c535a776300ebfdf6e308512ee99b2806a616d",
    "249b13d0872c5387e033081dce811b9af597243154788b6982d950ef72b57bff",
    "c619b712e33df29b7b39ba04931068783e2bcac08011e9ef4a5b8875dccbc4cc",
    "fc8974a6e31d3270043e779b5e3bdabd40f01cfc0f7438937d505a2897cdf0dc",
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Tripwire {
    pub outpoint: String,
    pub unspent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Chain {
    pub tip: u32,
    /// When the tip block was made, seconds since 1970.
    pub tip_time: Option<u64>,
    /// M1: from here the node runs OP_CHECKMLDSA44.
    pub mldsa44_height: Option<u32>,
    pub mldsa44_allowed: bool,
    /// M3: from here the node runs leaves of version 0xe0.
    pub tripwire_height: Option<u32>,
    /// The tip the tripwire state was read at (the gate of the mixed address goes by it).
    pub tripwire_tip: Option<u32>,
    /// Whether elliptic-curve checks in 0xe0 leaves fail from the next block on; None when unknown.
    pub ec_disabled: Option<bool>,
    pub tripwires: Vec<Tripwire>,
    pub mixed_allowed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainProblem {
    /// Another chain, or an answer that does not say which.
    WrongChain,
    /// Ark-0, but without P2MR active.
    P2mrInactive,
}

fn height(v: &Value) -> Option<u32> {
    v.as_u64().and_then(|n| u32::try_from(n).ok())
}

/// A buried deployment's height, as getdeploymentinfo gives it.
fn buried(deployments: &Value, name: &str) -> Option<u32> {
    let d = deployments.get(name)?;
    if d.get("type")?.as_str()? != "buried" {
        return None;
    }
    height(d.get("height")?)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_outpoint(s: &str) -> bool {
    match s.split_once(':') {
        Some((txid, vout)) => is_hex64(txid) && !vout.is_empty() && vout.len() <= 6 && vout.bytes().all(|b| b.is_ascii_digit()) && (vout == "0" || !vout.starts_with('0')),
        None => false,
    }
}

/// The tripwire state when every field is of its type; None otherwise (it is then unknown).
fn tripwire_state(v: &Value) -> Option<(u32, u32, String, bool, Vec<Tripwire>)> {
    let tip_hash = v.get("tip_hash")?.as_str()?;
    if !is_hex64(tip_hash) {
        return None;
    }
    let list = v.get("tripwires")?.as_array()?;
    if list.is_empty() || list.len() > MAX_TRIPWIRES {
        return None;
    }
    let mut tripwires = Vec::new();
    let mut seen = HashSet::new();
    for t in list {
        let outpoint = t.get("outpoint")?.as_str()?;
        let unspent = match t.get("state")?.as_str()? {
            "unspent" => true,
            "missing" => false,
            _ => return None,
        };
        if !is_outpoint(outpoint) || !seen.insert(outpoint) {
            return None;
        }
        tripwires.push(Tripwire { outpoint: outpoint.to_string(), unspent });
    }
    Some((
        height(v.get("tip_height")?)?,
        height(v.get("height")?)?,
        v.get("leaf_version")?.as_str()?.to_string(),
        v.get("ec_disabled_next_block")?.as_bool()?,
        tripwires,
    ))
}

/// The chain the API's /api/state describes, when it is Ark-0 with P2MR active.
pub fn check(state: &Value) -> Result<Chain, ChainProblem> {
    let tip = state.get("blocks").and_then(height).ok_or(ChainProblem::WrongChain)?;
    if state.get("chain").and_then(Value::as_str) != Some("signet")
        || state.get("signet_challenge").and_then(Value::as_str) != Some(ARK0_CHALLENGE)
    {
        return Err(ChainProblem::WrongChain);
    }
    let deployments = state.get("deployments").filter(|d| d.is_object()).ok_or(ChainProblem::WrongChain)?;
    if deployments.get("p2mr").and_then(|p| p.get("active")).and_then(Value::as_bool) != Some(true) {
        return Err(ChainProblem::P2mrInactive);
    }
    if buried(deployments, "p2mr") != Some(P2MR_HEIGHT)
        || buried(deployments, "p2mr_mldsa44") != Some(MLDSA44_HEIGHT)
        || buried(deployments, "p2mr_tripwire") != Some(TRIPWIRE_HEIGHT)
    {
        return Err(ChainProblem::WrongChain);
    }
    let (mldsa44_height, tripwire_height) = (Some(MLDSA44_HEIGHT), Some(TRIPWIRE_HEIGHT));
    // The state counts only for the height and leaf version the mixed address is built for, read at a
    // tip the node has reached.
    let known = state.get("tripwire").and_then(tripwire_state).filter(|(at, h3, leaf, _, _)| {
        *at <= tip && Some(*h3) == tripwire_height && *leaf == format!("{TRIPWIRED_LEAF_VERSION:x}")
    });
    let tripwire_tip = known.as_ref().map(|k| k.0);
    let mldsa44_allowed = mldsa44_height.is_some_and(|h| tip >= h.saturating_add(MARGIN));
    let mixed_allowed = matches!((tripwire_height, tripwire_tip), (Some(h3), Some(t)) if t >= h3.saturating_add(MARGIN));
    Ok(Chain {
        tip,
        tip_time: state.get("time").and_then(Value::as_u64),
        mldsa44_height,
        mldsa44_allowed,
        tripwire_height,
        tripwire_tip,
        ec_disabled: known.as_ref().map(|k| k.3),
        tripwires: known.map(|k| k.4).unwrap_or_default(),
        mixed_allowed,
    })
}

impl Chain {
    /// nLockTime of the wallet's transactions: M3's height while the mixed address may be handed out,
    /// else M1's while the ML-DSA-44 one may, else 0 (spendLockTime in chain.ts).
    pub fn lock_time(&self) -> u32 {
        if self.mixed_allowed {
            if let Some(h3) = self.tripwire_height {
                return h3;
            }
        }
        if self.mldsa44_allowed {
            return self.mldsa44_height.unwrap_or(0);
        }
        0
    }

    /// The leaf a spend from the mixed address takes: Schnorr while elliptic-curve checks are on, ML-DSA-44
    /// once they are off, none while that is unknown.
    pub fn mixed_path(&self) -> Option<Path> {
        self.ec_disabled.map(|off| if off { Path::Mldsa44 } else { Path::Schnorr })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn state(tip: u32, ec_disabled: bool) -> Value {
        json!({
            "chain": "signet",
            "signet_challenge": ARK0_CHALLENGE,
            "blocks": tip,
            "time": 1760000000u64,
            "deployments": {
                "p2mr": {"type": "buried", "active": true, "height": 1},
                "p2mr_mldsa44": {"type": "buried", "active": true, "height": 8600},
                "p2mr_tripwire": {"type": "buried", "active": true, "height": 30000}
            },
            "tripwire": {
                "tip_hash": "00".repeat(32), "tip_height": tip, "height": 30000, "leaf_version": "e0",
                "tripwires": [{"outpoint": format!("{}:0", "ab".repeat(32)), "state": if ec_disabled { "missing" } else { "unspent" }}],
                "ec_disabled_next_block": ec_disabled
            }
        })
    }

    #[test]
    fn gates_and_lock_time_follow_the_heights() {
        let c = check(&state(30005, false)).unwrap();
        assert!(c.mldsa44_allowed && !c.mixed_allowed);
        assert_eq!(c.lock_time(), 8600);
        let c = check(&state(30006, false)).unwrap();
        assert!(c.mixed_allowed);
        assert_eq!(c.lock_time(), 30000);
        assert_eq!(c.mixed_path(), Some(Path::Schnorr));
        let c = check(&state(40000, true)).unwrap();
        assert_eq!(c.mixed_path(), Some(Path::Mldsa44));
        assert!(!c.tripwires[0].unspent);
        let c = check(&state(8605, false)).unwrap();
        assert!(!c.mldsa44_allowed);
        assert_eq!(c.lock_time(), 0);
    }

    #[test]
    fn tripwire_lists_accept_the_real_size_and_the_limit_but_refuse_more() {
        for count in [2, MAX_TRIPWIRES, MAX_TRIPWIRES + 1] {
            let mut s = state(40000, false);
            s["tripwire"]["tripwires"] = json!((0..count).map(|i| json!({
                "outpoint": format!("{}:{i}", "ab".repeat(32)), "state": "unspent"
            })).collect::<Vec<_>>());
            let c = check(&s).unwrap();
            if count <= MAX_TRIPWIRES {
                assert_eq!(c.tripwires.len(), count);
                assert_eq!(c.ec_disabled, Some(false));
                assert!(c.mixed_allowed);
            } else {
                assert!(tripwire_state(&s["tripwire"]).is_none());
                assert!(c.tripwires.is_empty());
                assert_eq!((c.tripwire_tip, c.ec_disabled, c.mixed_path()), (None, None, None));
                assert!(!c.mixed_allowed);
            }
        }
    }

    #[test]
    fn duplicate_tripwire_outpoints_are_unknown_even_when_the_states_match() {
        for status in ["unspent", "missing"] {
            let mut s = state(40000, false);
            let mut duplicate = s["tripwire"]["tripwires"][0].clone();
            duplicate["state"] = json!(status);
            s["tripwire"]["tripwires"].as_array_mut().unwrap().push(duplicate);
            assert!(tripwire_state(&s["tripwire"]).is_none());
            let c = check(&s).unwrap();
            assert!(c.tripwires.is_empty());
            assert_eq!((c.tripwire_tip, c.ec_disabled, c.mixed_path()), (None, None, None));
            assert!(!c.mixed_allowed);
        }
    }

    #[test]
    fn another_chain_or_a_malformed_tripwire_is_not_trusted() {
        let mut s = state(40000, false);
        s["signet_challenge"] = json!("51");
        assert_eq!(check(&s), Err(ChainProblem::WrongChain));
        let mut s = state(40000, false);
        s["deployments"]["p2mr"]["active"] = json!(false);
        assert_eq!(check(&s), Err(ChainProblem::P2mrInactive));
        // An API that moves the network's deployments earlier is not describing Ark-0.
        for (name, height) in [("p2mr_mldsa44", 100), ("p2mr_tripwire", 1), ("p2mr", 0)] {
            let mut s = state(40000, false);
            s["deployments"][name]["height"] = json!(height);
            assert_eq!(check(&s), Err(ChainProblem::WrongChain), "{name}");
        }
        let mut s = state(40000, false);
        s["tripwire"]["leaf_version"] = json!("c0");
        let c = check(&s).unwrap();
        assert_eq!((c.ec_disabled, c.mixed_allowed), (None, false));
        let mut s = state(40000, false);
        s["tripwire"]["tripwires"][0]["outpoint"] = json!("xyz:0");
        assert_eq!(check(&s).unwrap().ec_disabled, None);
        // Read at a tip past the node's own: it would open the mixed address early.
        let mut s = state(30001, false);
        s["tripwire"]["tip_height"] = json!(30006);
        let c = check(&s).unwrap();
        assert_eq!((c.tripwire_tip, c.mixed_allowed), (None, false));
    }
}
