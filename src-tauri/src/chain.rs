//! What the node behind the API says about the chain, and what the wallet may do on it.
//!
//! No address is handed out until the node is on Ark-0 (its signet challenge) with P2MR active: a `tb1z`
//! prefix alone says nothing about the rules the node enforces, and where they are not enforced a witness
//! version 2 output is anyone's. The ML-DSA-44 address waits six blocks past M1's height, the mixed one six
//! past M3's, and the mixed one also waits until the drill tripwire's state is known: it decides which of
//! the two leaves a spend can use. These are the web wallet's rules (chain.ts, p2mr-ts).
//!
//! pq2 (M4) waits six blocks past H4T, the height of the lattice tripwire rules (leaf version 0xe2), and
//! until the lattice tripwire state is known: read at the current tip, about Ark-0's three tripwires, with a
//! flag that agrees with them; a node that does not report those rules at all is on Ark-0
//! still, it just offers no pq2. Unknown state never opens anything: no pq2 address, no ML-DSA-44 leaf.
use crate::keys::ARK0_CHALLENGE;
use crate::p2mr::{Path, LATTICE_TRIPWIRED_LEAF_VERSION, TRIPWIRED_LEAF_VERSION};
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
/// OP_CHECKSLHDSA128S (M4-S) from 32,000, and H4T: leaves of version 0xe2 and the lattice tripwires
/// (`p2mr_lattice_tripwire`, M4-T) from 55,000. A node that does not report them gives no pq2; one that
/// reports other heights is not describing Ark-0.
pub const SLHDSA128S_HEIGHT: u32 = 32_000;
pub const H4T: u32 = 55_000;
/// The transaction that made Ark-0's three lattice tripwires (outputs 0, 1 and 2).
pub const LATTICE_TRIPWIRE_TXID: &str = "aac5a1fef01545c338de92bceda520684a49682f2ec546900a4dbe99eba8827c";

/// M2: from this height every block carries an ML-DSA-44 signature by this key.
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
    /// H4T when the node reports both M4 deployments at Ark-0's heights; None when it reports neither or
    /// not both (then there is no pq2).
    pub lattice_height: Option<u32>,
    /// The tip the lattice tripwire state was read at; None when the state is unknown.
    pub lattice_tip: Option<u32>,
    /// Whether ML-DSA-44 checks in 0xe2 leaves fail from the next block on; None when unknown.
    pub mldsa_disabled: Option<bool>,
    /// The lattice tripwires as the node reports them.
    pub lattice_tripwires: Vec<LatticeTripwire>,
    /// pq2 addresses and outputs may be made: the tip is at least H4T + 6 and the state is known.
    pub pq2_allowed: bool,
    /// pq2 coins may be spent (through the SLH-DSA leaf when the state is unknown): the tip is at least
    /// H4T + 6.
    pub pq2_spendable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LatticeTripwire {
    pub outpoint: String,
    pub unspent: bool,
    /// SHA-256 of the output's ML-DSA-44 key, when the node gives it.
    pub key_sha256: Option<String>,
    /// The node's name for it ("NUMS ML-DSA-44", "destroyed key", "drill"), when it gives one.
    pub label: Option<String>,
}

/// The status of a verified pq2 output (design section 8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Pq2Status {
    /// Confirmed at or above H4T: every spend of it comes when both of its leaves are executed.
    Protected,
    /// Not yet confirmed.
    Pending,
    /// Confirmed below H4T (a payment made before activation, or a deep reorganization): a spend could come
    /// while 0xe2 leaves are not executed.
    Unprotected,
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

/// A label as a node writes it: short printable ASCII.
fn is_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// What `deployments` says of a deployment Ark-0 may not have yet: Ok(None) when it is not listed or is
/// listed in a form the wallet does not read (unknown: no pq2), Ok(Some) at Ark-0's height, and the wrong
/// chain when it is a buried deployment at any other height.
fn optional_buried(deployments: &Value, name: &str, pinned: u32) -> Result<Option<u32>, ChainProblem> {
    match deployments.get(name).map(|_| buried(deployments, name)) {
        None | Some(None) => Ok(None),
        Some(Some(h)) if h == pinned => Ok(Some(h)),
        Some(Some(_)) => Err(ChainProblem::WrongChain),
    }
}

/// The lattice tripwire state, gettripwireinfo's `lattice` object read at `read_at`, when every field
/// is of its type, the tripwires are exactly Ark-0's three, and the flag is what the node computes from
/// them: false while the rules are not active in the next block (read_at + 1 < height), else true exactly
/// when any tripwire is missing. (height, ML-DSA-44 disabled from the next block, the tripwires); None
/// otherwise: it is then unknown.
fn lattice_state(v: &Value, read_at: u32) -> Option<(u32, bool, Vec<LatticeTripwire>)> {
    if v.get("leaf_version")?.as_str()? != format!("{LATTICE_TRIPWIRED_LEAF_VERSION:x}") {
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
        // Optional, but a field that is there must be of its type.
        let key_sha256 = match t.get("key_sha256") {
            None => None,
            Some(k) => Some(k.as_str().filter(|k| is_hex64(k))?.to_string()),
        };
        let label = match t.get("label") {
            None => None,
            Some(l) => Some(l.as_str().filter(|l| is_label(l))?.to_string()),
        };
        tripwires.push(LatticeTripwire { outpoint: outpoint.to_string(), unspent, key_sha256, label });
    }
    let ark0: HashSet<String> = (0..3).map(|vout| format!("{LATTICE_TRIPWIRE_TXID}:{vout}")).collect();
    if seen.len() != ark0.len() || !seen.iter().all(|o| ark0.contains(*o)) {
        return None;
    }
    let height = height(v.get("height")?)?;
    let disabled = v.get("mldsa_disabled_next_block")?.as_bool()?;
    let expected = read_at.saturating_add(1) >= height && tripwires.iter().any(|t| !t.unspent);
    if disabled != expected {
        return None;
    }
    Some((height, disabled, tripwires))
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
    // Both M4 deployments, or no pq2: leaf B needs OP_CHECKSLHDSA128S, the 0xe2 leaves need H4T.
    let slhdsa128s = optional_buried(deployments, "p2mr_slhdsa128s", SLHDSA128S_HEIGHT)?;
    let lattice_height = optional_buried(deployments, "p2mr_lattice_tripwire", H4T)?.filter(|_| slhdsa128s.is_some());
    // The state counts only for the height and leaf version the mixed address is built for, read at a
    // tip the node has reached.
    let known = state.get("tripwire").and_then(tripwire_state).filter(|(at, h3, leaf, _, _)| {
        *at <= tip && Some(*h3) == tripwire_height && *leaf == format!("{TRIPWIRED_LEAF_VERSION:x}")
    });
    let tripwire_tip = known.as_ref().map(|k| k.0);
    // The lattice state is read in the same snapshot as the M3 state (gettripwireinfo): it counts only at a
    // tip the node has reached, for H4T and leaf version 0xe2, and only when the node runs those rules.
    let tripwire = state.get("tripwire");
    // Only a snapshot of the current tip counts: an older one may predate a spent tripwire.
    let read_at = tripwire
        .filter(|t| t.get("tip_hash").and_then(Value::as_str).is_some_and(is_hex64))
        .and_then(|t| t.get("tip_height"))
        .and_then(height)
        .filter(|at| *at == tip);
    let lattice = match (lattice_height, read_at) {
        (Some(h4t), Some(at)) => tripwire.and_then(|t| t.get("lattice")).and_then(|l| lattice_state(l, at)).filter(|(h, _, _)| *h == h4t).map(|l| (at, l)),
        _ => None,
    };
    let lattice_tip = lattice.as_ref().map(|(at, _)| *at);
    let pq2_allowed = matches!((lattice_height, lattice_tip), (Some(h), Some(t)) if t >= h.saturating_add(MARGIN) && tip >= h.saturating_add(MARGIN));
    let pq2_spendable = lattice_height.is_some_and(|h| tip >= h.saturating_add(MARGIN));
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
        lattice_height,
        lattice_tip,
        mldsa_disabled: lattice.as_ref().map(|(_, l)| l.1),
        lattice_tripwires: lattice.map(|(_, l)| l.2).unwrap_or_default(),
        pq2_allowed,
        pq2_spendable,
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

    /// nLockTime of a transaction the wallet builds: H4T when it creates a pq2 output (change included),
    /// which it does only while pq2 is open; otherwise as `lock_time`.
    pub fn lock_time_for(&self, creates_pq2: bool) -> u32 {
        match self.lattice_height {
            Some(h4t) if creates_pq2 && self.pq2_allowed => h4t,
            _ => self.lock_time(),
        }
    }

    /// The leaf a spend from the mixed address takes: Schnorr while elliptic-curve checks are on, ML-DSA-44
    /// once they are off, none while that is unknown.
    pub fn mixed_path(&self) -> Option<Path> {
        self.ec_disabled.map(|off| if off { Path::Mldsa44 } else { Path::Schnorr })
    }

    /// Whether a pq2 spend may go through the ML-DSA-44 leaf, when the user asks for it: only while the node
    /// reports that ML-DSA-44 checks in 0xe2 leaves still work in the next block. Unknown means no.
    pub fn pq2_mldsa44_allowed(&self) -> bool {
        self.mldsa_disabled == Some(false)
    }

    /// The leaf a pq2 spend takes: SLH-DSA unless the user asks for ML-DSA-44 and that is allowed.
    pub fn pq2_path(&self, wanted: Option<Path>) -> Path {
        if wanted == Some(Path::Mldsa44) && self.pq2_mldsa44_allowed() {
            Path::Mldsa44
        } else {
            Path::Slhdsa128s
        }
    }

    /// The status of a verified pq2 output (one whose tree the wallet has checked is exactly its own S1 and
    /// SLH1 at 0xe2) confirmed at `height`, or unconfirmed (None); None when H4T is unknown.
    pub fn pq2_status(&self, height: Option<u32>) -> Option<Pq2Status> {
        let h4t = self.lattice_height?;
        Some(match height {
            None => Pq2Status::Pending,
            Some(h) if h >= h4t => Pq2Status::Protected,
            Some(_) => Pq2Status::Unprotected,
        })
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

    /// A state from a node that runs the M4 rules: both deployments, and the lattice tripwire state in
    /// gettripwireinfo's `lattice` object.
    pub(crate) fn m4_state(tip: u32, mldsa_disabled: bool) -> Value {
        let mut s = state(tip, false);
        s["deployments"]["p2mr_slhdsa128s"] = json!({"type": "buried", "active": tip >= 32000, "height": 32000});
        s["deployments"]["p2mr_lattice_tripwire"] = json!({"type": "buried", "active": tip >= H4T, "height": H4T});
        s["tripwire"]["lattice"] = json!({
            "height": H4T, "leaf_version": "e2",
            "tripwires": [
                {"outpoint": format!("{LATTICE_TRIPWIRE_TXID}:0"), "state": "unspent", "key_sha256": "591dae318a0fdde81a590eab8c8581e07657d2c30b97cf31d87bafe636c92805", "label": "NUMS ML-DSA-44"},
                {"outpoint": format!("{LATTICE_TRIPWIRE_TXID}:1"), "state": if mldsa_disabled { "missing" } else { "unspent" }, "label": "destroyed key"},
                {"outpoint": format!("{LATTICE_TRIPWIRE_TXID}:2"), "state": "unspent"}
            ],
            "mldsa_disabled_next_block": mldsa_disabled
        });
        s
    }

    #[test]
    fn a_lattice_state_that_contradicts_itself_or_names_other_tripwires_is_unknown() {
        // A missing tripwire beside "not disabled", and the reverse.
        let mut s = m4_state(H4T + 100, false);
        s["tripwire"]["lattice"]["tripwires"][0]["state"] = json!("missing");
        assert_eq!(check(&s).unwrap().mldsa_disabled, None);
        let mut s = m4_state(H4T + 100, false);
        s["tripwire"]["lattice"]["mldsa_disabled_next_block"] = json!(true);
        assert_eq!(check(&s).unwrap().mldsa_disabled, None);
        // Any outpoints other than Ark-0's three: one too few, one too many, one changed, one twice.
        let wire = |o: String| json!({"outpoint": o, "state": "unspent"});
        for list in [
            json!([wire(format!("{LATTICE_TRIPWIRE_TXID}:0")), wire(format!("{LATTICE_TRIPWIRE_TXID}:1"))]),
            json!([wire(format!("{LATTICE_TRIPWIRE_TXID}:0")), wire(format!("{LATTICE_TRIPWIRE_TXID}:1")), wire(format!("{LATTICE_TRIPWIRE_TXID}:2")), wire(format!("{LATTICE_TRIPWIRE_TXID}:3"))]),
            json!([wire(format!("{LATTICE_TRIPWIRE_TXID}:0")), wire(format!("{LATTICE_TRIPWIRE_TXID}:1")), wire(format!("{}:2", "ab".repeat(32)))]),
            json!([wire(format!("{LATTICE_TRIPWIRE_TXID}:0")), wire(format!("{LATTICE_TRIPWIRE_TXID}:1")), wire(format!("{LATTICE_TRIPWIRE_TXID}:1"))]),
        ] {
            let mut s = m4_state(H4T + 100, false);
            s["tripwire"]["lattice"]["tripwires"] = list.clone();
            let c = check(&s).unwrap();
            assert_eq!((c.mldsa_disabled, c.pq2_allowed), (None, false), "{list}");
            assert!(!c.pq2_mldsa44_allowed());
        }
        // Before the rules are active in the next block, the node says "not disabled" whatever the outputs.
        let mut s = m4_state(H4T - 2, false);
        s["tripwire"]["lattice"]["tripwires"][1]["state"] = json!("missing");
        assert_eq!(check(&s).unwrap().mldsa_disabled, Some(false));
        let mut s = m4_state(H4T - 2, false);
        s["tripwire"]["lattice"]["mldsa_disabled_next_block"] = json!(true);
        assert_eq!(check(&s).unwrap().mldsa_disabled, None);
        // From the block before H4T on, the flag must follow the outputs.
        let mut s = m4_state(H4T - 1, false);
        s["tripwire"]["lattice"]["tripwires"][1]["state"] = json!("missing");
        assert_eq!(check(&s).unwrap().mldsa_disabled, None);
        assert_eq!(check(&m4_state(H4T - 1, true)).unwrap().mldsa_disabled, Some(true));
    }

    #[test]
    fn a_lattice_state_read_below_the_tip_is_unknown() {
        // Read at 55,006 while the node is at 60,000: an old "not disabled" says nothing about now.
        let mut s = m4_state(60_000, false);
        s["tripwire"]["tip_height"] = json!(H4T + 6);
        let c = check(&s).unwrap();
        assert_eq!((c.lattice_tip, c.mldsa_disabled, c.pq2_allowed), (None, None, false));
        assert!(!c.pq2_mldsa44_allowed());
        assert_eq!(c.pq2_path(Some(Path::Mldsa44)), Path::Slhdsa128s);
        // One block behind is behind too.
        let mut s = m4_state(60_000, false);
        s["tripwire"]["tip_height"] = json!(59_999);
        assert_eq!(check(&s).unwrap().mldsa_disabled, None);
        assert_eq!(check(&m4_state(60_000, false)).unwrap().mldsa_disabled, Some(false));
    }

    #[test]
    fn pq2_opens_at_h4t_plus_six_and_not_at_h4t_plus_five() {
        let c = check(&m4_state(H4T + 5, false)).unwrap();
        assert_eq!((c.lattice_height, c.lattice_tip, c.mldsa_disabled), (Some(H4T), Some(H4T + 5), Some(false)));
        assert!(!c.pq2_allowed);
        // Without pq2 open, a transaction keeps the lock time of the rules before it.
        assert_eq!((c.lock_time_for(true), c.lock_time_for(false)), (TRIPWIRE_HEIGHT, TRIPWIRE_HEIGHT));
        let c = check(&m4_state(H4T + 6, false)).unwrap();
        assert!(c.pq2_allowed);
        assert_eq!((c.lock_time_for(true), c.lock_time_for(false)), (H4T, TRIPWIRE_HEIGHT));
        assert_eq!(c.lattice_tripwires.len(), 3);
        assert_eq!(c.lattice_tripwires[0].label.as_deref(), Some("NUMS ML-DSA-44"));
        assert_eq!(c.lattice_tripwires[2].key_sha256, None);
        // The SLH-DSA leaf by default; the ML-DSA-44 leaf only when asked and allowed.
        assert_eq!((c.pq2_path(None), c.pq2_path(Some(Path::Mldsa44))), (Path::Slhdsa128s, Path::Mldsa44));
        let c = check(&m4_state(H4T + 100, true)).unwrap();
        assert!(c.pq2_allowed && !c.pq2_mldsa44_allowed());
        assert_eq!(c.pq2_path(Some(Path::Mldsa44)), Path::Slhdsa128s);
        assert!(!c.lattice_tripwires[1].unspent);
        // A reorganization back below H4T + 6 closes it again; the state read at a tip the node has not
        // reached does not count.
        assert!(!check(&m4_state(H4T + 2, false)).unwrap().pq2_allowed);
        let mut s = m4_state(H4T + 5, false);
        s["tripwire"]["tip_height"] = json!(H4T + 6);
        let c = check(&s).unwrap();
        assert_eq!((c.lattice_tip, c.mldsa_disabled, c.pq2_allowed), (None, None, false));
        // Spending waits for H4T + 6 as well, but not for the state: unknown means the SLH-DSA leaf.
        assert!(!check(&m4_state(H4T + 5, false)).unwrap().pq2_spendable);
        assert!(check(&m4_state(H4T + 6, false)).unwrap().pq2_spendable);
        let mut s = m4_state(H4T + 6, false);
        s["tripwire"].as_object_mut().unwrap().remove("lattice");
        let c = check(&s).unwrap();
        assert!(c.pq2_spendable && !c.pq2_allowed);
        assert_eq!(c.pq2_path(Some(Path::Mldsa44)), Path::Slhdsa128s);
    }

    #[test]
    fn pq2_status_follows_the_confirmation_height() {
        let c = check(&m4_state(H4T + 10, false)).unwrap();
        assert_eq!(c.pq2_status(None), Some(Pq2Status::Pending));
        assert_eq!(c.pq2_status(Some(H4T)), Some(Pq2Status::Protected));
        assert_eq!(c.pq2_status(Some(H4T + 9)), Some(Pq2Status::Protected));
        assert_eq!(c.pq2_status(Some(H4T - 1)), Some(Pq2Status::Unprotected));
        // Recomputed from what the chain says now: after a reorganization the same output may be pending
        // again or confirmed at another height.
        assert_eq!(check(&state(40_000, false)).unwrap().pq2_status(Some(H4T)), None);
    }

    #[test]
    fn todays_nodes_are_ark0_without_pq2_and_other_heights_are_another_chain() {
        // No M4 deployment at all, as today: not the wrong chain, simply no pq2.
        let c = check(&state(60_000, false)).unwrap();
        assert_eq!((c.lattice_height, c.lattice_tip, c.mldsa_disabled, c.pq2_allowed), (None, None, None, false));
        assert!(c.lattice_tripwires.is_empty());
        // Only one of the two: no pq2 either (leaf B needs OP_CHECKSLHDSA128S, the leaves need H4T).
        for name in ["p2mr_slhdsa128s", "p2mr_lattice_tripwire"] {
            let mut s = m4_state(H4T + 10, false);
            s["deployments"].as_object_mut().unwrap().remove(name);
            let c = check(&s).unwrap();
            assert_eq!((c.lattice_height, c.pq2_allowed, c.mldsa_disabled), (None, false, None), "{name}");
        }
        // Either reported at another height: another chain, whatever else the answer says.
        for (name, height) in [("p2mr_slhdsa128s", 31_999), ("p2mr_slhdsa128s", 55_000), ("p2mr_lattice_tripwire", 54_000), ("p2mr_lattice_tripwire", 1)] {
            let mut s = m4_state(H4T + 10, false);
            s["deployments"][name]["height"] = json!(height);
            assert_eq!(check(&s), Err(ChainProblem::WrongChain), "{name} at {height}");
            let mut s = state(40_000, false);
            s["deployments"][name] = json!({"type": "buried", "active": true, "height": height});
            assert_eq!(check(&s), Err(ChainProblem::WrongChain), "{name} at {height} alone");
        }
        // Listed in a form the wallet does not read: unknown, no pq2, not a reason to distrust the rest.
        for broken in [json!({"type": "bip9", "height": H4T}), json!({"type": "buried"}), json!({"type": "buried", "height": "55000"}), json!(null), json!([])] {
            let mut s = m4_state(H4T + 10, false);
            s["deployments"]["p2mr_lattice_tripwire"] = broken.clone();
            let c = check(&s).unwrap();
            assert_eq!((c.lattice_height, c.pq2_allowed), (None, false), "{broken}");
        }
    }

    #[test]
    fn the_lattice_state_is_parsed_strictly_and_unknown_is_never_a_default() {
        let unknown = |s: &Value, what: &str| {
            let c = check(s).unwrap();
            assert_eq!(c.lattice_height, Some(H4T), "{what}");
            assert_eq!((c.lattice_tip, c.mldsa_disabled, c.pq2_allowed), (None, None, false), "{what}");
            assert!(c.lattice_tripwires.is_empty(), "{what}");
            // Unknown: no ML-DSA-44 leaf, and a spend goes through the SLH-DSA leaf.
            assert!(!c.pq2_mldsa44_allowed(), "{what}");
            assert_eq!(c.pq2_path(Some(Path::Mldsa44)), Path::Slhdsa128s, "{what}");
        };
        let edits: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
            ("no lattice object", Box::new(|s| { s["tripwire"].as_object_mut().unwrap().remove("lattice"); })),
            ("lattice not an object", Box::new(|s| s["tripwire"]["lattice"] = json!("e2"))),
            ("no flag", Box::new(|s| { s["tripwire"]["lattice"].as_object_mut().unwrap().remove("mldsa_disabled_next_block"); })),
            ("flag not a boolean", Box::new(|s| s["tripwire"]["lattice"]["mldsa_disabled_next_block"] = json!("false"))),
            ("flag null", Box::new(|s| s["tripwire"]["lattice"]["mldsa_disabled_next_block"] = json!(null))),
            ("flag a number", Box::new(|s| s["tripwire"]["lattice"]["mldsa_disabled_next_block"] = json!(0))),
            ("other height", Box::new(|s| s["tripwire"]["lattice"]["height"] = json!(H4T + 1))),
            ("height a string", Box::new(|s| s["tripwire"]["lattice"]["height"] = json!("55000"))),
            ("no height", Box::new(|s| { s["tripwire"]["lattice"].as_object_mut().unwrap().remove("height"); })),
            ("leaf version e0", Box::new(|s| s["tripwire"]["lattice"]["leaf_version"] = json!("e0"))),
            ("leaf version upper case", Box::new(|s| s["tripwire"]["lattice"]["leaf_version"] = json!("E2"))),
            ("leaf version a number", Box::new(|s| s["tripwire"]["lattice"]["leaf_version"] = json!(226))),
            ("no tripwires", Box::new(|s| { s["tripwire"]["lattice"].as_object_mut().unwrap().remove("tripwires"); })),
            ("empty tripwires", Box::new(|s| s["tripwire"]["lattice"]["tripwires"] = json!([]))),
            ("too many tripwires", Box::new(|s| s["tripwire"]["lattice"]["tripwires"] = json!((0..=MAX_TRIPWIRES).map(|i| json!({"outpoint": format!("{}:{i}", "cd".repeat(32)), "state": "unspent"})).collect::<Vec<_>>()))),
            ("a tripwire's state unknown", Box::new(|s| s["tripwire"]["lattice"]["tripwires"][0]["state"] = json!("spent"))),
            ("a tripwire without state", Box::new(|s| { s["tripwire"]["lattice"]["tripwires"][0].as_object_mut().unwrap().remove("state"); })),
            ("a malformed outpoint", Box::new(|s| s["tripwire"]["lattice"]["tripwires"][0]["outpoint"] = json!("c1:0"))),
            ("an outpoint twice", Box::new(|s| s["tripwire"]["lattice"]["tripwires"][1]["outpoint"] = s["tripwire"]["lattice"]["tripwires"][0]["outpoint"].clone())),
            ("a key hash that is not one", Box::new(|s| s["tripwire"]["lattice"]["tripwires"][0]["key_sha256"] = json!("abc"))),
            ("a key hash in upper case", Box::new(|s| s["tripwire"]["lattice"]["tripwires"][0]["key_sha256"] = json!("AB".repeat(32)))),
            ("a key hash null", Box::new(|s| s["tripwire"]["lattice"]["tripwires"][0]["key_sha256"] = json!(null))),
            ("a label not a string", Box::new(|s| s["tripwire"]["lattice"]["tripwires"][0]["label"] = json!(7))),
            ("a label with a line break", Box::new(|s| s["tripwire"]["lattice"]["tripwires"][0]["label"] = json!("a\nb"))),
            ("a label far too long", Box::new(|s| s["tripwire"]["lattice"]["tripwires"][0]["label"] = json!("x".repeat(65)))),
            ("no tip hash", Box::new(|s| { s["tripwire"].as_object_mut().unwrap().remove("tip_hash"); })),
            ("no tip height", Box::new(|s| { s["tripwire"].as_object_mut().unwrap().remove("tip_height"); })),
        ];
        for (what, edit) in edits {
            let mut s = m4_state(H4T + 100, false);
            edit(&mut s);
            unknown(&s, what);
        }
        // Optional fields may be left out.
        let mut s = m4_state(H4T + 100, false);
        for t in s["tripwire"]["lattice"]["tripwires"].as_array_mut().unwrap() {
            t.as_object_mut().unwrap().retain(|k, _| k == "outpoint" || k == "state");
        }
        let c = check(&s).unwrap();
        assert!(c.pq2_allowed && c.lattice_tripwires.iter().all(|t| t.key_sha256.is_none() && t.label.is_none()));
        // The M3 state and the lattice state are independent: one unknown leaves the other as it is.
        let mut s = m4_state(H4T + 100, true);
        s["tripwire"]["leaf_version"] = json!("c0");
        let c = check(&s).unwrap();
        assert_eq!((c.ec_disabled, c.mldsa_disabled, c.pq2_allowed), (None, Some(true), true));
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
