//! The network the wallet is built for. A release build has Ark-0's parameters, fixed in the code
//! (`RELEASE`). A build with the `privnet` feature, for tests on a private network only, reads them once
//! at startup from the JSON file that `ARK0_PRIVNET_CONFIG` names, and keeps its files under an app
//! identifier of its own: it never opens or writes a release wallet's files.
use crate::chain::{H4T, MLDSA44_HEIGHT, P2MR_HEIGHT, PQBLOCK_HEIGHT, PQBLOCK_KEY, SLHDSA128S_HEIGHT, TRIPWIRE_HEIGHT};
use crate::keys::ARK0_CHALLENGE;

/// The parameters of a network: its signet challenge, the two API bases, the buried heights, the lattice
/// tripwire outputs and the ML-DSA-44 block signature.
#[derive(Debug, PartialEq, Eq)]
pub struct Network {
    pub challenge: &'static str,
    pub api_bases: [&'static str; 2],
    pub p2mr_height: u32,
    pub mldsa44_height: u32,
    pub tripwire_height: u32,
    pub slhdsa128s_height: u32,
    /// H4T, the height of `p2mr_lattice_tripwire`.
    pub h4t: u32,
    pub lattice_tripwires: &'static [&'static str],
    pub pqblock_height: u32,
    pub pqblock_key: &'static str,
}

/// Ark-0's three lattice tripwires, outputs 0, 1 and 2 of `LATTICE_TRIPWIRE_TXID` (a test checks it).
const ARK0_LATTICE: [&str; 3] = [
    "aac5a1fef01545c338de92bceda520684a49682f2ec546900a4dbe99eba8827c:0",
    "aac5a1fef01545c338de92bceda520684a49682f2ec546900a4dbe99eba8827c:1",
    "aac5a1fef01545c338de92bceda520684a49682f2ec546900a4dbe99eba8827c:2",
];

/// Ark-0.
pub const RELEASE: Network = Network {
    challenge: ARK0_CHALLENGE,
    api_bases: [crate::api::DEFAULT_BASE, crate::sources::SECOND_BASE],
    p2mr_height: P2MR_HEIGHT,
    mldsa44_height: MLDSA44_HEIGHT,
    tripwire_height: TRIPWIRE_HEIGHT,
    slhdsa128s_height: SLHDSA128S_HEIGHT,
    h4t: H4T,
    lattice_tripwires: &ARK0_LATTICE,
    pqblock_height: PQBLOCK_HEIGHT,
    pqblock_key: PQBLOCK_KEY,
};

/// The network of this build: Ark-0 unless the `privnet` feature is on.
#[cfg(not(feature = "privnet"))]
pub fn network() -> &'static Network {
    &RELEASE
}

#[cfg(feature = "privnet")]
pub use privnet::{load, network, APP_IDENTIFIER};

#[cfg(feature = "privnet")]
pub mod privnet {
    use super::Network;
    use serde_json::Value;
    use std::sync::OnceLock;

    /// The environment variable that names the network's JSON file.
    pub const CONFIG_ENV: &str = "ARK0_PRIVNET_CONFIG";
    /// The app identifier of this build, and so its data directory: never the release's.
    pub const APP_IDENTIFIER: &str = "si.ark0.wallet.privnet";

    static LOADED: OnceLock<Network> = OnceLock::new();

    /// The private network read by `load`. Before that, a unit test gets Ark-0's parameters (so that the
    /// suite runs unchanged with the feature on); anything else stops.
    pub fn network() -> &'static Network {
        match LOADED.get() {
            Some(n) => n,
            #[cfg(test)]
            None => &super::RELEASE,
            #[cfg(not(test))]
            None => panic!("the private network is read at startup ({CONFIG_ENV})"),
        }
    }

    /// Reads the file `ARK0_PRIVNET_CONFIG` names, once. The file:
    /// {"api_bases": [a, b], "signet_challenge": hex, "heights": {"p2mr", "mldsa44", "tripwire",
    /// "slhdsa128s", "p2mr_lattice_tripwire"}, "lattice_tripwires": ["txid:vout", ...],
    /// "pqblock": {"height", "key": hex or null}}. A base is https://, or http:// to 127.0.0.1.
    pub fn load() -> Result<&'static Network, String> {
        if let Some(n) = LOADED.get() {
            return Ok(n);
        }
        let path = std::env::var(CONFIG_ENV).map_err(|_| format!("{CONFIG_ENV} names no file"))?;
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
        let network = parse(&serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?)?;
        Ok(LOADED.get_or_init(|| network))
    }

    fn leak(s: &str) -> &'static str {
        Box::leak(s.to_string().into_boxed_str())
    }

    fn hex_of(v: Option<&Value>, what: &str, len: Option<usize>) -> Result<&'static str, String> {
        let s = v.and_then(Value::as_str).ok_or(format!("{what}: a hex string"))?;
        let bytes = hex::decode(s).map_err(|_| format!("{what}: not hex"))?;
        if s.is_empty() || len.is_some_and(|n| bytes.len() != n) || s != hex::encode(&bytes) {
            return Err(format!("{what}: lower-case hex{}", len.map(|n| format!(" of {n} bytes")).unwrap_or_default()));
        }
        Ok(leak(s))
    }

    fn base(v: &Value) -> Result<&'static str, String> {
        let s = v.as_str().ok_or("api_bases: strings")?.trim_end_matches('/');
        let local = s.strip_prefix("http://127.0.0.1:").is_some_and(|port| port.parse::<u16>().is_ok_and(|p| p > 0));
        if !(local || (s.starts_with("https://") && s.len() > "https://".len())) {
            return Err(format!("api_bases: {s} is neither https:// nor http://127.0.0.1:<port>"));
        }
        Ok(leak(s))
    }

    pub(super) fn parse(v: &Value) -> Result<Network, String> {
        let bases = v.get("api_bases").and_then(Value::as_array).filter(|b| b.len() == 2).ok_or("api_bases: two bases")?;
        let heights = v.get("heights").ok_or("heights")?;
        let h = |name: &str| -> Result<u32, String> {
            heights.get(name).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).filter(|n| *n >= 1).ok_or(format!("heights.{name}: a height of at least 1"))
        };
        let lattice: Vec<&'static str> = v
            .get("lattice_tripwires")
            .and_then(Value::as_array)
            .filter(|l| !l.is_empty() && l.len() <= 16)
            .ok_or("lattice_tripwires: 1 to 16 outpoints")?
            .iter()
            .map(|o| {
                let s = o.as_str().ok_or("lattice_tripwires: strings")?;
                let (txid, vout) = s.split_once(':').ok_or(format!("{s}: txid:vout"))?;
                hex_of(Some(&Value::from(txid)), "lattice tripwire txid", Some(32))?;
                vout.parse::<u32>().ok().filter(|n| n.to_string() == vout).ok_or(format!("{s}: txid:vout"))?;
                Ok(leak(s))
            })
            .collect::<Result<_, String>>()?;
        let pqblock = v.get("pqblock").ok_or("pqblock")?;
        let pqblock_height = pqblock.get("height").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or("pqblock.height")?;
        let pqblock_key = match pqblock.get("key") {
            None | Some(Value::Null) => super::RELEASE.pqblock_key,
            key => hex_of(key, "pqblock.key", Some(crate::mldsa::PUBLIC_KEY_LEN))?,
        };
        let network = Network {
            challenge: hex_of(v.get("signet_challenge"), "signet_challenge", None)?,
            api_bases: [base(&bases[0])?, base(&bases[1])?],
            p2mr_height: h("p2mr")?,
            mldsa44_height: h("mldsa44")?,
            tripwire_height: h("tripwire")?,
            slhdsa128s_height: h("slhdsa128s")?,
            h4t: h("p2mr_lattice_tripwire")?,
            lattice_tripwires: Box::leak(lattice.into_boxed_slice()),
            pqblock_height,
            pqblock_key,
        };
        if network.challenge == super::RELEASE.challenge {
            return Err("signet_challenge: Ark-0's; this build is for a private network".into());
        }
        Ok(network)
    }

    #[cfg(test)]
    mod tests {
        use serde_json::json;

        #[test]
        fn before_a_file_is_read_a_unit_test_sees_ark0() {
            let n = super::network();
            assert_eq!(n, &crate::net::RELEASE);
            assert_eq!(n.lattice_tripwires, (0..3).map(|v| format!("{}:{v}", crate::chain::LATTICE_TRIPWIRE_TXID)).collect::<Vec<_>>());
            assert_eq!(n.api_bases, ["https://wallet.ark0.si", "https://wallet2.ark0.si"]);
        }

        #[test]
        fn a_private_network_file_is_read_and_checked() {
            let good = json!({
                "api_bases": ["http://127.0.0.1:18501/", "http://127.0.0.1:18502"],
                "signet_challenge": "51",
                "heights": {"p2mr": 1, "mldsa44": 2, "tripwire": 3, "slhdsa128s": 4, "p2mr_lattice_tripwire": 120},
                "lattice_tripwires": [format!("{}:0", "ab".repeat(32))],
                "pqblock": {"height": 1_000_000, "key": null}
            });
            let n = super::parse(&good).unwrap();
            assert_eq!((n.api_bases, n.h4t, n.challenge), (["http://127.0.0.1:18501", "http://127.0.0.1:18502"], 120, "51"));
            for (field, bad) in [
                ("api_bases", json!(["http://example.com", "http://127.0.0.1:1"])),
                ("api_bases", json!(["http://127.0.0.1:1"])),
                ("signet_challenge", json!(crate::keys::ARK0_CHALLENGE)),
                ("signet_challenge", json!("5G")),
                ("lattice_tripwires", json!([])),
                ("lattice_tripwires", json!(["ab:0"])),
            ] {
                let mut v = good.clone();
                v[field] = bad;
                assert!(super::parse(&v).is_err(), "{field}");
            }
            let mut v = good.clone();
            v["heights"]["p2mr_lattice_tripwire"] = json!(0);
            assert!(super::parse(&v).is_err());
        }
    }
}

