//! The pq2 addresses of a 24-word wallet: which indices it has handed out, which it has seen paid, and how
//! far a recovery scan has looked. Kept in `pq2.json` beside the vault; it holds no secret, only indices
//! and the addresses they give.
//!
//! Every pq2 output has keys of its own, at a fresh index on the receiving chain (0) or the change chain
//! (1). The rules:
//! - An index is issued once: a receiving address is never handed out again, and no index below the
//!   highest issued one is handed out later.
//! - Gap limit 20 per chain: while 20 addresses this device handed out on a chain have no output seen
//!   paid to them, it hands out no new one on that chain. On the change chain that means no payment with
//!   change until one of them is seen (the wallet offers to send without change, or to wait).
//! - "Used": an address is used when the site reports history for it (an output paid to it in a block),
//!   or it holds coins now (confirmed or on their way), or the book already says so; the book keeps that
//!   for good.
//! - Recovery: each chain is scanned until 20 addresses in a row are not used; every index up to the
//!   highest used one plus 20 is then recorded as issued (reserved), so that no address another copy of
//!   the wallet may have handed out is handed out here again. Reserved addresses do not count towards the
//!   gap limit: this device never handed them out. Each refresh asks the site whether any of them received
//!   something in the blocks since its last check. Coins beyond the scanned range need a wider scan, which
//!   looks at the scanned range again too.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const GAP_LIMIT: u32 = 20;
/// How many more indices a wider scan looks at on each chain, at least.
pub const WIDER_SCAN: u32 = 100;
/// 2: addresses of reserved indices and how far each one's history has been checked (`checked`). Books of
/// version 1 are migrated when the wallet is opened (`migrate_from_1`). A book of version 2 written with a
/// single watermark for all reserved addresses is read without it: each address is checked from block 0
/// once.
const FILE_VERSION: u32 = 2;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainBook {
    /// Every index below this is issued: handed out here, or reserved by a recovery scan.
    pub issued: u32,
    /// Indices this device handed out (receiving addresses shown, change addresses put in a payment).
    pub handed_out: BTreeSet<u32>,
    /// Indices the wallet has seen an output paid to.
    pub used: BTreeSet<u32>,
    /// Every index below this was looked at by a recovery scan.
    pub scanned: u32,
    /// The address of every index handed out, used, or reserved by a scan, so that the wallet knows its own
    /// addresses without deriving keys.
    pub addresses: BTreeMap<u32, String>,
    /// For each reserved index, the height up to which its address's history has been checked (by a
    /// history check, or by the scan that reserved it). An index without one is checked from block 0.
    #[serde(default)]
    pub checked: BTreeMap<u32, u32>,
}

impl ChainBook {
    /// Addresses this device handed out that nothing has been seen paid to yet.
    pub fn waiting(&self) -> usize {
        self.handed_out.difference(&self.used).count()
    }

    /// Whether a new address may be handed out on this chain.
    pub fn can_issue(&self) -> bool {
        self.waiting() < GAP_LIMIT as usize && self.issued < crate::keys::MAX_PQ2_INDEX
    }

    /// The index the next address would get.
    pub fn next(&self) -> Option<u32> {
        self.can_issue().then_some(self.issued)
    }

    /// Hands out the next index, whose address is `address`; None at the gap limit.
    pub fn issue(&mut self, index: u32, address: &str) -> bool {
        if self.next() != Some(index) {
            return false;
        }
        self.issued = index + 1;
        self.handed_out.insert(index);
        self.addresses.insert(index, address.to_string());
        self.checked.remove(&index);
        true
    }

    /// Records that an output was seen paid to this index. Returns whether that is new.
    pub fn mark_used(&mut self, index: u32, address: &str) -> bool {
        self.issued = self.issued.max(index.saturating_add(1));
        self.addresses.insert(index, address.to_string());
        self.checked.remove(&index);
        self.used.insert(index)
    }

    /// The indices whose coins the wallet looks up: those it handed out and those it has seen used.
    pub fn watched(&self) -> Vec<u32> {
        self.handed_out.union(&self.used).copied().collect()
    }

    /// Indices a scan reserved, neither handed out here nor seen used: their history is checked on every
    /// refresh, from the tip of the last check.
    pub fn reserved(&self) -> Vec<u32> {
        (0..self.issued).filter(|i| !self.handed_out.contains(i) && !self.used.contains(i)).collect()
    }

    /// After a scan has looked at every index below `end`: reserve every index up to the highest one seen
    /// plus 20 (indices 0 to 19 when none was seen).
    pub fn scanned_to(&mut self, end: u32) {
        self.scanned = self.scanned.max(end);
        let top = self.used.last().map_or(GAP_LIMIT, |h| h.saturating_add(GAP_LIMIT + 1));
        self.issued = self.issued.max(top);
    }

    /// Where a scan stops: once it has looked at `minimum` indices from its start and the last 20 it looked
    /// at had nothing (an index this device handed out counts as something: it may still be paid).
    pub fn scan_done(&self, start: u32, at: u32, minimum: u32) -> bool {
        // The whole issued range, and a full gap past the highest index known used, every address of them
        // looked at.
        let past_used = self.used.last().map_or(0, |h| h.saturating_add(GAP_LIMIT + 1));
        if at < start.saturating_add(minimum) || at < GAP_LIMIT || at < self.issued || at < past_used {
            return false;
        }
        (at - GAP_LIMIT..at).all(|i| !self.used.contains(&i) && !self.handed_out.contains(&i))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Book {
    pub version: u32,
    /// The receiving address at index 0: ties the file to its wallet.
    pub wallet: String,
    /// The receiving chain, then the change chain.
    pub chains: [ChainBook; 2],
    /// A wallet restored here, or one made before this version, may have pq2 addresses another copy handed
    /// out: none is handed out here until a recovery scan has run.
    pub scan_needed: bool,
    /// Changes whenever a scan is required (`require_scan`).
    #[serde(default)]
    pub scan_revision: u64,
    /// Payments rebuilt through the SLH-DSA leaf: each lineage holds the original and every version made
    /// from it, with their inputs. A new version must conflict with every version that could still confirm.
    #[serde(default)]
    pub lineages: Vec<Lineage>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lineage {
    pub versions: Vec<Version>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub txid: String,
    /// Its inputs, as "txid:vout".
    pub inputs: Vec<String>,
}

impl Book {
    /// The lineage a payment belongs to, if it has been rebuilt before.
    pub fn lineage_of(&self, txid: &str) -> Option<&Lineage> {
        self.lineages.iter().find(|l| l.versions.iter().any(|v| v.txid == txid))
    }

    /// Records `version` as a new version of the lineage of `root` (made of `root` alone so far when it has
    /// none).
    pub fn add_version(&mut self, root: &Version, version: Version) {
        match self.lineages.iter_mut().find(|l| l.versions.iter().any(|v| v.txid == root.txid)) {
            Some(l) => {
                if !l.versions.iter().any(|v| v.txid == version.txid) {
                    l.versions.push(version);
                }
            }
            None => self.lineages.push(Lineage { versions: vec![root.clone(), version] }),
        }
    }
}

impl Book {
    /// The book of a wallet whose receiving address at index 0 is `wallet`. `made_here`: the words were
    /// made on this device just now, so no other copy has handed out anything.
    pub fn new(wallet: &str, made_here: bool) -> Book {
        Book { version: FILE_VERSION, wallet: wallet.to_string(), chains: Default::default(), scan_needed: !made_here, scan_revision: 0, lineages: Vec::new() }
    }

    /// Requires a scan before any address is handed out. The revision changes each time, so that a scan
    /// that began before clears the requirement only if nothing raised it again meanwhile.
    pub fn require_scan(&mut self) {
        self.scan_needed = true;
        self.scan_revision = self.scan_revision.wrapping_add(1);
    }

    /// Records a use of the address at this chain and index, however the wallet learnt of it (a history
    /// check, a coin lookup in a refresh or in planning). When this device did not hand the address out and
    /// it lies within a gap of the end of the issued range, another copy of the wallet may now hand out
    /// addresses up to a gap past it: the range is extended to there and a scan is required. Returns
    /// whether the use is new.
    pub fn record_use(&mut self, chain: u32, index: u32, address: &str) -> bool {
        let c = &mut self.chains[chain as usize];
        let new = c.mark_used(index, address);
        let top = index.saturating_add(GAP_LIMIT + 1);
        if !c.handed_out.contains(&index) && c.issued < top {
            c.issued = top;
            self.require_scan();
        }
        new
    }

    /// The chain and index of one of the wallet's own pq2 addresses (handed out or used).
    pub fn find(&self, address: &str) -> Option<(u32, u32)> {
        self.chains.iter().enumerate().find_map(|(c, book)| {
            book.addresses.iter().find(|(_, a)| a.as_str() == address).map(|(i, _)| (c as u32, *i))
        })
    }

    /// Whether the book's shape is one this version wrote.
    pub fn valid(&self) -> bool {
        self.version == FILE_VERSION && self.shape_ok()
    }

    /// Whether every record lies below its chain's issued index.
    fn shape_ok(&self) -> bool {
        self.chains.iter().all(|c| c.handed_out.iter().chain(&c.used).all(|i| *i < c.issued) && c.addresses.keys().all(|i| *i < c.issued))
    }

    /// A book of version 1, written before the history check: it kept no addresses for reserved indices
    /// and no history watermark. True for such a book of this wallet whose records are whole.
    pub fn needs_migration(&self, wallet: &str) -> bool {
        self.version == 1 && self.wallet == wallet && self.shape_ok()
    }

    /// The reserved indices whose address the book does not have, by chain.
    pub fn reserved_without_address(&self) -> Vec<(u32, u32)> {
        self.chains
            .iter()
            .enumerate()
            .flat_map(|(c, chain)| chain.reserved().into_iter().filter(|i| !chain.addresses.contains_key(i)).map(move |i| (c as u32, i)))
            .collect()
    }

    /// Makes a version 1 book a version 2 one: every issued record is kept, the addresses of reserved
    /// indices are filled in, and a new scan is required (the old one could not see emptied addresses).
    pub fn migrate_from_1(&mut self, reserved: &[(u32, u32, String)]) {
        for (c, i, a) in reserved {
            self.chains[*c as usize].addresses.entry(*i).or_insert_with(|| a.clone());
        }
        self.version = FILE_VERSION;
        self.require_scan();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(i: u32) -> String {
        format!("tb1zaddress{i}")
    }

    #[test]
    fn the_gap_limit_stops_issuing_until_an_address_is_used() {
        let mut c = ChainBook::default();
        for i in 0..GAP_LIMIT {
            assert_eq!(c.next(), Some(i));
            assert!(c.issue(i, &addr(i)));
        }
        // Twenty handed out, none used: nothing more, and an issued index is never given again.
        assert_eq!(c.next(), None);
        assert!(!c.issue(GAP_LIMIT, &addr(GAP_LIMIT)));
        assert!(!c.issue(3, &addr(3)));
        // One of them is paid: one more may be handed out, at the next index.
        assert!(c.mark_used(7, &addr(7)));
        assert!(!c.mark_used(7, &addr(7)));
        assert_eq!(c.next(), Some(GAP_LIMIT));
        assert!(c.issue(GAP_LIMIT, &addr(GAP_LIMIT)));
        assert_eq!(c.next(), None);
        assert_eq!(c.watched().len(), GAP_LIMIT as usize + 1);
    }

    #[test]
    fn a_scan_reserves_up_to_the_highest_seen_plus_twenty_and_reserved_ones_do_not_block() {
        let mut c = ChainBook::default();
        // Nothing seen: 0 to 19 reserved, and the first address handed out here is 20.
        assert!(!c.scan_done(0, 19, 0));
        assert!(c.scan_done(0, 20, 0));
        c.scanned_to(20);
        assert_eq!((c.issued, c.scanned), (20, 20));
        assert_eq!(c.next(), Some(20));
        // Coins at 3 and 31: the scan goes on to 51 at least, and reserves up to 51.
        let mut c = ChainBook::default();
        c.mark_used(3, &addr(3));
        assert!(!c.scan_done(0, 23, 0) && c.scan_done(0, 24, 0));
        c.mark_used(31, &addr(31));
        assert!(!c.scan_done(0, 51, 0) && c.scan_done(0, 52, 0));
        c.scanned_to(52);
        assert_eq!(c.issued, 52);
        assert_eq!(c.next(), Some(52));
        // A wider scan looks at a hundred more at least.
        assert!(!c.scan_done(52, 151, WIDER_SCAN) && c.scan_done(52, 152, WIDER_SCAN));
        // Addresses handed out here keep a scan going: they may be paid later.
        let mut c = ChainBook::default();
        c.issue(0, &addr(0));
        assert!(!c.scan_done(0, 20, 0) && c.scan_done(0, 21, 0));
    }

    #[test]
    fn books_find_addresses_and_refuse_shapes_they_did_not_write() {
        let mut b = Book::new("tb1zwallet", true);
        assert!(!b.scan_needed && Book::new("tb1zwallet", false).scan_needed);
        b.chains[1].issue(0, "tb1zchange0");
        b.chains[0].mark_used(4, "tb1zreceive4");
        assert_eq!(b.find("tb1zchange0"), Some((1, 0)));
        assert_eq!(b.find("tb1zreceive4"), Some((0, 4)));
        assert_eq!(b.find("tb1zother"), None);
        assert!(b.valid());
        let text = serde_json::to_string(&b).unwrap();
        assert_eq!(serde_json::from_str::<Book>(&text).unwrap(), b);
        let mut bad = b.clone();
        bad.chains[0].issued = 2;
        assert!(!bad.valid());
        let mut bad = b.clone();
        bad.version = 3;
        assert!(!bad.valid());
        // Version 1 is not valid as it is: it is migrated (it needs a scan, and its reserved addresses).
        let mut old = b.clone();
        old.version = 1;
        assert!(!old.valid() && old.needs_migration("tb1zwallet") && !old.needs_migration("tb1zother"));
        old.migrate_from_1(&[]);
        assert!(old.valid() && old.scan_needed);
    }
}
