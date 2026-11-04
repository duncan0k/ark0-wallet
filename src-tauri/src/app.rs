//! The commands the interface calls, and the state behind them.
//!
//! The interface never holds a key, a seed or a signature message. It asks for a send by address and
//! amount; the core plans it from coins it fetched itself, shows the plan, and signs exactly that plan
//! when the user confirms it in a dialog of the system (confirm.rs), after checking the coins are still
//! there. Secrets live in `Session` while the wallet is unlocked and are wiped when it locks (by hand, or
//! after the idle time).
use crate::api::{ApiError, BroadcastResult, CheckResult, Coin, Coins, TxStatus};
use crate::chain::{Chain, ChainProblem, Pq2Status};
use crate::keys::{looks_like_backup_code, word_list, KeyError, Keys, Secret, CHANGE_CHAIN, RECEIVE_CHAIN};
use crate::p2mr::{parse_destination, Destination, DestinationError, Kind, Path, Template, MLDSA44_SIGNATURE_CHUNKS, SLHDSA128S_SIGNATURE_CHUNKS};
use crate::pq2::{Book, Version, GAP_LIMIT, WIDER_SCAN};
use crate::proof::REQUIRED_BLOCKS;
use crate::sources::{Flags, Sources, StateError};
use crate::store::{self, Sent, Settings};
use crate::vault::{self, VaultError};
use crate::wallet::{self, Account, Amount, Plan, PlanError, SignError, FEE_RATE};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::{poll_fn, Future};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::watch;
use zeroize::Zeroizing;

pub const EXPLORER: &str = "https://explorer.ark0.si";
pub const FAUCET: &str = "https://faucet.ark0.si/";
/// A planned send that waits longer than this for its confirmation is dropped.
const PLAN_LIFETIME: Duration = Duration::from_secs(600);

/// A mutex's data. A panic while one was held leaves its data whole here (an Option replaced, an Instant
/// set), so the lock is taken back instead of failing every later command, the session's above all.
fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An error as the interface sees it: a code it translates.
#[derive(Debug, Serialize)]
pub struct Failure {
    pub code: String,
}

impl Failure {
    fn new(code: &str) -> Self {
        Failure { code: code.to_string() }
    }
}

fn code_of<T: Serialize>(value: &T) -> Failure {
    Failure { code: serde_json::to_value(value).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_else(|| "internal".into()) }
}

impl From<VaultError> for Failure {
    fn from(e: VaultError) -> Self {
        code_of(&e)
    }
}
impl From<KeyError> for Failure {
    fn from(e: KeyError) -> Self {
        code_of(&e)
    }
}
impl From<ApiError> for Failure {
    fn from(e: ApiError) -> Self {
        code_of(&e)
    }
}
impl From<PlanError> for Failure {
    fn from(e: PlanError) -> Self {
        code_of(&e)
    }
}
impl From<DestinationError> for Failure {
    fn from(e: DestinationError) -> Self {
        code_of(&e)
    }
}
impl From<ChainProblem> for Failure {
    fn from(e: ChainProblem) -> Self {
        code_of(&e)
    }
}
impl From<StateError> for Failure {
    fn from(e: StateError) -> Self {
        match e {
            StateError::Api(e) => e.into(),
            StateError::Chain(e) => e.into(),
        }
    }
}
impl From<SignError> for Failure {
    fn from(e: SignError) -> Self {
        match e {
            SignError::Key(k) => k.into(),
            SignError::Mismatch => Failure::new("mismatch"),
        }
    }
}

type Res<T> = Result<T, Failure>;

/// A wallet's identity (its pq2 receiving address at index 0) and the session generation, taken when
/// asynchronous pq2 work starts: its results go to that wallet's book only, and only in that session.
#[derive(Clone, Debug)]
struct Bound {
    wallet: String,
    generation: u64,
}

/// What a refresh works for, taken in one section of the session: the three fixed templates, the pq2
/// wallet (None without pq2) and the session generation. A refresh checks it again after every wait on the
/// network and before it returns (`AppState::current`).
#[derive(Clone)]
struct Snapshot {
    templates: (Template, Template, Template),
    bound: Option<Bound>,
    generation: u64,
}

/// The unlocked wallet.
struct Session {
    legacy: bool,
    keys: Keys,
    schnorr: Template,
    mldsa44: Template,
    mixed: Template,
    /// The pq2 receiving address at index 0, which names the wallet's pq2 book; None without pq2.
    pq2_wallet: Option<String>,
    /// pq2 templates derived so far, by chain and index (public data only).
    pq2: HashMap<(u32, u32), Template>,
}

impl Session {
    fn new(secret: &Secret) -> Result<Session, KeyError> {
        let keys = Keys::from_secret(secret)?;
        let mut pq2 = HashMap::new();
        let pq2_wallet = if keys.has_pq2() {
            let first = keys.pq2(RECEIVE_CHAIN, 0)?.template();
            let address = first.address.clone();
            pq2.insert((RECEIVE_CHAIN, 0), first);
            Some(address)
        } else {
            None
        };
        Ok(Session {
            legacy: secret.is_legacy(),
            schnorr: keys.template(Kind::Schnorr),
            mldsa44: keys.template(Kind::Mldsa44),
            mixed: keys.template(Kind::Mixed),
            keys,
            pq2_wallet,
            pq2,
        })
    }

    /// The pq2 output at this chain and index, derived once per session.
    fn pq2_template(&mut self, chain: u32, index: u32) -> Res<Template> {
        if let Some(t) = self.pq2.get(&(chain, index)) {
            return Ok(t.clone());
        }
        let t = self.keys.pq2(chain, index)?.template();
        self.pq2.insert((chain, index), t.clone());
        Ok(t)
    }

    /// The template of one of the three fixed addresses; pq2 addresses are looked up by address.
    fn template(&self, kind: Kind) -> Res<Template> {
        match kind {
            Kind::Schnorr => Ok(self.schnorr.clone()),
            Kind::Mldsa44 => Ok(self.mldsa44.clone()),
            Kind::Mixed => Ok(self.mixed.clone()),
            Kind::Pq2 => Err(Failure::new("address_not_ready")),
        }
    }
}

struct PendingSend {
    id: String,
    created: Instant,
    kind: Kind,
    path: Path,
    destination: Destination,
    plan: Plan,
    /// The system dialog showed the warnings, so recording may go ahead with them.
    caution: bool,
    sources: Flags,
    /// The payment creates a pq2 output (its change, or the destination is one of the wallet's own pq2
    /// addresses): its lock time is H4T.
    creates_pq2: bool,
    /// A spend from a pq2 address.
    pq2: Option<Pq2Pending>,
    /// The address the payment spends from.
    plan_address: String,
    /// The payment this one rebuilds through the SLH-DSA leaf.
    rebuild: Option<Rebuild>,
}

/// A rebuild is bound to the payment it replaces through one anchor input: the original's first input,
/// fixed when the original was recorded. Every version of the payment spends the anchor, so any two
/// versions conflict and at most one can confirm. A rebuild is planned only while the anchor is spendable
/// (unspent, held by no transaction in the mempool), and none is made once a version of the payment is in
/// the mempool or confirmed. The lineage (the versions made so far, kept in the book) is a record for the
/// lookups before broadcast and for display; it decides nothing about safety.
#[derive(Clone, Debug)]
struct Rebuild {
    /// The original asked to be rebuilt, with its inputs; its txid is empty when it was dropped before it
    /// was sent (then nothing else of it can confirm, and the rebuild is bound to nothing).
    root: Version,
    /// Every version of the lineage, the original included, as the book had it when planning.
    versions: Vec<Version>,
}

impl Rebuild {
    /// The rebuild of a recorded payment, with its lineage from the book.
    fn of(book: &Book, original: &Sent) -> Rebuild {
        let root = Version { txid: original.txid.clone(), inputs: original.outpoints.clone() };
        let versions = book.lineage_of(&original.txid).map_or_else(|| vec![root.clone()], |l| l.versions.clone());
        Rebuild { root, versions }
    }

    /// The rebuild of a payment dropped before it was sent.
    fn unsent() -> Rebuild {
        Rebuild { root: Version { txid: String::new(), inputs: Vec::new() }, versions: Vec::new() }
    }

    fn bound(&self) -> bool {
        !self.root.txid.is_empty()
    }

    /// The anchor: the original's first input (the first version of the lineage), which every version
    /// spends.
    fn anchor(&self) -> Option<&str> {
        self.versions.first().unwrap_or(&self.root).inputs.first().map(String::as_str)
    }

    /// Whether every recorded version of the payment spends its anchor. A lineage made before every version
    /// had to may hold one that does not; such a payment is not rebuilt (`rebuild_not_possible`): a new
    /// version could share no input with it.
    fn anchored(&self, versions: &[Version]) -> bool {
        self.anchor().is_some_and(|a| versions.iter().all(|v| v.inputs.iter().any(|i| i == a)))
    }
}

/// What a command reports when the pq2 book could not be read or saved: `pq2_book_full` when the change
/// would make it larger than the wallet reads back.
fn book_write_failure(e: std::io::Error) -> Failure {
    Failure::new(if e.kind() == std::io::ErrorKind::FileTooLarge { "pq2_book_full" } else { "io" })
}

/// Whether a version of the payment is in the mempool or confirmed, by the wallet's records: then no more
/// rebuilds of it.
fn lineage_went_out(versions: &[Version], sent: &[Sent]) -> bool {
    versions.iter().any(|v| sent.iter().any(|s| s.txid == v.txid && original_went_out(s) && s.status != "replaced"))
}

#[derive(Clone, Copy, Debug)]
struct Pq2Pending {
    /// The receiving or change chain and the index of the address spent from.
    chain: u32,
    index: u32,
    /// The change chain index the change goes to, handed out when the payment is recorded.
    change: Option<u32>,
}

/// A new wallet's words, between showing them and saving the vault.
struct NewWallet {
    secret: Secret,
    confirmed: bool,
}

pub struct AppState {
    dir: PathBuf,
    sources: Arc<Sources>,
    session: Mutex<Option<Session>>,
    new_wallet: Mutex<Option<NewWallet>>,
    pending: Mutex<Option<PendingSend>>,
    /// The last use by the monotonic clock and by the wall clock: the first may stop while the device
    /// sleeps, the second may be set back by hand. The idle lock goes by whichever has gone further.
    last_use: Mutex<(Instant, SystemTime)>,
    settings: Mutex<Settings>,
    /// Held while the vault is made, replaced or removed, or read to open a session.
    vault_ops: Mutex<()>,
    /// Held while the record of sent transactions is read, changed and saved (`edit_sent`).
    sent_ops: Mutex<()>,
    /// Held while the pq2 book is read, changed and saved (`edit_book`).
    pq2_ops: Mutex<()>,
    /// Held while a payment is committed: the final check of a rebuild's lineage, its joining the lineage,
    /// the change address handed out and the record made as submitting, all in one section.
    commit_ops: Mutex<()>,
    /// One operation on the pq2 address book at a time, held across its waits on the network: a recovery
    /// scan, a history check of the reserved addresses, handing out a receiving address, handing out a
    /// change address when a payment is committed. A history check that finds another operation running
    /// (a scan among them) is skipped; the next refresh makes it.
    book_ops: tokio::sync::Mutex<()>,
    /// Tests: this many next saves of the pq2 book fail.
    #[cfg(test)]
    fail_book_writes: AtomicUsize,
    /// Tests: this many next saves of the record of payments fail.
    #[cfg(test)]
    fail_sent_writes: AtomicUsize,
    /// Tests: run in a confirmation after its last wait on the network, before it commits the payment.
    #[cfg(test)]
    before_commit: Mutex<Option<Box<dyn FnMut(&AppState) + Send>>>,
    /// Tests: run by a create or restore before its section.
    #[cfg(test)]
    before_set_up: Mutex<Option<Box<dyn FnMut(&AppState) + Send>>>,
    /// Tests: run before a plan is kept, ahead of the section that checks and keeps it.
    #[cfg(test)]
    before_plan_kept: Mutex<Option<Box<dyn FnMut(&AppState) + Send>>>,
    /// Tests: run when a session has been installed, before its book is written.
    #[cfg(test)]
    after_session_installed: Mutex<Option<Box<dyn FnMut(&AppState) + Send>>>,
    /// Tests: run after every network answer a scan or a refresh of pq2 gets.
    #[cfg(test)]
    after_network_answer: Mutex<Option<Box<dyn FnMut(&AppState) + Send>>>,
    /// Lookups started by any refresh, until their results have been saved.
    sent_lookups: Mutex<HashSet<String>>,
    /// The wallet's addresses' coins as the last lookup of each found them (SEEN_FOR at most): a plan and its
    /// confirmation take the pending coins of the addresses they do not pay from here (`pending_everywhere`).
    /// Emptied when the wallet locks.
    seen_coins: SeenCoins,
    /// Counts locks. Work that began before a lock (an unlock's key derivation, a send waiting on the
    /// network or the user) neither opens a session nor signs after it.
    generation: AtomicU64,
    /// Wakes every sensitive command waiting for a system dialog when the wallet locks.
    locked: watch::Sender<()>,
    /// Kept open until shutdown; the lock file itself is never removed or replaced.
    _wallet_lock: std::fs::File,
}

impl AppState {
    pub fn new(dir: PathBuf) -> Result<Self, std::fs::TryLockError> {
        let wallet_lock = store::lock_wallet(&dir)?;
        let settings = store::load_settings(&dir.join("settings.json"));
        let state = AppState {
            sources: Arc::new(Sources::default()),
            settings: Mutex::new(if settings.valid() { settings } else { Settings::default() }),
            dir,
            session: Mutex::new(None),
            new_wallet: Mutex::new(None),
            pending: Mutex::new(None),
            last_use: Mutex::new((Instant::now(), SystemTime::now())),
            vault_ops: Mutex::new(()),
            sent_ops: Mutex::new(()),
            pq2_ops: Mutex::new(()),
            commit_ops: Mutex::new(()),
            book_ops: tokio::sync::Mutex::const_new(()),
            #[cfg(test)]
            fail_book_writes: AtomicUsize::new(0),
            #[cfg(test)]
            fail_sent_writes: AtomicUsize::new(0),
            #[cfg(test)]
            after_network_answer: Mutex::new(None),
            #[cfg(test)]
            after_session_installed: Mutex::new(None),
            #[cfg(test)]
            before_set_up: Mutex::new(None),
            #[cfg(test)]
            before_plan_kept: Mutex::new(None),
            #[cfg(test)]
            before_commit: Mutex::new(None),
            sent_lookups: Mutex::new(HashSet::new()),
            seen_coins: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
            locked: watch::channel(()).0,
            _wallet_lock: wallet_lock,
        };
        // The startup migration goes through the size check too; when the record does not fit, the readable file stays as it was.
        let _ = edit_sent(&state, |sent| {
            for s in sent.iter_mut().filter(|s| s.status == "submitting") {
                s.status = "unknown".into();
                s.doubted = true;
            }
        });
        Ok(state)
    }

    fn vault_path(&self) -> PathBuf {
        self.dir.join("vault.json")
    }

    fn sent_path(&self) -> PathBuf {
        self.dir.join("sent.json")
    }

    fn pq2_path(&self) -> PathBuf {
        self.dir.join("pq2.json")
    }

    fn touch(&self) {
        *guard(&self.last_use) = (Instant::now(), SystemTime::now());
    }

    /// Time since the last use, by whichever clock has gone further.
    fn idle(&self) -> Duration {
        let (at, wall) = *guard(&self.last_use);
        at.elapsed().max(wall.elapsed().unwrap_or_default())
    }

    fn lock(&self) {
        // A commit in progress finishes first (`commit_ops` is always taken before the session).
        let _commit = guard(&self.commit_ops);
        // Serialize locking with the final session check and mutation of a confirmed wallet change.
        self.lock_session(guard(&self.session));
    }

    fn lock_session(&self, mut session: MutexGuard<'_, Option<Session>>) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.locked.send_replace(());
        *session = None;
        drop(session);
        *guard(&self.pending) = None;
        guard(&self.seen_coins).clear();
        self.cancel_new_wallet();
    }

    pub(crate) fn cancel_new_wallet(&self) {
        *guard(&self.new_wallet) = None;
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// The language of a system dialog.
    fn dialog_locale(&self, resolved: Option<&str>) -> &'static str {
        crate::confirm::locale(&guard(&self.settings).language, resolved)
    }

    fn unlocked(&self) -> bool {
        guard(&self.session).is_some()
    }

    /// The templates of the unlocked wallet (public data only).
    fn templates(&self) -> Res<(Template, Template, Template)> {
        let s = guard(&self.session);
        let s = s.as_ref().ok_or_else(|| Failure::new("locked"))?;
        Ok((s.schnorr.clone(), s.mldsa44.clone(), s.mixed.clone()))
    }

    /// Opens the wallet, unless it was locked since `generation` was read. `made_here`: the words were just
    /// made on this device, so no other copy of the wallet has handed out pq2 addresses.
    fn open_session(&self, secret: &Secret, generation: u64, made_here: bool) -> Res<()> {
        let session = Session::new(secret)?;
        self.install_session(session, generation, made_here, || Ok(()))
    }

    /// Installs a session whose keys are derived, unless the wallet was locked since `generation`.
    /// `first_write` (a new wallet's vault), the session and the wallet's first book are made in one
    /// section under the commit lock, after the generation check: locking, removing or replacing a wallet
    /// (each takes that lock) cannot come between them, and a request begun before a lock writes nothing.
    fn install_session(&self, session: Session, generation: u64, made_here: bool, first_write: impl FnOnce() -> Res<()>) -> Res<()> {
        let wallet = session.pq2_wallet.clone();
        let _commit = guard(&self.commit_ops);
        // The generation changes only under the commit lock.
        if self.generation() != generation {
            return Err(Failure::new("locked"));
        }
        first_write()?;
        let mut current = guard(&self.session);
        *current = Some(session);
        drop(current);
        self.touch();
        #[cfg(test)]
        {
            let hook = guard(&self.after_session_installed).take();
            if let Some(mut hook) = hook {
                hook(self);
            }
        }
        // A pq2 book of another wallet, or none: a fresh one, which scans first unless the words are new.
        // A book of an older version is migrated: its records kept, the reserved addresses derived, and a
        // scan required.
        if let Some(wallet) = wallet {
            let current = self.edit_book_raw(|book| book.clone()).ok().flatten();
            let mut reserved = Vec::new();
            if let Some(old) = current.filter(|b| b.needs_migration(&wallet)) {
                for (c, i) in old.reserved_without_address() {
                    reserved.push((c, i, self.pq2_template(c, i)?.address));
                }
            }
            let _ = self.edit_book_raw(|book| match book {
                Some(b) if b.needs_migration(&wallet) => b.migrate_from_1(&reserved),
                Some(b) if b.wallet == wallet && b.valid() => {}
                _ => *book = Some(Book::new(&wallet, made_here)),
            });
        }
        Ok(())
    }

    /// The pq2 book, read, changed and saved under its lock; saved only when it changed. A file that cannot
    /// be read is not replaced.
    fn edit_book_raw<R>(&self, change: impl FnOnce(&mut Option<Book>) -> R) -> std::io::Result<R> {
        let _one_at_a_time = guard(&self.pq2_ops);
        let path = self.pq2_path();
        let mut book: Option<Book> = match store::read_capped(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).ok(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let before = book.clone();
        let result = change(&mut book);
        if book != before {
            if let Some(b) = &book {
                #[cfg(test)]
                if self.fail_book_writes.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
                    return Err(std::io::Error::other("a failing disk (test)"));
                }
                // Never a book the wallet could not read back: the change is refused instead.
                store::save_readable(&path, b)?;
            }
        }
        Ok(result)
    }

    /// The unlocked wallet's pq2 book, changed under its lock; `pq2_unavailable` for a wallet without pq2.
    fn edit_book<R>(&self, change: impl FnOnce(&mut Book) -> R) -> Res<R> {
        let wallet = guard(&self.session).as_ref().ok_or_else(|| Failure::new("locked"))?.pq2_wallet.clone();
        let wallet = wallet.ok_or_else(|| Failure::new("pq2_unavailable"))?;
        self.edit_book_raw(|book| match book {
            Some(b) if b.wallet == wallet && b.valid() => Ok(change(b)),
            _ => Err(Failure::new("pq2_unavailable")),
        })
        .map_err(book_write_failure)?
    }

    /// The pq2 book of the wallet named `wallet`, changed under its lock, only while that wallet is still
    /// the open one and the session has not been locked since `generation`: work begun for one wallet never
    /// writes into another's book.
    fn edit_book_of<R>(&self, wallet: &str, generation: u64, change: impl FnOnce(&mut Book) -> R) -> Res<R> {
        self.still_open(wallet, generation)?;
        self.edit_book_raw(|book| match book {
            Some(b) if b.wallet == wallet && b.valid() && self.generation() == generation => Ok(change(b)),
            _ => Err(Failure::new("locked")),
        })
        .map_err(book_write_failure)?
    }

    /// Err("locked") unless `wallet` is still the open wallet and nothing locked it since `generation`.
    fn still_open(&self, wallet: &str, generation: u64) -> Res<()> {
        let session = guard(&self.session);
        let open = session.as_ref().and_then(|s| s.pq2_wallet.as_deref()) == Some(wallet);
        if !open || self.generation() != generation {
            return Err(Failure::new("locked"));
        }
        Ok(())
    }

    /// The pq2 template at this chain and index of the wallet named `wallet`, while it is still open.
    fn pq2_template_of(&self, wallet: &str, generation: u64, chain: u32, index: u32) -> Res<Template> {
        let mut session = guard(&self.session);
        let s = session.as_mut().filter(|s| s.pq2_wallet.as_deref() == Some(wallet) && self.generation() == generation);
        s.ok_or_else(|| Failure::new("locked"))?.pq2_template(chain, index)
    }

    /// After an answer from the network: Err("locked") unless the bound wallet is still open in the same
    /// session.
    fn answered(&self, bound: &Bound) -> Res<()> {
        #[cfg(test)]
        {
            let hook = guard(&self.after_network_answer).take();
            if let Some(mut hook) = hook {
                hook(self);
                *guard(&self.after_network_answer) = Some(hook);
            }
        }
        self.still_open(&bound.wallet, bound.generation)
    }

    fn book(&self) -> Res<Book> {
        self.edit_book(|b| b.clone())
    }

    /// The open wallet's templates, pq2 identity and session generation, all read under one hold of the
    /// session (a lock changes the generation under the same hold).
    fn snapshot(&self) -> Res<Snapshot> {
        let session = guard(&self.session);
        let s = session.as_ref().ok_or_else(|| Failure::new("locked"))?;
        let generation = self.generation();
        Ok(Snapshot {
            templates: (s.schnorr.clone(), s.mldsa44.clone(), s.mixed.clone()),
            bound: s.pq2_wallet.clone().map(|wallet| Bound { wallet, generation }),
            generation,
        })
    }

    /// Err("locked") unless the wallet of the snapshot is still open in the same session: after each wait
    /// on the network, and before a refresh returns or keeps anything.
    fn current(&self, snapshot: &Snapshot) -> Res<()> {
        #[cfg(test)]
        {
            let hook = guard(&self.after_network_answer).take();
            if let Some(mut hook) = hook {
                hook(self);
                *guard(&self.after_network_answer) = Some(hook);
            }
        }
        self.still_current(snapshot)
    }

    /// The pq2 book of the snapshot's wallet, changed only while it is still open in the same session.
    fn edit_book_for<R>(&self, snapshot: &Snapshot, change: impl FnOnce(&mut Book) -> R) -> Res<R> {
        let b = snapshot.bound.as_ref().ok_or_else(|| Failure::new("pq2_unavailable"))?;
        self.edit_book_of(&b.wallet, b.generation, change)
    }

    /// The check of `current`, alone.
    fn still_current(&self, snapshot: &Snapshot) -> Res<()> {
        let session = guard(&self.session);
        let same = session.as_ref().is_some_and(|s| s.pq2_wallet == snapshot.bound.as_ref().map(|b| b.wallet.clone()));
        if !same || self.generation() != snapshot.generation {
            return Err(Failure::new("locked"));
        }
        Ok(())
    }

    /// The pq2 template at this chain and index.
    fn pq2_template(&self, chain: u32, index: u32) -> Res<Template> {
        guard(&self.session).as_mut().ok_or_else(|| Failure::new("locked"))?.pq2_template(chain, index)
    }

    /// The wallet's own addresses: the three fixed ones, and the pq2 addresses it handed out or saw used.
    fn own_templates(&self) -> Res<Vec<Template>> {
        let (a, b, c) = self.templates()?;
        let mut own = vec![a, b, c];
        if let Ok(book) = self.book() {
            for (chain, c) in book.chains.iter().enumerate() {
                for index in c.watched() {
                    own.push(self.pq2_template(chain as u32, index)?);
                }
            }
        }
        Ok(own)
    }
}

/// Locks the wallet after the idle time; started once with the app.
pub fn start_idle_lock(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let state = app.state::<AppState>();
        let minutes = guard(&state.settings).auto_lock_minutes;
        if minutes > 0 && state.unlocked() && state.idle() >= Duration::from_secs(60 * u64::from(minutes)) {
            state.lock();
            let _ = app.emit("wallet-locked", ());
        }
    });
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Amounts as the interface writes them: coins with at most eight decimals ("1.5", "0.0001").
fn parse_coins(text: &str) -> Option<u64> {
    let text = text.trim();
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() || whole.len() > 8 || frac.len() > 8 || !whole.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    if text.ends_with('.') {
        return None;
    }
    let sats = whole.parse::<u64>().ok()? * 100_000_000 + format!("{frac:0<8}").parse::<u64>().ok()?;
    (sats > 0).then_some(sats)
}

// ---- the wallet's existence, creation and unlocking ----

#[derive(Serialize)]
pub struct Status {
    exists: bool,
    unlocked: bool,
    legacy: Option<bool>,
}

#[tauri::command]
pub fn wallet_status(state: State<'_, AppState>) -> Status {
    let session = guard(&state.session);
    Status { exists: vault::exists(&state.vault_path()), unlocked: session.is_some(), legacy: session.as_ref().map(|s| s.legacy) }
}

/// Makes the 24 words of a new wallet (nothing is saved until `create_wallet`).
#[tauri::command]
pub fn new_phrase(state: State<'_, AppState>) -> Res<Vec<String>> {
    let generation = state.generation();
    let mut new = guard(&state.new_wallet);
    *new = None;
    let secret = Secret::new_bip39()?;
    let words = secret.recovery_text().split(' ').map(String::from).collect();
    if state.generation() != generation {
        return Err(Failure::new("locked"));
    }
    *new = Some(NewWallet { secret, confirmed: false });
    Ok(words)
}

/// Leaving the create flow drops its pending secret, whose bytes are wiped on drop.
#[tauri::command]
pub fn cancel_new_wallet(state: State<'_, AppState>) {
    state.cancel_new_wallet();
}

/// The words at these positions (0-based, at least three different ones), as the user typed them back
/// from their copy.
#[tauri::command]
pub fn confirm_phrase(state: State<'_, AppState>, positions: Vec<usize>, words: Vec<String>) -> Res<()> {
    let words = Zeroizing::new(words);
    let mut new = guard(&state.new_wallet);
    let new = new.as_mut().ok_or_else(|| Failure::new("no_phrase"))?;
    let text = new.secret.recovery_text();
    let all: Vec<&str> = text.split(' ').collect();
    let distinct: std::collections::HashSet<usize> = positions.iter().copied().collect();
    let ok = distinct.len() >= 3
        && positions.len() == words.len()
        && positions.iter().zip(words.iter()).all(|(&i, w)| all.get(i).is_some_and(|x| x.eq_ignore_ascii_case(w.trim())));
    new.confirmed = ok;
    if ok {
        Ok(())
    } else {
        Err(Failure::new("phrase_mismatch"))
    }
}

#[tauri::command(async)]
pub fn create_wallet(state: State<'_, AppState>, password: String) -> Res<Status> {
    create_confirmed_wallet(&state, password)?;
    Ok(wallet_status(state))
}

fn create_confirmed_wallet(state: &AppState, password: String) -> Res<()> {
    let password = Zeroizing::new(password);
    let generation = state.generation();
    let secret = {
        let pending = guard(&state.new_wallet);
        let new = pending.as_ref().ok_or_else(|| Failure::new("no_phrase"))?;
        if !new.confirmed {
            return Err(Failure::new("phrase_not_confirmed"));
        }
        new.secret.clone()
    };
    // The slow derivations first, outside any lock.
    let sealed = vault::seal_new(&password, &secret)?;
    let session = Session::new(&secret)?;
    before_set_up(state);
    let _one_at_a_time = guard(&state.vault_ops);
    state.install_session(session, generation, true, || {
        // The same confirmed words still pending; they are kept for another try on failure, and taken
        // only once the vault is written.
        let mut pending = guard(&state.new_wallet);
        if !pending.as_ref().is_some_and(|n| n.confirmed && n.secret == secret) {
            return Err(Failure::new("no_phrase"));
        }
        remove_orphaned_record(state)?;
        vault::create_sealed(&state.vault_path(), &sealed)?;
        pending.take();
        Ok(())
    })
}

/// Tests: run by a create or restore after its slow derivations, before its section.
fn before_set_up(_state: &AppState) {
    #[cfg(test)]
    {
        let hook = guard(&_state.before_set_up).take();
        if let Some(mut hook) = hook {
            hook(_state);
        }
    }
}

#[derive(Serialize)]
pub struct RecoveryKind {
    legacy: bool,
}

fn parse_recovery(text: &str) -> Res<Secret> {
    if looks_like_backup_code(text) {
        Ok(Secret::from_backup_code(text)?)
    } else {
        Ok(Secret::from_phrase(text)?)
    }
}

/// Whether the text is 24 valid words or a valid backup code, without keeping it.
#[tauri::command]
pub fn check_recovery(text: String) -> Res<RecoveryKind> {
    let text = Zeroizing::new(text);
    Ok(RecoveryKind { legacy: parse_recovery(&text)?.is_legacy() })
}

#[tauri::command(async)]
pub fn restore_wallet(state: State<'_, AppState>, text: String, password: String) -> Res<Status> {
    restore_wallet_from_text(&state, text, password)?;
    Ok(wallet_status(state))
}

fn restore_wallet_from_text(state: &AppState, text: String, password: String) -> Res<()> {
    let (text, password) = (Zeroizing::new(text), Zeroizing::new(password));
    let generation = state.generation();
    let secret = parse_recovery(&text)?;
    // The slow derivations first, outside any lock.
    let sealed = vault::seal_new(&password, &secret)?;
    let session = Session::new(&secret)?;
    before_set_up(state);
    let _one_at_a_time = guard(&state.vault_ops);
    state.install_session(session, generation, false, || {
        remove_orphaned_record(state)?;
        vault::create_sealed(&state.vault_path(), &sealed)?;
        Ok(())
    })
}

#[tauri::command]
pub fn bip39_words() -> Vec<&'static str> {
    word_list().to_vec()
}

#[tauri::command(async)]
pub fn unlock(state: State<'_, AppState>, password: String) -> Res<Status> {
    unlock_wallet(&state, password)?;
    Ok(wallet_status(state))
}

fn unlock_wallet(state: &AppState, password: String) -> Res<()> {
    let password = Zeroizing::new(password);
    let generation = state.generation();
    let _one_at_a_time = guard(&state.vault_ops);
    let secret = vault::open(&state.vault_path(), &password)?;
    state.open_session(&secret, generation, false)
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) {
    state.lock();
}

/// The interface reports use (input, clicks) so that the idle lock counts from the last one.
#[tauri::command]
pub fn touch(state: State<'_, AppState>) {
    if state.unlocked() {
        state.touch();
    }
}

/// The words or backup code, after the password again and a confirmation outside the web view.
#[tauri::command]
pub async fn reveal_recovery(app: AppHandle, state: State<'_, AppState>, password: String, locale: Option<String>) -> Res<String> {
    reveal_secret(&state, password, locale.as_deref(), |dialog| crate::confirm::ask(&app, dialog)).await
}

async fn reveal_secret<F: Future<Output = bool>>(
    state: &AppState,
    password: String,
    locale: Option<&str>,
    ask: impl FnOnce(crate::confirm::Dialog) -> F,
) -> Res<String> {
    let password = Zeroizing::new(password);
    let generation = state.generation();
    if !state.unlocked() {
        return Err(Failure::new("locked"));
    }
    let secret = vault::open(&state.vault_path(), &password)?;
    drop(password);
    confirm_unlocked(state, generation, crate::confirm::recovery(state.dialog_locale(locale), secret.is_legacy()), ask).await?;
    let session = guard(&state.session);
    if session.is_none() || state.generation() != generation {
        return Err(Failure::new("locked"));
    }
    Ok(secret.recovery_text().to_string())
}

/// A lock ends the request without waiting for the native dialog's answer. The dialog owns no secrets;
/// dropping its future leaves any later answer with no command to authorize.
async fn confirm_unlocked<F: Future<Output = bool>>(
    state: &AppState,
    generation: u64,
    dialog: crate::confirm::Dialog,
    ask: impl FnOnce(crate::confirm::Dialog) -> F,
) -> Res<()> {
    // Subscribe before checking the generation so that a lock cannot be missed between them.
    let mut locked = state.locked.subscribe();
    if state.generation() != generation || !state.unlocked() {
        return Err(Failure::new("locked"));
    }
    let mut answer = std::pin::pin!(ask(dialog));
    let mut changed = std::pin::pin!(locked.changed());
    let confirmed = poll_fn(|cx| {
        // Locking wins when both the lock and the dialog answer are ready.
        if changed.as_mut().poll(cx).is_ready() || state.generation() != generation {
            return Poll::Ready(Err(Failure::new("locked")));
        }
        answer.as_mut().poll(cx).map(Ok)
    }).await?;
    if state.generation() != generation || !state.unlocked() {
        return Err(Failure::new("locked"));
    }
    if !confirmed {
        return Err(Failure::new("cancelled"));
    }
    Ok(())
}

#[tauri::command]
pub async fn change_password(app: AppHandle, state: State<'_, AppState>, old: String, new: String, locale: Option<String>) -> Res<()> {
    change_wallet_password(&state, old, new, locale.as_deref(), |dialog| crate::confirm::ask(&app, dialog)).await
}

async fn change_wallet_password<F: Future<Output = bool>>(
    state: &AppState,
    old: String,
    new: String,
    locale: Option<&str>,
    ask: impl FnOnce(crate::confirm::Dialog) -> F,
) -> Res<()> {
    let (old, new) = (Zeroizing::new(old), Zeroizing::new(new));
    let generation = state.generation();
    if !state.unlocked() {
        return Err(Failure::new("locked"));
    }
    // Check the password before asking, and drop the decrypted secret immediately.
    vault::open(&state.vault_path(), &old)?;
    confirm_unlocked(state, generation, crate::confirm::password_change(state.dialog_locale(locale)), ask).await?;
    let _one_at_a_time = guard(&state.vault_ops);
    let session = guard(&state.session);
    if session.is_none() || state.generation() != generation {
        return Err(Failure::new("locked"));
    }
    Ok(vault::change_password(&state.vault_path(), &old, &new)?)
}

/// Removes the wallet from this device: the vault and the record of sent transactions.
#[tauri::command]
pub async fn delete_wallet(app: AppHandle, state: State<'_, AppState>, password: String, locale: Option<String>) -> Res<Status> {
    remove_wallet(&state, password, locale.as_deref(), |dialog| crate::confirm::ask(&app, dialog)).await?;
    Ok(wallet_status(state))
}

async fn remove_wallet<F: Future<Output = bool>>(
    state: &AppState,
    password: String,
    locale: Option<&str>,
    ask: impl FnOnce(crate::confirm::Dialog) -> F,
) -> Res<()> {
    let password = Zeroizing::new(password);
    let generation = state.generation();
    if !state.unlocked() {
        return Err(Failure::new("locked"));
    }
    vault::open(&state.vault_path(), &password)?;
    confirm_unlocked(state, generation, crate::confirm::removal(state.dialog_locale(locale)), ask).await?;
    {
        let _one_at_a_time = guard(&state.vault_ops);
        // A commit in progress finishes first.
        let _commit = guard(&state.commit_ops);
        let session = guard(&state.session);
        if session.is_none() || state.generation() != generation {
            return Err(Failure::new("locked"));
        }
        // The password may have changed while the dialog was open. Check it before deleting either file.
        vault::open(&state.vault_path(), &password)?;
        // Locked before the record goes, so that no send begun earlier records into a fresh one.
        state.lock_session(session);
        remove_wallet_files(state)?;
    }
    Ok(())
}

/// For a forgotten password: removes the wallet without it, only while it is locked, and only after the
/// user confirms in a system dialog (the interface's own confirmation is not enough: it is the web view's).
/// The recovery words or backup code bring the wallet back.
#[tauri::command]
pub async fn forget_wallet(app: AppHandle, state: State<'_, AppState>, locale: Option<String>) -> Res<Status> {
    forget_locked_wallet(&state, locale.as_deref(), |dialog| crate::confirm::ask(&app, dialog)).await?;
    Ok(wallet_status(state))
}

async fn forget_locked_wallet<F: Future<Output = bool>>(
    state: &AppState,
    locale: Option<&str>,
    ask: impl FnOnce(crate::confirm::Dialog) -> F,
) -> Res<()> {
    // Subscribe before reading the generation so that a lock cannot be missed between them.
    let mut locked = state.locked.subscribe();
    let generation = state.generation();
    if state.unlocked() {
        return Err(Failure::new("unlocked"));
    }
    let mut answer = std::pin::pin!(ask(crate::confirm::removal(state.dialog_locale(locale))));
    let mut changed = std::pin::pin!(locked.changed());
    let confirmed = poll_fn(|cx| {
        // Locking wins when both the lock and the dialog answer are ready.
        if changed.as_mut().poll(cx).is_ready() || state.generation() != generation {
            return Poll::Ready(Err(Failure::new("cancelled")));
        }
        if state.unlocked() {
            return Poll::Ready(Err(Failure::new("unlocked")));
        }
        answer.as_mut().poll(cx).map(Ok)
    }).await?;
    if !confirmed {
        return Err(Failure::new("cancelled"));
    }
    {
        let _one_at_a_time = guard(&state.vault_ops);
        // A commit in progress finishes first.
        let _commit = guard(&state.commit_ops);
        let session = guard(&state.session);
        if state.generation() != generation {
            return Err(Failure::new("cancelled"));
        }
        if session.is_some() {
            return Err(Failure::new("unlocked"));
        }
        // An unlock still deriving its key does not open the wallet after it is gone.
        state.lock_session(session);
        remove_wallet_files(state)?;
    }
    Ok(())
}

/// Called under vault_ops before creating a vault; only NotFound means the old vault is gone.
fn remove_orphaned_record(state: &AppState) -> Res<()> {
    match std::fs::symlink_metadata(state.vault_path()) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(_) => return Err(Failure::new("io")),
    }
    let _sent = guard(&state.sent_ops);
    let _pq2 = guard(&state.pq2_ops);
    for path in [state.sent_path(), state.pq2_path()] {
        if let Err(error) = std::fs::remove_file(path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(Failure::new("io"));
            }
        }
    }
    Ok(())
}

/// Called under vault_ops after locking; a vault that cannot be removed must leave the record intact.
fn remove_wallet_files(state: &AppState) -> Res<()> {
    let _sent = guard(&state.sent_ops);
    let _pq2 = guard(&state.pq2_ops);
    for path in [state.vault_path(), state.sent_path(), state.pq2_path()] {
        if let Err(error) = std::fs::remove_file(path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(Failure::new("io"));
            }
        }
    }
    Ok(())
}

// ---- the chain and the addresses ----

#[derive(Serialize)]
pub struct AccountView {
    kind: Kind,
    address: String,
    /// Whether the address may be handed out and spent from now (see chain.rs).
    shown: bool,
    /// The leaf its spends take now; None while that is unknown.
    path: Option<Path>,
    spendable: u64,
    pending: u64,
    incoming: u64,
    coins: usize,
    /// False when the lookup failed or may be missing payments on their way.
    complete: bool,
}

/// One output paid to a pq2 address, with its status (design section 8.3).
#[derive(Serialize)]
pub struct Pq2CoinView {
    txid: String,
    vout: u32,
    sats: u64,
    /// None while unconfirmed.
    height: Option<u32>,
    status: Pq2Status,
    /// Spent by a transaction waiting for a block.
    spending: bool,
}

#[derive(Serialize)]
pub struct Pq2AddressView {
    chain: u32,
    index: u32,
    address: String,
    /// All its coins fit in one payment through the ML-DSA-44 leaf (which must spend them together).
    mldsa44_fits: bool,
    spendable: u64,
    pending: u64,
    incoming: u64,
    coins: Vec<Pq2CoinView>,
    complete: bool,
}

/// pq2 as the overview shows it. There is none at all while the node does not report the lattice tripwire
/// rules; until it may be used, it says why not yet and shows no address.
#[derive(Serialize)]
pub struct Pq2View {
    /// Why no new pq2 address can be handed out now: "legacy" (a backup code's wallet), "waiting" (the
    /// tip is not yet H4T + 6), "unknown_state" (the lattice tripwire state is unknown), "scan_needed"
    /// (a restored wallet's addresses have not been scanned yet), "gap_limit" (20 handed out unused);
    /// None when one can.
    blocked: Option<&'static str>,
    /// pq2 may be used: the tip is at least H4T + 6 and the state is known.
    allowed: bool,
    /// pq2 coins may be spent: the tip is at least H4T + 6 (through the SLH-DSA leaf while the state is
    /// unknown, and without change then).
    spend_allowed: bool,
    /// H4T + 6.
    opens_at: u32,
    /// The ML-DSA-44 leaf may be chosen for a spend: the node reports ML-DSA-44 checks still on.
    mldsa44_allowed: bool,
    /// The node reports ML-DSA-44 checks in 0xe2 leaves off from the next block (None: unknown).
    mldsa_disabled: Option<bool>,
    addresses: Vec<Pq2AddressView>,
    spendable: u64,
    pending: u64,
    incoming: u64,
    complete: bool,
    /// No payment with change while the change chain is at the gap limit.
    change_blocked: bool,
    /// Every index below these was looked at by a recovery scan, on each chain.
    scanned: [u32; 2],
    /// Every index below these is issued (handed out, or reserved by a scan), on each chain.
    issued: [u32; 2],
}

#[derive(Serialize)]
pub struct Overview {
    chain: Option<Chain>,
    problem: Option<String>,
    accounts: Vec<AccountView>,
    pq2: Option<Pq2View>,
    fetched: u64,
}

fn path_now(kind: Kind, chain: &Chain) -> Option<Path> {
    match kind {
        Kind::Schnorr => Some(Path::Schnorr),
        Kind::Mldsa44 => Some(Path::Mldsa44),
        Kind::Mixed => chain.mixed_path(),
        Kind::Pq2 => Some(chain.pq2_path(None)),
    }
}

fn shown(kind: Kind, chain: &Chain) -> bool {
    match kind {
        Kind::Schnorr => true,
        Kind::Mldsa44 => chain.mldsa44_allowed,
        Kind::Mixed => chain.mixed_allowed && chain.mixed_path().is_some(),
        Kind::Pq2 => chain.pq2_allowed,
    }
}

async fn current_chain(sources: &Sources, flags: &mut Flags) -> Res<Chain> {
    Ok(flags.take(sources.state().await)?)
}

/// Whether the API lists anything paid to the address: an unspent output, one being spent, or one on its way.
fn anything_paid(coins: &Coins) -> bool {
    !coins.spendable.is_empty() || !coins.pending.is_empty() || !coins.incoming.is_empty()
}

/// Records the pq2 address as used when its coins show anything paid to it.
/// Records a use of the address when its coins show anything paid to it (`Book::record_use`: the range
/// extended and a scan required when another copy may now hand out more). The save's failure is returned.
fn note_used(state: &AppState, bound: &Bound, chain: u32, index: u32, address: &str, coins: &Coins) -> Res<()> {
    if anything_paid(coins) {
        state.edit_book_of(&bound.wallet, bound.generation, |b| b.record_use(chain, index, address))?;
    }
    Ok(())
}

/// Why no new pq2 address can be handed out on `chain_index` now, or None.
fn pq2_blocked(legacy: bool, chain: &Chain, book: Option<&Book>, chain_index: u32) -> Option<&'static str> {
    if legacy {
        return Some("legacy");
    }
    if chain.mldsa_disabled.is_none() && chain.lattice_tip.is_none() && chain.tip >= chain.lattice_height?.saturating_add(crate::chain::MARGIN) {
        return Some("unknown_state");
    }
    if !chain.pq2_allowed {
        return Some("waiting");
    }
    let Some(book) = book else { return Some("unknown_state") };
    if book.scan_needed {
        return Some("scan_needed");
    }
    if !book.chains[chain_index as usize].can_issue() {
        return Some("gap_limit");
    }
    None
}

/// The pq2 part of the overview, bound to the wallet open when the refresh began (`bound`, None for a
/// wallet without pq2): after every answer from the network it checks that wallet is still open in the
/// same session, and it reads and writes that wallet's book only. Err("locked") otherwise.
async fn pq2_overview(state: &AppState, bound: Option<&Bound>, chain: &Chain, sources: &Sources, flags: &mut Flags) -> Res<Option<Pq2View>> {
    let read_book = || bound.and_then(|b| state.edit_book_of(&b.wallet, b.generation, |x| x.clone()).ok());
    let legacy = bound.is_none();
    let Some(h4t) = chain.lattice_height else {
        // One node runs the M4 rules and the other does not: no pq2 yet, and the view says why.
        if !chain.source_not_upgraded {
            return Ok(None);
        }
        let book = read_book();
        return Ok(Some(Pq2View {
            blocked: Some(if legacy { "legacy" } else { "source_not_upgraded" }),
            allowed: false,
            spend_allowed: false,
            opens_at: crate::net::network().h4t.saturating_add(crate::chain::MARGIN),
            mldsa44_allowed: false,
            mldsa_disabled: None,
            addresses: Vec::new(),
            spendable: 0,
            pending: 0,
            incoming: 0,
            complete: false,
            change_blocked: true,
            scanned: book.as_ref().map_or([0, 0], |b| [b.chains[0].scanned, b.chains[1].scanned]),
            issued: book.as_ref().map_or([0, 0], |b| [b.chains[0].issued, b.chains[1].issued]),
        }));
    };
    let book = read_book();
    let mut view = Pq2View {
        blocked: pq2_blocked(legacy, chain, book.as_ref(), RECEIVE_CHAIN),
        allowed: chain.pq2_allowed && !legacy,
        spend_allowed: chain.pq2_spendable && !legacy,
        opens_at: h4t.saturating_add(crate::chain::MARGIN),
        mldsa44_allowed: chain.pq2_mldsa44_allowed(),
        mldsa_disabled: chain.mldsa_disabled,
        addresses: Vec::new(),
        spendable: 0,
        pending: 0,
        incoming: 0,
        complete: true,
        change_blocked: book.as_ref().is_none_or(|b| !b.chains[CHANGE_CHAIN as usize].can_issue()),
        scanned: book.as_ref().map_or([0, 0], |b| [b.chains[0].scanned, b.chains[1].scanned]),
        issued: book.as_ref().map_or([0, 0], |b| [b.chains[0].issued, b.chains[1].issued]),
    };
    let (Some(bound), Some(_)) = (bound, &book) else { return Ok(Some(view)) };
    // Reserved addresses first: one that received something since the last check is looked up below.
    if !check_reserved(state, bound, sources, flags).await? {
        view.complete = false;
    }
    let Some(book) = read_book() else { return Ok(Some(view)) };
    for (c, chain_book) in book.chains.iter().enumerate() {
        for index in chain_book.watched() {
            // Verified: only an address the wallet's own keys give at that index (a book changed on disk
            // gets no status).
            let Some(address) = chain_book.addresses.get(&index).cloned() else { continue };
            if state.pq2_template_of(&bound.wallet, bound.generation, c as u32, index).ok().is_none_or(|t| t.address != address) {
                view.complete = false;
                continue;
            }
            let answer = sources.coins(&address).await;
            // The two sources disagreeing on the address's coins: its view may be incomplete.
            let disagree = answer.flags.disagree;
            let found = flags.take(answer);
            state.answered(bound)?;
            remember(state, bound.generation, &address, &found);
            let Ok(coins) = found else {
                view.complete = false;
                continue;
            };
            if note_used(state, bound, c as u32, index, &address, &coins).is_err() {
                view.complete = false;
            }
            let sum = |c: &[Coin]| c.iter().map(|c| c.sats).sum::<u64>();
            let mut list: Vec<Pq2CoinView> = Vec::new();
            for (c, spending) in coins.spendable.iter().map(|c| (c, false)).chain(coins.pending.iter().map(|c| (c, true))) {
                // Confirmed: the API gives the height of the block it is in on the chain as it is now.
                let status = chain.pq2_status(Some(c.height)).unwrap_or(Pq2Status::Pending);
                list.push(Pq2CoinView { txid: c.txid.clone(), vout: c.vout, sats: c.sats, height: Some(c.height), status, spending });
            }
            for i in &coins.incoming {
                list.push(Pq2CoinView { txid: i.txid.clone(), vout: i.vout, sats: i.sats, height: None, status: Pq2Status::Pending, spending: false });
            }
            let incoming: u64 = coins.incoming.iter().map(|i| i.sats).sum();
            let complete = coins.incoming_complete && !coins.truncated && !disagree;
            view.complete &= complete;
            view.spendable += sum(&coins.spendable);
            view.pending += sum(&coins.pending);
            view.incoming += incoming;
            if !list.is_empty() {
                let template = state.pq2_template_of(&bound.wallet, bound.generation, c as u32, index).ok();
                let fits = template.as_ref().is_some_and(|t| mldsa44_fits(t, &coins.spendable, &Destination { address: t.address.clone(), script_pubkey: t.script_pubkey.clone(), dust: 330 }));
                view.addresses.push(Pq2AddressView {
                    chain: c as u32,
                    index,
                    mldsa44_fits: fits,
                    address,
                    spendable: sum(&coins.spendable),
                    pending: sum(&coins.pending),
                    incoming,
                    coins: list,
                    complete,
                });
            }
        }
    }
    // Nothing is spendable from pq2 while it may not be used (a reorganization below H4T + 6).
    if !view.spend_allowed {
        view.spendable = 0;
    }
    let book = read_book();
    view.blocked = pq2_blocked(legacy, chain, book.as_ref(), RECEIVE_CHAIN);
    view.change_blocked = !chain.pq2_allowed || book.as_ref().is_none_or(|b| !b.chains[CHANGE_CHAIN as usize].can_issue());
    Ok(Some(view))
}

#[tauri::command]
pub async fn overview(state: State<'_, AppState>) -> Res<Overview> {
    overview_of(&state).await
}

async fn overview_of(state: &AppState) -> Res<Overview> {
    let snapshot = state.snapshot()?;
    let (schnorr, mldsa44, mixed) = snapshot.templates.clone();
    let sources = state.sources.clone();
    let mut flags = Flags::default();
    let chain = current_chain(&sources, &mut flags).await;
    state.current(&snapshot)?;
    let chain = match chain {
        Ok(c) => c,
        Err(f) => return Ok(Overview { chain: None, problem: Some(f.code), accounts: vec![], pq2: None, fetched: now() }),
    };
    let mut accounts = Vec::new();
    for t in [schnorr, mldsa44, mixed] {
        // Coins are looked up for every address, shown or not: the seed alone makes it, and coins may be there.
        let answer = sources.coins(&t.address).await;
        let disagree = answer.flags.disagree;
        let found = flags.take(answer);
        state.current(&snapshot)?;
        remember(state, snapshot.generation, &t.address, &found);
        let sum = |c: &[Coin]| c.iter().map(|c| c.sats).sum::<u64>();
        let (spendable, pending, incoming, n, complete) = match &found {
            Ok(c) => (sum(&c.spendable), sum(&c.pending), c.incoming.iter().map(|i| i.sats).sum(), c.spendable.len(), c.incoming_complete && !c.truncated && !disagree),
            Err(_) => (0, 0, 0, 0, false),
        };
        let ready = shown(t.kind, &chain);
        accounts.push(AccountView {
            kind: t.kind,
            shown: ready,
            path: path_now(t.kind, &chain),
            // The interface gets an address only once it may be handed out.
            address: if ready { t.address } else { String::new() },
            spendable,
            pending,
            incoming,
            coins: n,
            complete,
        });
    }
    let pq2 = pq2_overview(state, snapshot.bound.as_ref(), &chain, &sources, &mut flags).await?;
    // Nothing of a wallet that was locked or replaced meanwhile is shown.
    state.current(&snapshot)?;
    Ok(Overview { chain: Some(chain), problem: None, accounts, pq2, fetched: now() })
}

#[derive(Debug, Serialize)]
pub struct NewAddress {
    address: String,
    index: u32,
}

/// Hands out the next pq2 receiving address: a fresh index, recorded as issued before it is shown, so that
/// it is never handed out again. Only while pq2 may be used, after a restored wallet's scan, and below the
/// gap limit.
#[tauri::command]
pub async fn pq2_new_address(state: State<'_, AppState>) -> Res<NewAddress> {
    new_pq2_address(&state).await
}

async fn new_pq2_address(state: &AppState) -> Res<NewAddress> {
    state.touch();
    // The wallet this command is for is the one open when it was called: still that one once the book is
    // free, or `locked`.
    let snapshot = state.snapshot()?;
    let _book_op = state.book_ops.lock().await;
    state.still_current(&snapshot)?;
    let legacy = snapshot.bound.is_none();
    let chain = current_chain(&state.sources, &mut Flags::default()).await;
    state.current(&snapshot)?;
    let chain = chain?;
    if chain.source_not_upgraded {
        return Err(Failure::new("pq2_source_not_upgraded"));
    }
    if chain.lattice_height.is_none() {
        return Err(Failure::new("address_not_ready"));
    }
    let book = match &snapshot.bound {
        None => None,
        Some(b) => Some(state.edit_book_of(&b.wallet, b.generation, |x| x.clone())?),
    };
    if let Some(reason) = pq2_blocked(legacy, &chain, book.as_ref(), RECEIVE_CHAIN) {
        return Err(Failure::new(&format!("pq2_{reason}")));
    }
    let index = book.as_ref().and_then(|b| b.chains[RECEIVE_CHAIN as usize].next()).ok_or_else(|| Failure::new("pq2_gap_limit"))?;
    let bound = snapshot.bound.as_ref().ok_or_else(|| Failure::new("pq2_unavailable"))?;
    let template = state.pq2_template_of(&bound.wallet, bound.generation, RECEIVE_CHAIN, index)?;
    let issued = state.edit_book_of(&bound.wallet, bound.generation, |b| !b.scan_needed && b.chains[RECEIVE_CHAIN as usize].issue(index, &template.address))?;
    if !issued {
        return Err(Failure::new("pq2_gap_limit"));
    }
    Ok(NewAddress { address: template.address, index })
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    /// Addresses with something paid to them, found on both chains.
    found: usize,
    scanned: [u32; 2],
    issued: [u32; 2],
}

/// The recovery scan of both pq2 chains, 20 addresses at a time: an index is used when the site reports
/// history for its address, or it holds coins now (confirmed or on their way), or the book says so. Each
/// chain is scanned until 20 indices in a row are not used (a wider scan: from index 0 again, and at least
/// 100 past where the last scan ended). Every index up to the highest used one plus 20 is then recorded as
/// issued. When the site cannot answer about history, the scan does not complete.
#[tauri::command]
pub async fn pq2_scan(state: State<'_, AppState>, wider: bool) -> Res<ScanResult> {
    scan_pq2(&state, wider).await
}

async fn scan_pq2(state: &AppState, wider: bool) -> Res<ScanResult> {
    state.touch();
    // Every result of this scan is bound to the wallet and the session it was called in: once the book is
    // free, after each answer from the network, and before each write to the book, both are checked again.
    let snapshot = state.snapshot()?;
    let Bound { wallet, generation } = snapshot.bound.clone().ok_or_else(|| Failure::new("pq2_unavailable"))?;
    let _book_op = state.book_ops.lock().await;
    state.still_current(&snapshot)?;
    // A scan needs to be finished before addresses are handed out again: set before the first use it finds
    // is saved, cleared only after both chains and their reserved addresses are.
    let book = state.edit_book_of(&wallet, generation, |b| {
        b.require_scan();
        b.clone()
    })?;
    let revision = book.scan_revision;
    let bound = Bound { wallet: wallet.clone(), generation };
    let answered = |state: &AppState| state.answered(&bound);
    let mut found = 0;
    let mut flags = Flags::default();
    let batch = crate::api::MAX_HISTORY_ADDRESSES as u32;
    for c in [RECEIVE_CHAIN, CHANGE_CHAIN] {
        let minimum = if wider { book.chains[c as usize].scanned.saturating_add(WIDER_SCAN) } else { GAP_LIMIT };
        let mut at = 0;
        // The addresses of indices that are not used, with the tip their history was checked to: those that
        // end up reserved are kept in the book.
        let mut unused: HashMap<u32, (String, u32)> = HashMap::new();
        loop {
            let done = state.edit_book_of(&wallet, generation, |b| b.chains[c as usize].scan_done(0, at, minimum))?;
            if done || at >= crate::keys::MAX_PQ2_INDEX - batch {
                break;
            }
            let mut templates = Vec::new();
            for index in at..at + batch {
                templates.push(state.pq2_template_of(&wallet, generation, c, index)?);
            }
            let addresses: Vec<String> = templates.iter().map(|t| t.address.clone()).collect();
            let history = flags.take(state.sources.history(&addresses, 0).await);
            answered(state)?;
            let history = history.map_err(|_| Failure::new("history_unavailable"))?;
            for (i, template) in templates.iter().enumerate() {
                let index = at + i as u32;
                let coins = flags.take(state.sources.coins(&template.address).await);
                answered(state)?;
                let used = history.used[i] || anything_paid(&coins?);
                if used {
                    if state.edit_book_of(&wallet, generation, |b| b.chains[c as usize].mark_used(index, &template.address))? {
                        found += 1;
                    }
                } else {
                    unused.insert(index, (template.address.clone(), history.tip_height));
                }
            }
            at += batch;
        }
        state.edit_book_of(&wallet, generation, |b| {
            let chain = &mut b.chains[c as usize];
            chain.scanned_to(at);
            let issued = chain.issued;
            for (i, (a, tip)) in unused {
                if i < issued {
                    chain.addresses.entry(i).or_insert(a);
                    // This scan asked about the address's whole history, up to that tip.
                    chain.checked.insert(i, tip);
                }
            }
        })?;
    }
    let book = state.edit_book_of(&wallet, generation, |b| {
        // Only when nothing required a scan again while this one ran.
        if b.scan_revision == revision {
            b.scan_needed = false;
        }
        b.clone()
    })?;
    Ok(ScanResult {
        found,
        scanned: [book.chains[0].scanned, book.chains[1].scanned],
        issued: [book.chains[0].issued, book.chains[1].issued],
    })
}

/// Blocks below the last checked tip that a check asks about again: a reorganization of up to this many
/// blocks may have replaced them.
const HISTORY_OVERLAP: u32 = 6;

/// Address history from `from` on. When the answer's tip is below `from` (a reorganization lowered it),
/// asks once more from six blocks below that tip and uses that answer; one still below its `from` is no
/// answer.
async fn history_since(sources: &Sources, addresses: &[String], from: u32, flags: &mut Flags) -> Option<crate::api::History> {
    let first = flags.take(sources.history(addresses, from).await).ok()?;
    if first.tip_height >= from {
        return Some(first);
    }
    let again = first.tip_height.saturating_sub(HISTORY_OVERLAP);
    let second = flags.take(sources.history(addresses, again).await).ok()?;
    (second.tip_height >= again).then_some(second)
}

/// Asks the site whether any reserved address received something in the blocks since its own last check
/// (the height in `checked`, less six blocks for a reorganization; from block 0 when it has none); one that
/// did becomes used, and its coins are looked up like the others'. Only the addresses asked about move
/// their watermark, each to the tip of the answer that covered it. Skipped (false) while another operation
/// on the address book runs, a scan among them. False also when the site could not answer: the addresses
/// it answered for are saved, the others stay where they were.
async fn check_reserved(state: &AppState, bound: &Bound, sources: &Sources, flags: &mut Flags) -> Res<bool> {
    let Ok(_book_op) = state.book_ops.try_lock() else { return Ok(false) };
    let Ok(book) = state.edit_book_of(&bound.wallet, bound.generation, |b| b.clone()) else { return Ok(true) };
    // The reserved addresses, grouped by the block their check starts from.
    let mut by_start: BTreeMap<u32, Vec<(u32, u32, String)>> = BTreeMap::new();
    for (c, chain) in book.chains.iter().enumerate() {
        for i in chain.reserved() {
            let Some(a) = chain.addresses.get(&i) else { continue };
            let from = chain.checked.get(&i).map_or(0, |h| h.saturating_sub(HISTORY_OVERLAP));
            by_start.entry(from).or_default().push((c as u32, i, a.clone()));
        }
    }
    let mut answered_all = true;
    let mut checked: Vec<(u32, u32, u32)> = Vec::new();
    let mut found = Vec::new();
    'ask: for (from, list) in &by_start {
        for part in list.chunks(crate::api::MAX_HISTORY_ADDRESSES) {
            let addresses: Vec<String> = part.iter().map(|(_, _, a)| a.clone()).collect();
            let history = history_since(sources, &addresses, *from, flags).await;
            state.answered(bound)?;
            let Some(history) = history else {
                answered_all = false;
                break 'ask;
            };
            for ((c, i, a), used) in part.iter().zip(history.used) {
                checked.push((*c, *i, history.tip_height));
                // Only an address the wallet's own keys give at that index.
                if used && state.pq2_template_of(&bound.wallet, bound.generation, *c, *i).is_ok_and(|t| &t.address == a) {
                    found.push((*c, *i, a.clone()));
                }
            }
        }
    }
    if checked.is_empty() {
        return Ok(answered_all);
    }
    // The uses found and the watermarks of the addresses asked about go into the book in one save: when
    // that fails, none of it is kept, and the next check asks about the same blocks again.
    let saved = state
        .edit_book_of(&bound.wallet, bound.generation, |b| {
            for (c, i, tip) in &checked {
                b.chains[*c as usize].checked.insert(*i, *tip);
            }
            for (c, i, a) in &found {
                b.record_use(*c, *i, a);
            }
        })
        .is_ok();
    Ok(answered_all && saved)
}

/// What the review shows of a payment from a pq2 address.
#[derive(Debug, Serialize)]
pub struct Pq2PlanView {
    address: String,
    /// The ML-DSA-44 leaf may be chosen: the node reports ML-DSA-44 checks in 0xe2 leaves still on.
    mldsa44_allowed: bool,
    /// Why not, when not: "disabled" (the node reports them off from the next block), "unknown", or
    /// "too_many_coins" (all the address's coins, which that leaf must spend together, do not fit).
    mldsa44_reason: Option<&'static str>,
    /// Bytes of witness per input through the leaf taken (design section 8.1: 7,972 or 3,795).
    witness_bytes: usize,
    /// The payment spends several coins of the address.
    several_coins: bool,
    /// Coins of the address this payment leaves on it, and their total: send again to move them.
    staying_coins: usize,
    staying_sats: u64,
    /// The change address, on the change chain.
    change_address: Option<String>,
    /// The change chain is at the gap limit: the payment can only go without change.
    change_blocked: bool,
    /// This plan replaces a payment through the ML-DSA-44 leaf that can no longer go through.
    rebuilt_from: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SendPlan {
    id: String,
    from: Kind,
    signature: Path,
    to: String,
    send: u64,
    fee: u64,
    change: u64,
    inputs: usize,
    vsize: usize,
    size: usize,
    fee_rate: u64,
    left: usize,
    /// The API listed only part of the address's coins: "all" may leave some behind.
    truncated: bool,
    /// The destination is one of this wallet's own addresses.
    to_self: bool,
    /// Earlier payments without a clear answer that this one spends a coin of (see `plan_send`).
    replaces: usize,
    /// An earlier payment the wallet doubted has gone out, or may have: none of its coins are usable, or
    /// a payment on its way spends one of them.
    went_out: bool,
    /// A payment without a clear answer from another address, which this one cannot replace.
    unclear_elsewhere: bool,
    /// Coins of the wallet's are being spent by a payment it has no record of here.
    unrecorded: bool,
    one_source: bool,
    sources_disagree: bool,
    /// A payment from a pq2 address.
    pq2: Option<Pq2PlanView>,
}

fn account_for(template: Template, chain: &Chain, path: Option<Path>) -> Res<Account> {
    if !shown(template.kind, chain) {
        return Err(Failure::new("address_not_ready"));
    }
    let path = path.or_else(|| path_now(template.kind, chain)).ok_or_else(|| Failure::new("address_not_ready"))?;
    Account::new(template, path).ok_or_else(|| Failure::new("address_not_ready"))
}

/// Plans a send; nothing is signed until `confirm_send` with the plan's id. From a pq2 address, `address`
/// names it and `path` may ask for the ML-DSA-44 leaf; the SLH-DSA leaf is the default.
#[tauri::command]
pub async fn plan_send(state: State<'_, AppState>, from: Kind, to: String, amount: String, address: Option<String>, path: Option<Path>) -> Res<SendPlan> {
    if from == Kind::Pq2 {
        let address = address.ok_or_else(|| Failure::new("address_not_ready"))?;
        return plan_pq2_payment(&state, address, to, amount, path, None).await;
    }
    plan_payment(&state, from, to, amount).await
}

/// The name a payment's account goes by in the record: its kind, or "pq2:" and its address.
fn account_name(kind: Kind, pq2_address: Option<&str>) -> String {
    match pq2_address {
        Some(a) if kind == Kind::Pq2 => format!("pq2:{a}"),
        _ => kind_name(kind),
    }
}

/// The account a recorded payment was made from, as `account_name` names it.
fn account_of(s: &Sent) -> String {
    if s.from == "pq2" {
        format!("pq2:{}", s.address)
    } else {
        s.from.clone()
    }
}

fn parse_amount(amount: &str) -> Res<Amount> {
    if amount.trim() == "all" {
        Ok(Amount::All)
    } else {
        Ok(Amount::Sats(parse_coins(amount).ok_or_else(|| Failure::new("invalid_amount"))?))
    }
}

/// The book's pq2 addresses this wallet may pay itself at: only those it handed out or saw used.
/// Every pq2 address the wallet knows, from its book: handed out (receiving or change), seen used, or kept by
/// a recovery scan. A payment to one of them creates the wallet's own pq2 output.
fn own_pq2(state: &AppState) -> HashSet<String> {
    state.book().map(|b| b.chains.iter().flat_map(|c| c.addresses.values().cloned()).collect()).unwrap_or_default()
}

async fn plan_payment(state: &AppState, from: Kind, to: String, amount: String) -> Res<SendPlan> {
    state.touch();
    let snapshot = state.snapshot()?;
    let template = guard(&state.session).as_ref().ok_or_else(|| Failure::new("locked"))?.template(from)?;
    let own = state.own_templates()?;
    let destination = parse_destination(&to)?;
    let amount = parse_amount(&amount)?;
    let sources = state.sources.clone();
    let mut flags = Flags::default();
    // After every answer from the network, its session first: a command of a locked one uses nothing of it.
    let chain = current_chain(&sources, &mut flags).await;
    state.current(&snapshot)?;
    let chain = chain?;
    // The wallet does not pay its own address before it hands that out either.
    if own.iter().any(|t| t.address == destination.address && !shown(t.kind, &chain)) {
        return Err(Failure::new("destination_not_ready"));
    }
    // Paying one of its own pq2 addresses (handed out, change, or kept by a scan) creates a pq2 output: only once
    // pq2 is open (H4T + 6 and the state known), whatever account pays, and with lock time H4T.
    let creates_pq2 = own_pq2(state).contains(&destination.address);
    if creates_pq2 && !chain.pq2_allowed {
        return Err(Failure::new("destination_not_ready"));
    }
    let account = account_for(template, &chain, None)?;
    let view_from_address = account.template.address.clone();
    let coins = flags.take(sources.coins(&account.template.address).await);
    state.current(&snapshot)?;
    remember(state, snapshot.generation, &account.template.address, &coins);
    let coins = coins?;
    // The wallet's own payments that are, or may be, on their way, looked up again first.
    let at = now();
    let sent = refresh_sent(state, snapshot.generation, |s| {
        matches!(s.status.as_str(), "mempool" | "unknown") || (s.status == "confirmed" && !s.proven()) || (refused(s) && recent(s, at))
    }, &mut flags).await;
    state.current(&snapshot)?;
    // One payment at a time: while one is being handed to the API, its outcome is not known yet.
    if sent.iter().any(|s| s.status == "submitting") {
        return Err(Failure::new("sending"));
    }
    let pending = pending_everywhere(&sources, &coins, &own, &account.template.address, Some(&state.seen_coins), &mut flags).await;
    state.current(&snapshot)?;
    let pending = pending?;
    let earlier = earlier_payments(&sent, &kind_name(from), &coins.spendable, &pending);
    let went_out = earlier.spent || surfaced(&sent);
    let plan = wallet::plan_spend(&account, &earlier.usable, &earlier.required, &destination, amount, chain.lock_time_for(creates_pq2))?;
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| Failure::new("internal"))?;
    let view = SendPlan {
        id: hex::encode(id),
        from,
        signature: account.path,
        to: destination.address.clone(),
        send: plan.send,
        fee: plan.fee,
        change: plan.change,
        inputs: plan.coins.len(),
        vsize: plan.sizes.vsize,
        size: plan.sizes.size,
        fee_rate: FEE_RATE,
        left: plan.left,
        truncated: coins.truncated,
        to_self: own.iter().any(|t| t.address == destination.address),
        replaces: earlier.replaces.len(),
        went_out,
        unclear_elsewhere: earlier.elsewhere,
        unrecorded: earlier.unrecorded,
        one_source: flags.one_source,
        sources_disagree: flags.disagree,
        pq2: None,
    };
    let caution = went_out || earlier.elsewhere || earlier.unrecorded;
    // The plan is kept only for the wallet and session it was made in.
    state.current(&snapshot)?;
    keep_plan(state, &snapshot, PendingSend {
        id: view.id.clone(), created: Instant::now(), kind: from, path: account.path, destination, plan, caution, sources: flags,
        creates_pq2, pq2: None, plan_address: view_from_address, rebuild: None,
    })?;
    Ok(view)
}

/// Plans a payment from one pq2 address: all of its coins together, through the SLH-DSA leaf unless the
/// user asks for the ML-DSA-44 leaf and the node reports it still works, the change to a fresh address on
/// the change chain (or no change, at its gap limit), nLockTime H4T. `rebuilt_from`: the payment through
/// the ML-DSA-44 leaf this one replaces.
async fn plan_pq2_payment(state: &AppState, address: String, to: String, amount: String, wanted: Option<Path>, rebuild: Option<Rebuild>) -> Res<SendPlan> {
    let snapshot = state.snapshot()?;
    plan_pq2_payment_in(state, snapshot, address, to, amount, wanted, rebuild).await
}

/// `plan_pq2_payment` for the wallet and session of `snapshot` (a confirmation's own, for its fallback):
/// every book read and every derivation is of that wallet, checked after each wait on the network.
async fn plan_pq2_payment_in(state: &AppState, snapshot: Snapshot, address: String, to: String, amount: String, wanted: Option<Path>, rebuild: Option<Rebuild>) -> Res<SendPlan> {
    state.touch();
    let plan_bound = snapshot.bound.clone();
    let book = state.edit_book_for(&snapshot, |b| b.clone())?;
    let (chain_index, index) = book.find(&address).ok_or_else(|| Failure::new("address_not_ready"))?;
    let destination = parse_destination(&to)?;
    let amount = parse_amount(&amount)?;
    let sources = state.sources.clone();
    let mut flags = Flags::default();
    let chain = current_chain(&sources, &mut flags).await;
    state.current(&snapshot)?;
    let chain = chain?;
    // Spending waits for H4T + 6; with the lattice state unknown it goes through the SLH-DSA leaf, and
    // without change (no new pq2 output then).
    if !chain.pq2_spendable {
        return Err(Failure::new("address_not_ready"));
    }
    let own = state.own_templates()?;
    if own.iter().any(|t| t.address == destination.address && !shown(t.kind, &chain)) {
        return Err(Failure::new("destination_not_ready"));
    }
    let bound = snapshot.bound.clone().ok_or_else(|| Failure::new("pq2_unavailable"))?;
    let template = state.pq2_template_of(&bound.wallet, bound.generation, chain_index, index)?;
    let coins = flags.take(sources.coins(&template.address).await);
    state.current(&snapshot)?;
    remember(state, snapshot.generation, &template.address, &coins);
    let coins = coins?;
    if let Some(bound) = &plan_bound {
        note_used(state, bound, chain_index, index, &address, &coins)?;
    }
    let at = now();
    let sent = refresh_sent(state, snapshot.generation, |s| {
        matches!(s.status.as_str(), "mempool" | "unknown") || (s.status == "confirmed" && !s.proven()) || (refused(s) && recent(s, at))
    }, &mut flags).await;
    state.current(&snapshot)?;
    if sent.iter().any(|s| s.status == "submitting") {
        return Err(Failure::new("sending"));
    }
    // A rebuild is decided again as the refresh found its versions: none once one of them is in the
    // mempool or confirmed.
    let anchor: Option<String> = match &rebuild {
        Some(r) if r.bound() => {
            if lineage_went_out(&r.versions, &sent) {
                return Err(Failure::new("rebuild_original_went_out"));
            }
            if !r.anchored(&r.versions) {
                return Err(Failure::new("rebuild_not_possible"));
            }
            Some(r.anchor().ok_or_else(|| Failure::new("rebuild_anchor_unavailable"))?.to_string())
        }
        _ => None,
    };
    let pending = pending_everywhere(&sources, &coins, &own, &template.address, Some(&state.seen_coins), &mut flags).await;
    state.current(&snapshot)?;
    let pending = pending?;
    let name = account_name(Kind::Pq2, Some(&address));
    let earlier = earlier_payments(&sent, &name, &coins.spendable, &pending);
    let went_out = earlier.spent || surfaced(&sent);
    // No new address, change included, while a recovery scan is incomplete: only payments without change.
    let book_now = state.edit_book_for(&snapshot, |b| b.clone())?;
    let change_index = book_now.chains[CHANGE_CHAIN as usize].next().filter(|_| chain.pq2_allowed && !book_now.scan_needed);
    let change = match change_index {
        Some(i) => Some(state.pq2_template_of(&bound.wallet, bound.generation, CHANGE_CHAIN, i)?),
        None => None,
    };
    // Through the ML-DSA-44 leaf every usable coin of the address goes at once: the spend shows the key all
    // of them are locked to. When they do not fit in one transaction, that leaf is not offered here.
    let mldsa44_fits = mldsa44_fits(&template, &earlier.usable, &destination);
    let path = if mldsa44_fits { chain.pq2_path(wanted) } else { Path::Slhdsa128s };
    let account = Account::new(template, path).ok_or_else(|| Failure::new("address_not_ready"))?;
    // Through the SLH-DSA leaf, the fewest coins that pay (largest first), or as many as fit for "all";
    // the coins other payments still waiting require go first, and for a rebuild its anchor, which must be
    // spendable now. The versions of the rebuild's own payment need nothing more: they all spend the anchor.
    // The payment's other unclear payments are covered starting from the anchor: one already spending it
    // needs nothing more.
    let anchor_coin = match &anchor {
        Some(a) => Some(earlier.usable.iter().find(|c| &c.outpoint() == a).ok_or_else(|| Failure::new("rebuild_anchor_unavailable"))?.clone()),
        None => None,
    };
    let lineage: HashSet<&str> = rebuild.iter().filter(|r| r.bound()).flat_map(|r| r.versions.iter().map(|v| v.txid.as_str())).collect();
    let others_required = if lineage.is_empty() {
        earlier.required.clone()
    } else {
        let others: Vec<Sent> = sent.iter().filter(|s| !lineage.contains(s.txid.as_str())).cloned().collect();
        let forced: Vec<Coin> = anchor_coin.iter().cloned().collect();
        earlier_payments(&others, &name, &coins.spendable, &pending).cover(&forced)
    };
    let mut required = if path == Path::Mldsa44 { earlier.usable.clone() } else { others_required };
    if let Some(coin) = anchor_coin {
        if !required.contains(&coin) {
            required.insert(0, coin);
        }
    }
    // nLockTime H4T when the payment creates a pq2 output: its change, or one of the wallet's own pq2
    // addresses as destination. The lock time does not change the sizes, so it is set once planned.
    let to_own_pq2 = own_pq2(state).contains(&destination.address);
    let mut plan = wallet::plan_spend_to(&account, &earlier.usable, &required, &destination, amount, chain.lock_time(), change.as_ref().map(|t| &t.script_pubkey))
        .map_err(|e| if e == PlanError::NeedsChange { Failure::new("pq2_change_limit") } else { e.into() })?;
    if anchor.as_ref().is_some_and(|a| !plan.coins.iter().any(|c| &c.outpoint() == a)) {
        return Err(Failure::new("rebuild_anchor_unavailable"));
    }
    let change_used = plan.change > 0;
    let creates_pq2 = change_used || to_own_pq2;
    let planned: HashSet<String> = plan.coins.iter().map(Coin::outpoint).collect();
    let staying: Vec<&Coin> = earlier.usable.iter().filter(|c| !planned.contains(&c.outpoint())).collect();
    if creates_pq2 && !chain.pq2_allowed {
        return Err(Failure::new("destination_not_ready"));
    }
    plan.lock_time = chain.lock_time_for(creates_pq2);
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| Failure::new("internal"))?;
    let view = SendPlan {
        id: hex::encode(id),
        from: Kind::Pq2,
        signature: account.path,
        to: destination.address.clone(),
        send: plan.send,
        fee: plan.fee,
        change: plan.change,
        inputs: plan.coins.len(),
        vsize: plan.sizes.vsize,
        size: plan.sizes.size,
        fee_rate: FEE_RATE,
        left: plan.left,
        truncated: coins.truncated,
        to_self: own.iter().any(|t| t.address == destination.address),
        replaces: earlier.replaces.len(),
        went_out,
        unclear_elsewhere: earlier.elsewhere,
        unrecorded: earlier.unrecorded,
        one_source: flags.one_source,
        sources_disagree: flags.disagree,
        pq2: Some(Pq2PlanView {
            address: address.clone(),
            mldsa44_allowed: chain.pq2_mldsa44_allowed() && mldsa44_fits,
            mldsa44_reason: match chain.mldsa_disabled {
                Some(false) if mldsa44_fits => None,
                Some(false) => Some("too_many_coins"),
                Some(true) => Some("disabled"),
                None => Some("unknown"),
            },
            staying_coins: staying.len(),
            staying_sats: staying.iter().map(|c| c.sats).sum(),
            witness_bytes: witness_bytes(path),
            several_coins: plan.coins.len() > 1,
            change_address: change.filter(|_| change_used).map(|t| t.address),
            change_blocked: change_index.is_none(),
            rebuilt_from: rebuild.as_ref().map(|r| r.root.txid.clone()),
        }),
    };
    let caution = went_out || earlier.elsewhere || earlier.unrecorded;
    // The plan is kept only for the wallet and session it was made in.
    state.current(&snapshot)?;
    keep_plan(state, &snapshot, PendingSend {
        id: view.id.clone(), created: Instant::now(), kind: Kind::Pq2, path: account.path, destination, plan, caution, sources: flags,
        creates_pq2,
        pq2: Some(Pq2Pending { chain: chain_index, index, change: change_index.filter(|_| change_used) }),
        plan_address: address,
        rebuild,
    })?;
    Ok(view)
}

/// Keeps a plan for review: the check that the wallet and session are still those of `snapshot` and the
/// replacement of the kept plan are one section under the commit lock, which locking also takes, so a
/// plan begun before a lock never replaces one made after it. Err("locked") then, with nothing kept.
fn keep_plan(state: &AppState, snapshot: &Snapshot, plan: PendingSend) -> Res<()> {
    #[cfg(test)]
    {
        let hook = guard(&state.before_plan_kept).take();
        if let Some(mut hook) = hook {
            hook(state);
        }
    }
    let _commit = guard(&state.commit_ops);
    state.still_current(snapshot)?;
    *guard(&state.pending) = Some(plan);
    Ok(())
}

/// Whether every usable coin of a pq2 address fits in one transaction through the ML-DSA-44 leaf, with a
/// destination and a change output.
fn mldsa44_fits(template: &Template, usable: &[Coin], destination: &Destination) -> bool {
    let Some(account) = Account::new(template.clone(), Path::Mldsa44) else { return false };
    let outputs = [(0, destination.script_pubkey.clone()), (0, template.script_pubkey.clone())];
    usable.is_empty() || wallet::measure(&account, usable, &outputs, 0).size <= wallet::MAX_TX_BYTES
}

/// The original of a rebuild has gone out after all, or is on its way: confirmed, in the mempool, or
/// replaced by a proven payment.
fn original_went_out(s: &Sent) -> bool {
    matches!(s.status.as_str(), "confirmed" | "mempool" | "replaced")
}

/// The serialized witness of one input through a leaf: count, then each element with its length.
fn witness_bytes(path: Path) -> usize {
    let element = |n: usize| if n < 0xfd { 1 + n } else { 3 + n };
    let (chunks, leaf): (&[usize], usize) = match path {
        Path::Schnorr => (&[64], 34),
        Path::Mldsa44 => (&MLDSA44_SIGNATURE_CHUNKS, 1322),
        Path::Slhdsa128s => (&SLHDSA128S_SIGNATURE_CHUNKS, 34),
    };
    1 + chunks.iter().map(|&n| element(n)).sum::<usize>() + element(leaf) + element(33)
}

/// A rebuild through the SLH-DSA leaf of a recorded pq2 payment through the ML-DSA-44 leaf that can no
/// longer go through: the node reports ML-DSA-44 checks in 0xe2 leaves off (or that is unknown), and the
/// payment was refused or has left the mempool. The same coins (all of the address's), the same
/// destination and amount (everything, when the higher fee no longer leaves the amount), a new fee and a
/// new signature; it goes through the review and the system dialog like any payment, and once it is
/// proven the old one is marked replaced.
#[tauri::command]
pub async fn plan_rebuild(state: State<'_, AppState>, txid: String) -> Res<SendPlan> {
    rebuild_plan(&state, &txid).await
}

async fn rebuild_plan(state: &AppState, txid: &str) -> Res<SendPlan> {
    let snapshot = state.snapshot()?;
    rebuild_plan_in(state, &snapshot, txid).await
}

/// `rebuild_plan` for the wallet and session of `snapshot`, taken before the first wait (or the
/// confirmation's own, for the rebuild that follows a refused broadcast): the book read and both planning
/// attempts are of that session, and a changed one ends `locked` with nothing saved.
async fn rebuild_plan_in(state: &AppState, snapshot: &Snapshot, txid: &str) -> Res<SendPlan> {
    let sent: Vec<Sent> = store::load(&state.sent_path());
    let old = sent.iter().find(|s| s.txid == txid).cloned().ok_or_else(|| Failure::new("no_plan"))?;
    let chain = current_chain(&state.sources, &mut Flags::default()).await;
    state.current(snapshot)?;
    if !needs_rebuild(&old, &chain?) {
        return Err(Failure::new("no_rebuild"));
    }
    let amount = format_coins(old.send);
    let rebuild = Rebuild::of(&state.edit_book_for(snapshot, |b| b.clone())?, &old);
    match plan_pq2_payment_in(state, snapshot.clone(), old.address.clone(), old.to.clone(), amount, Some(Path::Slhdsa128s), Some(rebuild.clone())).await {
        Err(f) if f.code == "insufficient" || f.code == "pq2_change_limit" || f.code == "too_large" => {
            plan_pq2_payment_in(state, snapshot.clone(), old.address.clone(), old.to.clone(), "all".into(), Some(Path::Slhdsa128s), Some(rebuild)).await
        }
        other => other,
    }
}

/// A recorded pq2 payment through the ML-DSA-44 leaf that cannot go through now: refused, or no longer
/// in the mempool, while the node reports ML-DSA-44 checks in 0xe2 leaves off or that state is unknown.
fn needs_rebuild(s: &Sent, chain: &Chain) -> bool {
    s.from == "pq2" && s.signature == "mldsa44" && matches!(s.status.as_str(), "unknown" | "rejected" | "failed") && !chain.pq2_mldsa44_allowed()
}

fn format_coins(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

#[derive(Debug, Serialize)]
pub struct SendResult {
    result: BroadcastResult,
    txid: String,
    sign_ms: f64,
    /// The payment went through the ML-DSA-44 leaf and the node now reports that leaf disabled (or the
    /// state unknown): rebuilt through the SLH-DSA leaf, this plan waits for review and confirmation. When
    /// the state flipped before broadcasting, the old transaction was dropped unsent (`txid` is empty).
    rebuilt: Option<SendPlan>,
    /// That rebuild was due but could not be planned now (its error code, e.g. "limit"): it can be started
    /// from the activity view. None when it was planned or not needed.
    rebuild_error: Option<String>,
}

/// Signs and broadcasts the plan the interface showed, if its coins are still unspent, the chain's rules
/// for it have not changed since, and the user confirms its figures in a system dialog. The transaction is
/// recorded before the API sees it, so that no answer of the API can make the wallet forget it.
#[tauri::command]
pub async fn confirm_send(app: AppHandle, state: State<'_, AppState>, id: String, locale: Option<String>) -> Res<SendResult> {
    send_plan(&state, &id, locale.as_deref(), |dialog| crate::confirm::ask(&app, dialog)).await
}

async fn send_plan<F: Future<Output = bool>>(
    state: &AppState,
    id: &str,
    locale: Option<&str>,
    ask: impl FnOnce(crate::confirm::Dialog) -> F,
) -> Res<SendResult> {
    state.touch();
    let snapshot = state.snapshot()?;
    let generation = snapshot.generation;
    let mut pending = guard(&state.pending).take().ok_or_else(|| Failure::new("no_plan"))?;
    if pending.id != id || pending.created.elapsed() > PLAN_LIFETIME {
        return Err(Failure::new("no_plan"));
    }
    let (account, coins, spending) = match recheck_payment(state, &snapshot, &mut pending).await {
        Err(f) if f.code == "mldsa44_disabled" => return rebuild_unsent(state, &pending, &snapshot).await,
        other => other?,
    };
    let dialog = crate::confirm::payment(
        state.dialog_locale(locale),
        pending.plan.send,
        &pending.destination.address,
        pending.plan.fee,
        pending.plan.change,
        pending.caution,
        pending.sources,
    );
    if !ask(dialog).await {
        return Err(Failure::new("cancelled"));
    }
    if state.generation() != generation {
        return Err(Failure::new("locked"));
    }
    if pending.created.elapsed() > PLAN_LIFETIME {
        return Err(Failure::new("no_plan"));
    }
    // From here until the payment is recorded, the address book is this payment's: no scan, no address
    // handed out, no history check writes to it (each holds book_ops), so the last look at it below stands.
    let book_op = state.book_ops.lock().await;
    state.still_current(&snapshot)?;
    // The last check, after the dialog and before signing: whether the payment creates one of the wallet's own
    // pq2 outputs (its destination, or its change, against the book as it is now). Such a payment must have
    // been planned as one, which passed the gate (pq2 open) at the re-check, and carries nLockTime H4T.
    // Otherwise nothing is signed or sent: a new plan is needed.
    let creates_now = pending.pq2.is_some_and(|p| p.change.is_some()) || own_pq2(state).contains(&pending.destination.address);
    if creates_now && (!pending.creates_pq2 || pending.plan.lock_time != crate::net::network().h4t) {
        return Err(Failure::new("chain_changed"));
    }
    let started = Instant::now();
    let signed = {
        let session = guard(&state.session);
        let session = session.as_ref().ok_or_else(|| Failure::new("locked"))?;
        if state.generation() != generation {
            return Err(Failure::new("locked"));
        }
        match pending.pq2 {
            Some(p) => wallet::sign_pq2_plan(&pending.plan, &account, &session.keys.pq2(p.chain, p.index)?)?,
            None => wallet::sign_plan(&pending.plan, &account, &session.keys)?,
        }
    };
    let sign_ms = started.elapsed().as_secs_f64() * 1000.0;
    // Through the ML-DSA-44 leaf, the node's state is read again just before broadcasting: once ML-DSA-44
    // checks in 0xe2 leaves are off (or that is unknown) the transaction cannot go through. It is dropped
    // unsent and rebuilt through the SLH-DSA leaf.
    if pending.pq2.is_some() && pending.path == Path::Mldsa44 {
        let still = current_chain(&state.sources, &mut Flags::default()).await.is_ok_and(|c| c.pq2_spendable && c.pq2_mldsa44_allowed());
        state.current(&snapshot)?;
        if !still {
            return rebuild_unsent(state, &pending, &snapshot).await;
        }
    }
    // A rebuild, right before it goes out: no version of its lineage has gone out meanwhile (each looked up
    // again now; no answer, no broadcast).
    let looked_up: Option<Vec<Version>> = match pending.rebuild.as_ref().filter(|r| r.bound()) {
        None => None,
        Some(r) => {
            let versions = state.edit_book_for(&snapshot, |b| b.clone())?.lineage_of(&r.root.txid).map_or_else(|| vec![r.root.clone()], |l| l.versions.clone());
            for v in &versions {
                let status = state.sources.tx_status(&v.txid).await.value;
                state.current(&snapshot)?;
                let status = status?;
                if matches!(status, TxStatus::Confirmed { .. } | TxStatus::Mempool) {
                    let _ = edit_sent_at(state, generation, |sent| {
                        if let Some(s) = sent.iter_mut().find(|s| s.txid == v.txid) {
                            let (st, n) = match status {
                                TxStatus::Confirmed { confirmations } => ("confirmed", confirmations.min(REQUIRED_BLOCKS - 1)),
                                _ => ("mempool", 0),
                            };
                            s.status = st.into();
                            s.confirmations = n;
                        }
                        mark_replaced(sent);
                    });
                    return Err(Failure::new("rebuild_original_went_out"));
                }
            }
            Some(versions)
        }
    };
    #[cfg(test)]
    {
        let hook = guard(&state.before_commit).take();
        if let Some(mut hook) = hook {
            hook(state);
        }
    }
    {
        // One section, with no wait on the network, in this order and with no rollback: the checks (the
        // wallet and session the confirmation began in; for a rebuild, its anchor among the coins it
        // spends; every precondition of the record); then the change index, checked and handed out in one
        // write of the pq2 book (if it cannot be, nothing else is written); then the record as submitting;
        // then the version joins its payment's lineage. A change index handed out for a payment whose
        // record then fails stays unused (a gap); a version missing from the lineage after a failed write
        // decides nothing, since the anchor does. Locking the wallet waits for this section.
        let _commit = guard(&state.commit_ops);
        state.still_current(&snapshot)?;
        let rebuild = pending.rebuild.as_ref().filter(|r| r.bound());
        if let Some(r) = rebuild {
            // Every version recorded now spends the anchor, and so does the one planned.
            let recorded = state.edit_book_for(&snapshot, |b| b.lineage_of(&r.root.txid).map(|l| l.versions.clone()))?;
            if !r.anchored(&r.versions) || recorded.is_some_and(|v| !r.anchored(&v)) {
                return Err(Failure::new("rebuild_not_possible"));
            }
            if !r.anchor().is_some_and(|a| pending.plan.coins.iter().any(|c| c.outpoint() == a)) {
                return Err(Failure::new("rebuild_anchor_unavailable"));
            }
        }
        let record = signed_record(&pending, &signed, sign_ms);
        {
            let recorded: Vec<Sent> = store::load_existing(&state.sent_path()).map_err(|_| Failure::new("io"))?;
            record_allowed(state, &recorded, &pending, &coins, &spending, generation, &record)?;
        }
        if let Some(Pq2Pending { change: Some(index), .. }) = pending.pq2 {
            let bound = snapshot.bound.as_ref().ok_or_else(|| Failure::new("pq2_unavailable"))?;
            let address = state.pq2_template_of(&bound.wallet, bound.generation, CHANGE_CHAIN, index)?.address;
            state.edit_book_for(&snapshot, |b| {
                if b.scan_needed {
                    return Err(Failure::new("pq2_scan_needed"));
                }
                if !b.chains[CHANGE_CHAIN as usize].issue(index, &address) {
                    return Err(Failure::new("coins_changed"));
                }
                Ok(())
            })??;
        }
        // Recorded before the API sees it. Not sent at all when that fails.
        record_payment(state, &pending, &coins, &spending, generation, record)?;
        if let (Some(r), Some(_)) = (rebuild, &looked_up) {
            let version = Version { txid: signed.txid.clone(), inputs: pending.plan.coins.iter().map(Coin::outpoint).collect() };
            let _ = state.edit_book_for(&snapshot, |b| b.add_version(&r.root, version));
        }
    }
    // Recorded: the address book is free again.
    drop(book_op);
    let result = state.sources.broadcast(&signed.hex, &signed.txid).await.value;
    // The answer is written for the session that sent it only: after a lock the record stays submitting, and is
    // looked up as unknown later.
    // What the API answered; a refusal is kept too, and looked up again later (activity), because only
    // the network can say whether the transaction went out.
    let (status, reason) = match &result {
        BroadcastResult::Sent { .. } => ("mempool", String::new()),
        BroadcastResult::Unknown => ("unknown", String::new()),
        BroadcastResult::Rejected { reason } => ("rejected", reason.clone()),
        BroadcastResult::Failed { error } => ("failed", error.clone()),
    };
    let wrote = edit_sent_at(state, generation, |sent| {
        if let Some(s) = sent.iter_mut().find(|s| s.txid == signed.txid) {
            s.status = status.into();
            s.reason = reason;
            s.doubted |= status != "mempool";
        }
        mark_replaced(sent);
    });
    if matches!(&wrote, Err(f) if f.code == "locked") {
        return Err(Failure::new("locked"));
    }
    // A refused payment through the ML-DSA-44 leaf: whether to rebuild it is decided from the node's state,
    // not from the words of the refusal.
    let mut rebuilt = None;
    let mut rebuild_error = None;
    if pending.pq2.is_some() && pending.path == Path::Mldsa44 && matches!(result, BroadcastResult::Rejected { .. } | BroadcastResult::Failed { .. }) {
        let recorded: Vec<Sent> = store::load(&state.sent_path());
        let chain = current_chain(&state.sources, &mut Flags::default()).await;
        state.current(&snapshot)?;
        let flipped = match &chain {
            Ok(c) => recorded.iter().any(|s| s.txid == signed.txid && needs_rebuild(s, c)),
            // No answer: unknown, and unknown means the SLH-DSA leaf.
            Err(_) => true,
        };
        if flipped {
            match rebuild_plan_in(state, &snapshot, &signed.txid).await {
                Ok(plan) => rebuilt = Some(plan),
                Err(f) => rebuild_error = Some(f.code),
            }
        }
    }
    // Whether the rebuild failed, succeeded or was not tried: a confirmation whose wallet was locked at any point
    // ends locked (its record, written while the session was current, stays; a lock leaves no plan kept).
    state.current(&snapshot)?;
    Ok(SendResult { result, txid: signed.txid, sign_ms, rebuilt, rebuild_error })
}

/// The payment through the ML-DSA-44 leaf was not recorded or sent; the same payment through the SLH-DSA
/// leaf, planned anew, waits for review.
async fn rebuild_unsent(state: &AppState, pending: &PendingSend, snapshot: &Snapshot) -> Res<SendResult> {
    // For the wallet and session the confirmation began in, and no other: checked before the address is
    // derived, through the planning (after each of its waits and before it keeps the plan) and before
    // returning.
    state.current(snapshot)?;
    let p = pending.pq2.ok_or_else(|| Failure::new("chain_changed"))?;
    let bound = snapshot.bound.as_ref().ok_or_else(|| Failure::new("pq2_unavailable"))?;
    let address = state.pq2_template_of(&bound.wallet, bound.generation, p.chain, p.index)?.address;
    let to = pending.destination.address.clone();
    let rebuild = Rebuild::unsent();
    let mut plan = plan_pq2_payment_in(state, snapshot.clone(), address.clone(), to.clone(), format_coins(pending.plan.send), Some(Path::Slhdsa128s), Some(rebuild.clone())).await;
    if matches!(&plan, Err(f) if f.code == "insufficient" || f.code == "pq2_change_limit" || f.code == "too_large") {
        plan = plan_pq2_payment_in(state, snapshot.clone(), address, to, "all".into(), Some(Path::Slhdsa128s), Some(rebuild)).await;
    }
    let plan = plan?;
    state.current(snapshot)?;
    Ok(SendResult { result: BroadcastResult::Unknown, txid: String::new(), sign_ms: 0.0, rebuilt: Some(plan), rebuild_error: None })
}

fn signed_record(pending: &PendingSend, signed: &wallet::Signed, sign_ms: f64) -> Sent {
    Sent {
        txid: signed.txid.clone(),
        created: now(),
        from: kind_name(pending.kind),
        address: match pending.pq2 {
            Some(_) => pending.plan_address.clone(),
            None => String::new(),
        },
        to: pending.destination.address.clone(),
        send: pending.plan.send,
        fee: pending.plan.fee,
        change: pending.plan.change,
        vsize: signed.sizes.vsize,
        size: signed.sizes.size,
        signature: kind_name_path(pending.path),
        inputs: pending.plan.coins.len(),
        sign_ms,
        status: "submitting".into(),
        confirmations: 0,
        proof_verified: false,
        reason: String::new(),
        outpoints: pending.plan.coins.iter().map(Coin::outpoint).collect(),
        doubted: false,
        lookup_mark: 0,
    }
}

/// A leaf's signature as the record names it.
fn kind_name_path(path: Path) -> String {
    serde_json::to_value(path).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

/// The confirmation's re-read of the chain and the coins, for the session of `snapshot`: after every answer
/// from the network that session is checked first, and a lock ends it `locked` with nothing written.
async fn recheck_payment(state: &AppState, snapshot: &Snapshot, pending: &mut PendingSend) -> Res<(Account, Coins, PendingCoins)> {
    let mut flags = pending.sources;
    let chain = current_chain(&state.sources, &mut flags).await;
    state.current(snapshot)?;
    let chain = chain?;
    // Whatever account pays: a payment that creates one of the wallet's own pq2 outputs (as planned, or to an
    // address the book has come to know since) goes only while pq2 is open, with lock time H4T (checked below).
    pending.creates_pq2 |= own_pq2(state).contains(&pending.destination.address);
    if pending.creates_pq2 && !chain.pq2_allowed {
        return Err(Failure::new("chain_changed"));
    }
    let account = match pending.pq2 {
        Some(p) => {
            if !chain.pq2_spendable {
                return Err(Failure::new("chain_changed"));
            }
            // Through the ML-DSA-44 leaf only while the node reports it on; otherwise rebuilt (send_plan).
            if pending.path == Path::Mldsa44 && !chain.pq2_mldsa44_allowed() {
                return Err(Failure::new("mldsa44_disabled"));
            }
            // The plan's own leaf is what is checked (pending.path): ML-DSA-44 above, and its all-coins rule
            // below; SLH-DSA, the default or a fallback, needs nothing more.
            // The change address is still the next one to hand out, and no scan is waiting.
            if let Some(index) = p.change {
                let book = state.book()?;
                if book.scan_needed {
                    return Err(Failure::new("pq2_scan_needed"));
                }
                if book.chains[CHANGE_CHAIN as usize].next() != Some(index) {
                    return Err(Failure::new("coins_changed"));
                }
            }
            Account::new(state.pq2_template(p.chain, p.index)?, pending.path).ok_or_else(|| Failure::new("address_not_ready"))?
        }
        None => {
            let template = guard(&state.session).as_ref().ok_or_else(|| Failure::new("locked"))?.template(pending.kind)?;
            let account = account_for(template, &chain, None)?;
            if account.path != pending.path {
                return Err(Failure::new("chain_changed"));
            }
            account
        }
    };
    if chain.lock_time_for(pending.creates_pq2) != pending.plan.lock_time {
        return Err(Failure::new("chain_changed"));
    }
    let coins = flags.take(state.sources.coins(&account.template.address).await);
    state.current(snapshot)?;
    remember(state, snapshot.generation, &account.template.address, &coins);
    let coins = coins?;
    let unspent: HashMap<String, u64> = coins.spendable.iter().map(|c| (c.outpoint(), c.sats)).collect();
    if !pending.plan.coins.iter().all(|c| unspent.get(&c.outpoint()) == Some(&c.sats)) {
        return Err(Failure::new("coins_changed"));
    }
    // Through the ML-DSA-44 leaf every coin of the address goes: one that came since the review means a new
    // review.
    if pending.pq2.is_some() && pending.path == Path::Mldsa44 && coins.spendable.len() != pending.plan.coins.len() && pending.plan.left == 0 {
        let planned: HashSet<String> = pending.plan.coins.iter().map(Coin::outpoint).collect();
        if coins.spendable.iter().any(|c| !planned.contains(&c.outpoint())) {
            return Err(Failure::new("coins_changed"));
        }
    }
    let at = now();
    let sent = refresh_sent(state, snapshot.generation, |s| {
        matches!(s.status.as_str(), "mempool" | "unknown") || (s.status == "confirmed" && !s.proven()) || (refused(s) && recent(s, at))
    }, &mut flags).await;
    state.current(snapshot)?;
    let own = state.own_templates()?;
    let spending = pending_everywhere(&state.sources, &coins, &own, &account.template.address, None, &mut flags).await;
    state.current(snapshot)?;
    let spending = spending?;
    let earlier = earlier_payments(&sent, &pending_account(pending), &coins.spendable, &spending);
    pending.sources = flags;
    pending.caution = earlier.spent || earlier.elsewhere || earlier.unrecorded || surfaced(&sent);
    Ok((account, coins, spending))
}

/// The account a pending payment spends from, as the record names it.
fn pending_account(pending: &PendingSend) -> String {
    match pending.pq2 {
        Some(_) => account_name(Kind::Pq2, Some(&pending.plan_address)),
        None => kind_name(pending.kind),
    }
}

/// Whether a payment may be recorded now, by the record as it is (`sent`): every precondition of
/// `record_payment`, with nothing written.
fn record_allowed(state: &AppState, sent: &[Sent], pending: &PendingSend, coins: &Coins, spending: &PendingCoins, generation: u64, record: &Sent) -> Res<()> {
    if state.generation() != generation {
        return Err(Failure::new("locked"));
    }
    let shared = |s: &Sent| s.outpoints.iter().any(|o| record.outpoints.contains(o));
    let same = |s: &Sent| s.txid == record.txid;
    if sent.iter().any(|s| s.status == "submitting") {
        return Err(Failure::new("sending"));
    }
    if sent.iter().any(|s| s.status == "mempool" && !same(s) && shared(s)) {
        return Err(Failure::new("coins_changed"));
    }
    // The wallet's other payments as they are now, after the dialog: one still being sent when the plan
    // was made may since need covering (this payment must spend one of its coins), or a warning the
    // plan was made without. Then the payment is reviewed again.
    let earlier = earlier_payments(sent, &pending_account(pending), &coins.spendable, spending);
    let covered = earlier.replaces.iter().all(|txid| sent.iter().any(|s| &s.txid == txid && shared(s)));
    if !covered || (!pending.caution && (earlier.spent || earlier.elsewhere || earlier.unrecorded || surfaced(sent))) {
        return Err(Failure::new("coins_changed"));
    }
    Ok(())
}

fn record_payment(state: &AppState, pending: &PendingSend, coins: &Coins, spending: &PendingCoins, generation: u64, record: Sent) -> Res<()> {
    edit_sent(state, |sent| {
        record_allowed(state, sent, pending, coins, spending, generation, &record)?;
        let same = |s: &Sent| s.txid == record.txid;
        // The same transaction again (an identical retry) keeps its doubt and lookup mark.
        let doubted = record.doubted || sent.iter().any(|s| same(s) && s.doubted);
        let lookup_mark = sent.iter().filter(|s| same(s)).map(|s| s.lookup_mark).max().unwrap_or(0).max(record.lookup_mark);
        sent.retain(|s| !same(s));
        sent.insert(0, Sent { doubted, lookup_mark, ..record });
        Ok(())
    })
    .map_err(|_| Failure::new("io"))?
}

/// The record of sent transactions, read, changed and saved in one go under its lock, so that two
/// commands never overwrite each other's changes. It is saved only when something changed, and never
/// over a file that could not be read.
fn edit_sent<R>(state: &AppState, change: impl FnOnce(&mut Vec<Sent>) -> R) -> std::io::Result<R> {
    let _one_at_a_time = guard(&state.sent_ops);
    let mut sent: Vec<Sent> = store::load_existing(&state.sent_path())?;
    let before = sent.clone();
    for s in &mut sent {
        prepare_record(s);
    }
    mark_replaced(&mut sent);
    let result = change(&mut sent);
    if sent != before {
        let mut bytes = serde_json::to_vec_pretty(&sent)?;
        if bytes.len() > PRUNE_ABOVE_BYTES {
            prune(&mut sent, now());
            bytes = serde_json::to_vec_pretty(&sent)?;
        }
        // Records that cannot be pruned may still fit without indentation.
        if bytes.len() as u64 > store::MAX_FILE_BYTES {
            bytes = serde_json::to_vec(&sent)?;
        }
        // Never a file the wallet could not read back: the change is refused instead.
        if bytes.len() as u64 > store::MAX_FILE_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "the record of payments is full"));
        }
        #[cfg(test)]
        if state.fail_sent_writes.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
            return Err(std::io::Error::other("a failing disk (test)"));
        }
        store::write_atomic(&state.sent_path(), &bytes)?;
    }
    Ok(result)
}

/// Err("locked") once the session of `generation` has been locked.
fn still_generation(state: &AppState, generation: u64) -> Res<()> {
    if state.generation() != generation {
        return Err(Failure::new("locked"));
    }
    Ok(())
}

/// `edit_sent` for a command of the session of `generation`: under the commit lock, which locking also takes,
/// and only while that is still the session's; Err(locked) otherwise, with nothing written. Not for the commit
/// section itself, which holds that lock already.
fn edit_sent_at<R>(state: &AppState, generation: u64, change: impl FnOnce(&mut Vec<Sent>) -> R) -> Res<R> {
    let _commit = guard(&state.commit_ops);
    if state.generation() != generation {
        return Err(Failure::new("locked"));
    }
    edit_sent(state, change).map_err(|_| Failure::new("io"))
}

/// The record is pruned past half the size the wallet reads back.
const PRUNE_ABOVE_BYTES: usize = (store::MAX_FILE_BYTES / 2) as usize;

fn prepare_record(s: &mut Sent) -> bool {
    let mut changed = false;
    if !s.proof_verified && s.confirmations >= REQUIRED_BLOCKS {
        s.confirmations = REQUIRED_BLOCKS - 1;
        changed = true;
    }
    if !s.doubted && (matches!(s.status.as_str(), "unknown" | "rejected" | "failed" | "replaced") || (s.status == "confirmed" && !s.proven())) {
        s.doubted = true;
        changed = true;
    }
    changed
}

fn confirmed_status(confirmations: u32, blocks: u32) -> (TxStatus, bool) {
    let proven = blocks == REQUIRED_BLOCKS;
    let confirmations = if proven { confirmations } else { confirmations.min(REQUIRED_BLOCKS - 1) };
    (TxStatus::Confirmed { confirmations }, proven)
}

async fn lookup_sent(sources: &Sources, txid: &str, flags: &mut Flags) -> Result<(TxStatus, bool), ApiError> {
    let status = flags.take(sources.tx_status(txid).await)?;
    if let TxStatus::Confirmed { confirmations } = status {
        if confirmations >= REQUIRED_BLOCKS {
            // A failed proof leaves a confirmed but unproven payment: the cover and warning rules still apply to it.
            let blocks = flags.take(sources.proof(txid).await).unwrap_or(0);
            return Ok(confirmed_status(confirmations, blocks));
        }
    }
    Ok((status, false))
}

/// Brings the record down to half the size the wallet reads back. Only payments a month old and settled
/// for good go, the oldest first: replaced or refused ones that a payment confirmed six times covers (it
/// spends one of their coins), then payments confirmed six times that no remaining record shares a coin
/// with, so that no rule loses what it goes by. Payments that may still go out are never dropped.
fn prune(sent: &mut Vec<Sent>, now: u64) {
    const SETTLED_AFTER_SECS: u64 = 30 * 24 * 3600;
    mark_replaced(sent);
    // As written inside the list: each line two spaces further in, and a comma and a newline after it.
    let size = |s: &Sent| serde_json::to_vec_pretty(s).map_or(0, |b| b.len() + 2 * b.iter().filter(|&&c| c == b'\n').count() + 4);
    // The list's brackets around them: never less than the file will be.
    let mut total: usize = 4 + sent.iter().map(size).sum::<usize>();
    let old = |s: &Sent| now.saturating_sub(s.created) > SETTLED_AFTER_SECS;
    let done_for_good = Sent::proven;
    let spent_for_good: HashSet<&str> = sent.iter().filter(|s| done_for_good(s)).flat_map(|s| s.outpoints.iter().map(String::as_str)).collect();
    let mut dropped: HashSet<usize> = HashSet::new();
    let mut drop_oldest = |mut picked: Vec<usize>, dropped: &mut HashSet<usize>| {
        picked.sort_by_key(|&i| sent[i].created);
        for i in picked {
            if total <= PRUNE_ABOVE_BYTES {
                break;
            }
            total -= size(&sent[i]);
            dropped.insert(i);
        }
    };
    let covered = (0..sent.len())
        .filter(|&i| {
            let s = &sent[i];
            old(s) && (s.status == "replaced" || refused(s)) && s.outpoints.iter().any(|o| spent_for_good.contains(o.as_str()))
        })
        .collect();
    drop_oldest(covered, &mut dropped);
    let mut users: HashMap<&str, usize> = HashMap::new();
    for (_, s) in sent.iter().enumerate().filter(|(i, _)| !dropped.contains(i)) {
        for o in &s.outpoints {
            *users.entry(o.as_str()).or_default() += 1;
        }
    }
    let alone = (0..sent.len())
        .filter(|&i| {
            let s = &sent[i];
            !dropped.contains(&i) && old(s) && done_for_good(s) && s.outpoints.iter().all(|o| users.get(o.as_str()) == Some(&1))
        })
        .collect();
    drop_oldest(alone, &mut dropped);
    let mut i = 0;
    sent.retain(|_| {
        i += 1;
        !dropped.contains(&(i - 1))
    });
}

/// Outcomes that the node not having the transaction does not change: it refused it, the API did not
/// pass it on, or a proven payment spent one of its coins.
fn settled(s: &Sent) -> bool {
    matches!(s.status.as_str(), "rejected" | "failed" | "replaced")
}

/// Only a proven payment settles an attempt spending one of the same coins. Older records
/// marked replaced while a retry was merely in the mempool become unclear again, with their doubt.
fn mark_replaced(sent: &mut [Sent]) {
    let taken: HashSet<String> =
        sent.iter().filter(|s| s.proven()).flat_map(|s| s.outpoints.iter().cloned()).collect();
    for s in sent.iter_mut().filter(|s| !s.proven() && !refused(s) && s.status != "submitting") {
        if s.outpoints.iter().any(|o| taken.contains(o)) {
            s.status = "replaced".into();
        } else if s.status == "replaced" {
            s.status = "unknown".into();
            s.doubted = true;
        }
    }
}

#[derive(Default)]
struct PendingCoins {
    coins: Vec<Coin>,
    spent_by: HashMap<String, HashSet<String>>,
    unnamed_spenders: HashSet<String>,
}

/// The coins being spent by mempool transactions from any of the wallet's addresses (`coins` are those
/// of `paying`, already fetched): a payment made before the wallet was restored here, or on another
/// device, may have gone from any of them. No answer means no plan.
/// How long a lookup of an address's coins stands in for another (`AppState::seen_coins`): longer than the
/// overview's refresh (30 s), so that the addresses a payment does not pay from are not asked for again.
const SEEN_FOR: Duration = Duration::from_secs(60);

type SeenCoins = Mutex<HashMap<String, (Instant, Coins)>>;

/// Keeps a successful lookup of an address's coins (`AppState::seen_coins`), made under `generation`: only while
/// that is still the session's. The check and the insert are under the cache's lock, and locking empties the
/// cache after it moves the generation on, so a lookup of a locked session never stays.
fn remember(state: &AppState, generation: u64, address: &str, found: &Result<Coins, ApiError>) {
    if let Ok(coins) = found {
        let mut seen = guard(&state.seen_coins);
        if state.generation() == generation {
            seen.insert(address.to_string(), (Instant::now(), coins.clone()));
        }
    }
}

/// The pending coins of the paying address (`coins`, just looked up) and of the wallet's other addresses. With
/// `seen` (a plan), an address a lookup of the last SEEN_FOR found is taken from there and only the others are
/// looked up; without it (a confirmation's re-check), every address is looked up now, as before. The other
/// addresses only feed the warning of a coin spent by a payment no record names; a risk that appears between
/// the plan and its confirmation still sends the payment back to review.
async fn pending_everywhere(sources: &Sources, coins: &Coins, own: &[Template], paying: &str, seen: Option<&SeenCoins>, flags: &mut Flags) -> Res<PendingCoins> {
    let mut pending = PendingCoins {
        coins: coins.pending.clone(), spent_by: coins.spent_by.clone(), unnamed_spenders: coins.unnamed_spenders.clone(),
    };
    for t in own.iter().filter(|t| t.address != paying) {
        let recent = seen.and_then(|seen| guard(seen).get(&t.address).filter(|(at, _)| at.elapsed() <= SEEN_FOR).map(|(_, c)| c.clone()));
        let coins = match recent {
            Some(c) => c,
            None => flags.take(sources.coins(&t.address).await)?,
        };
        pending.coins.extend(coins.pending);
        for (outpoint, txids) in coins.spent_by { pending.spent_by.entry(outpoint).or_default().extend(txids); }
        pending.unnamed_spenders.extend(coins.unnamed_spenders);
    }
    Ok(pending)
}

/// An address's kind as the record names it.
fn kind_name(kind: Kind) -> String {
    serde_json::to_value(kind).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

/// A payment the wallet doubted that the network has now, lately.
fn surfaced(sent: &[Sent]) -> bool {
    sent.iter().any(|s| s.doubted && (s.status == "mempool" || (s.status == "confirmed" && !s.proven())))
}

// An unproven confirmation keeps its status for display; the protection treats it as unclear.
fn unclear(s: &Sent) -> bool {
    s.status == "unknown" || (s.status == "confirmed" && !s.proven())
}

/// Refused by the node, or not passed on by the API: what the API answered, which it may have done while
/// passing the transaction on all the same.
fn refused(s: &Sent) -> bool {
    matches!(s.status.as_str(), "rejected" | "failed")
}

fn recent(s: &Sent, now: u64) -> bool {
    now.saturating_sub(s.created) < RECHECK_SETTLED_SECS
}

/// What the wallet's earlier payments mean for a new one from an account (its name as recorded) whose
/// unspent coins are `spendable`.
struct Earlier {
    /// The coins the new payment may spend: not those of a payment on its way, which it would try to
    /// replace.
    usable: Vec<Coin>,
    /// For each of the address's payments that may still go out (no clear answer, or refused: the API may
    /// have passed it on all the same), its largest coin still unspent: the new payment spends it too, so
    /// that the two can never both go through. Only a proven payment spending one of its coins covers it.
    required: Vec<Coin>,
    /// The txids of those payments.
    replaces: Vec<String>,
    /// For each of those payments, its usable coins: spending any one of them covers it.
    covers: Vec<Vec<Coin>>,
    /// Such a payment with no usable coins left, or with a coin spent by a payment on its way, and no
    /// proven cover: it may still go out, and a new payment may be one more rather than a retry.
    spent: bool,
    /// Such a payment from another address, or recorded without its coins: the new payment cannot replace
    /// it. It stays one until a payment from its own address covers it.
    elsewhere: bool,
    /// A coin of the wallet's is being spent by a transaction in the mempool that no record names: a
    /// payment made before the wallet was restored here, or on another device.
    unrecorded: bool,
}

fn earlier_payments(sent: &[Sent], account: &str, spendable: &[Coin], pending: &PendingCoins) -> Earlier {
    let coins_of = |statuses: &[&str]| -> HashSet<String> {
        sent.iter().filter(|s| !unclear(s) && statuses.contains(&s.status.as_str())).flat_map(|s| s.outpoints.iter().cloned()).collect()
    };
    // Mempool inputs stay unavailable, but only proven payments settle an unclear payment.
    let in_flight = coins_of(&["submitting", "mempool"]);
    let taken: HashSet<String> = sent.iter().filter(|s| s.proven()).flat_map(|s| s.outpoints.iter().cloned()).collect();
    let usable: Vec<Coin> = spendable.iter().filter(|c| !in_flight.contains(&c.outpoint())).cloned().collect();
    let recorded: HashSet<(&str, &str)> = sent.iter().flat_map(|s| s.outpoints.iter().map(move |o| (s.txid.as_str(), o.as_str()))).collect();
    let unrecorded = pending.coins.iter().any(|c| {
        let outpoint = c.outpoint();
        if taken.contains(&outpoint) { return false; }
        pending.unnamed_spenders.contains(&outpoint) || match pending.spent_by.get(&outpoint) {
            Some(txids) => txids.is_empty() || txids.iter().any(|txid| !recorded.contains(&(txid.as_str(), outpoint.as_str()))),
            None => true,
        }
    });
    let spending: HashSet<String> = pending.coins.iter().map(Coin::outpoint).chain(in_flight).collect();
    let mut e = Earlier { usable: Vec::new(), required: Vec::new(), replaces: Vec::new(), covers: Vec::new(), spent: false, elsewhere: false, unrecorded };
    for s in sent.iter().filter(|s| unclear(s) || refused(s)) {
        if s.outpoints.iter().any(|o| taken.contains(o)) {
            // A proven payment spends one of its coins: it cannot go through.
            continue;
        }
        if account_of(s) != account || s.outpoints.is_empty() {
            e.elsewhere = true;
            continue;
        }
        e.spent |= s.outpoints.iter().any(|o| spending.contains(o));
        match usable.iter().filter(|c| s.outpoints.contains(&c.outpoint())).max_by_key(|c| c.sats) {
            Some(coin) => {
                if !e.required.contains(coin) {
                    e.required.push(coin.clone());
                }
                e.replaces.push(s.txid.clone());
                e.covers.push(usable.iter().filter(|c| s.outpoints.contains(&c.outpoint())).cloned().collect());
            }
            None => e.spent = true,
        }
    }
    e.usable = usable;
    e
}

impl Earlier {
    /// The coins to add to `forced` (inputs the payment spends anyway) so that it covers every payment in
    /// `covers`: a payment one of whose coins is already spent is covered; then, one at a time, the coin
    /// shared by the most payments not yet covered, the largest among equals.
    fn cover(&self, forced: &[Coin]) -> Vec<Coin> {
        let mut added: Vec<Coin> = Vec::new();
        loop {
            let open: Vec<&Vec<Coin>> = self.covers.iter().filter(|set| !set.iter().any(|c| forced.contains(c) || added.contains(c))).collect();
            let mut best: Option<(&Coin, usize)> = None;
            for coin in open.iter().flat_map(|set| set.iter()) {
                let n = open.iter().filter(|set| set.contains(coin)).count();
                if best.is_none_or(|(b, bn)| n > bn || (n == bn && coin.sats > b.sats)) {
                    best = Some((coin, n));
                }
            }
            match best {
                Some((coin, _)) => added.push(coin.clone()),
                None => return added,
            }
        }
    }
}

/// Releases this refresh's claims even when its future is dropped before the lookups finish.
struct SentLookups<'a> {
    state: &'a AppState,
    txids: Vec<String>,
}

impl Drop for SentLookups<'_> {
    fn drop(&mut self) {
        let mut in_flight = guard(&self.state.sent_lookups);
        for txid in &self.txids {
            in_flight.remove(txid);
        }
    }
}

/// Looks up again the recorded transactions `due` picks, and uncovered refusals, at most 20 per refresh.
/// The least recently started lookup goes first, in record order among equals. All refreshes share the
/// marks and skip each other's unfinished work. One being handed to the API is left to its command.
async fn refresh_sent(state: &AppState, generation: u64, due: impl Fn(&Sent) -> bool, flags: &mut Flags) -> Vec<Sent> {
    refresh_sent_with_clock(state, generation, due, flags, Instant::now).await
}

/// Every write is bound to `generation`, the session of the command that refreshes: once the wallet is
/// locked, no lookup mark and no status is written, and the command ends `locked` at its next check.
async fn refresh_sent_with_clock(state: &AppState, generation: u64, due: impl Fn(&Sent) -> bool, flags: &mut Flags, mut clock: impl FnMut() -> Instant) -> Vec<Sent> {
    let ready = edit_sent_at(state, generation, |sent| {
        // Still being handed to the API long after any answer would have come: the send was cut short.
        let at = now();
        for s in sent.iter_mut().filter(|s| s.status == "submitting" && at.saturating_sub(s.created) > SUBMIT_TIMEOUT_SECS) {
            s.status = "unknown".into();
            s.doubted = true;
        }
        mark_replaced(sent);
    }).is_ok();
    let mut lookups = SentLookups { state, txids: Vec::new() };
    let mut found = Vec::new();
    let deadline = clock() + LOOKUP_BUDGET;
    for _ in 0..20 {
        if !ready || clock() > deadline {
            break;
        }
        let picked = {
            let mut in_flight = guard(&state.sent_lookups);
            let picked = edit_sent_at(state, generation, |sent| {
                let taken: HashSet<&str> = sent.iter().filter(|s| s.proven()).flat_map(|s| s.outpoints.iter().map(String::as_str)).collect();
                let picked = sent.iter().enumerate().filter(|(_, s)| {
                    !in_flight.contains(&s.txid) && s.status != "submitting"
                        && (due(s) || (refused(s) && !s.outpoints.iter().any(|o| taken.contains(o.as_str()))))
                }).min_by_key(|(_, s)| s.lookup_mark).map(|(i, _)| i)?;
                let mark = sent.iter().map(|s| s.lookup_mark).max().unwrap_or(0) + 1;
                let s = &mut sent[picked];
                // Persist the start too, so a cancelled refresh or a restart keeps its place.
                s.lookup_mark = mark;
                Some((s.txid.clone(), (s.status.clone(), s.confirmations, s.proof_verified), mark))
            }).ok().flatten();
            if let Some((txid, _, _)) = &picked {
                in_flight.insert(txid.clone());
                lookups.txids.push(txid.clone());
            }
            picked
        };
        let Some((txid, was, mark)) = picked else { break };
        let status = lookup_sent(&state.sources, &txid, flags).await.ok();
        found.push((txid, was, mark, status));
    }
    let refreshed = edit_sent_at(state, generation, |sent| {
        for (txid, was, mark, result) in &found {
            let Some(s) = sent.iter_mut().find(|s| &s.txid == txid) else { continue };
            // A failed lookup or a changed status still keeps the lookup's place in the order.
            s.lookup_mark = s.lookup_mark.max(*mark);
            let Some((status, proven)) = result else { continue };
            if s.status != was.0 || s.confirmations != was.1 || s.proof_verified != was.2 { continue; }
            let (st, n) = match status {
                TxStatus::Confirmed { confirmations } => ("confirmed", *confirmations),
                TxStatus::Mempool => ("mempool", 0),
                // The node does not have it: a settled outcome stays, anything else is unknown.
                TxStatus::Unknown if settled(s) => continue,
                TxStatus::Unknown => ("unknown", 0),
            };
            s.status = st.into();
            s.confirmations = n;
            s.proof_verified = *proven;
            s.doubted |= st == "unknown";
            prepare_record(s);
        }
        mark_replaced(sent);
        sent.clone()
    });
    refreshed.unwrap_or_else(|_| {
        let mut sent: Vec<Sent> = store::load(&state.sent_path());
        for s in &mut sent {
            prepare_record(s);
        }
        mark_replaced(&mut sent);
        sent
    })
}

/// How long a settled outcome is still looked up even when a proven payment covers it. An uncovered
/// refused transaction stays due however old: it may have gone out after all.
const RECHECK_SETTLED_SECS: u64 = 7 * 24 * 3600;
/// Far longer than a broadcast can take (the API client gives up after 20 seconds).
const SUBMIT_TIMEOUT_SECS: u64 = 120;
/// Lookups of one refresh stop starting after this long: a review or the activity list waits on them.
const LOOKUP_BUDGET: Duration = Duration::from_secs(15);

/// A recorded payment, and whether it can be rebuilt through the SLH-DSA leaf now (`plan_rebuild`).
#[derive(Serialize)]
pub struct ActivityItem {
    #[serde(flatten)]
    sent: Sent,
    rebuild: bool,
}

/// The transactions this wallet sent, their states looked up again where they may have changed.
#[tauri::command]
pub async fn activity(state: State<'_, AppState>) -> Res<Vec<ActivityItem>> {
    activity_of(&state).await
}

async fn activity_of(state: &AppState) -> Res<Vec<ActivityItem>> {
    let snapshot = state.snapshot()?;
    let at = now();
    let sent = refresh_sent(state, snapshot.generation, |s| !s.proven() && (!settled(s) || recent(s, at)), &mut Flags::default()).await;
    state.current(&snapshot)?;
    // Only when there is a pq2 payment through the ML-DSA-44 leaf that did not go through is the node's
    // state read for it.
    let candidate = |s: &Sent| s.from == "pq2" && s.signature == "mldsa44" && matches!(s.status.as_str(), "unknown" | "rejected" | "failed");
    let chain = if sent.iter().any(candidate) { current_chain(&state.sources, &mut Flags::default()).await.ok() } else { None };
    state.current(&snapshot)?;
    // Not offered once any version of the payment's lineage is confirmed or on its way.
    let book = snapshot.bound.as_ref().and_then(|b| state.edit_book_of(&b.wallet, b.generation, |x| x.clone()).ok());
    let went_out = |s: &Sent| {
        let versions = book.as_ref().and_then(|b| b.lineage_of(&s.txid)).map(|l| l.versions.clone()).unwrap_or_default();
        versions.iter().any(|v| sent.iter().any(|r| r.txid == v.txid && original_went_out(r) && r.status != "replaced"))
    };
    let flags: Vec<bool> = sent.iter().map(|s| chain.as_ref().is_some_and(|c| needs_rebuild(s, c)) && !went_out(s)).collect();
    state.current(&snapshot)?;
    Ok(sent.into_iter().zip(flags).map(|(s, rebuild)| ActivityItem { rebuild, sent: s }).collect())
}

#[derive(Serialize)]
pub struct DrillResult {
    verdict: CheckResult,
    signature: Path,
    vsize: usize,
    size: usize,
    sign_ms: f64,
}

/// The drill: the mixed address's largest coin, spent back to the same address through the leaf of
/// `path`, signed after a system confirmation and recorded before the node checks it. The wallet never
/// broadcasts it, but the node could. After the tripwire, the node refuses the Schnorr leaf.
#[tauri::command]
pub async fn drill_check(app: AppHandle, state: State<'_, AppState>, path: Path, locale: Option<String>) -> Res<DrillResult> {
    run_drill(&state, path, locale.as_deref(), |dialog| crate::confirm::ask(&app, dialog)).await
}

async fn run_drill<F: std::future::Future<Output = bool>>(
    state: &AppState,
    path: Path,
    locale: Option<&str>,
    ask: impl FnOnce(crate::confirm::Dialog) -> F,
) -> Res<DrillResult> {
    state.touch();
    let generation = state.generation();
    let (_, _, mixed) = state.templates()?;
    let sources = state.sources.clone();
    let mut flags = Flags::default();
    // After every answer from the network, the session first.
    let chain = current_chain(&sources, &mut flags).await;
    still_generation(state, generation)?;
    let chain = chain?;
    let account = account_for(mixed, &chain, Some(path))?;
    let coins = flags.take(sources.coins(&account.template.address).await);
    still_generation(state, generation)?;
    let coins = coins?;
    let largest = coins.spendable.iter().max_by_key(|c| c.sats).cloned().ok_or_else(|| Failure::new("no_coins"))?;
    let destination = parse_destination(&account.template.address)?;
    let plan = wallet::plan_spend(&account, std::slice::from_ref(&largest), &[], &destination, Amount::All, chain.lock_time())?;
    let own = { let (a, b, c) = state.templates()?; vec![a, b, c] };
    let spending = pending_everywhere(&sources, &coins, &own, &account.template.address, None, &mut flags).await;
    still_generation(state, generation)?;
    let spending = spending?;
    let pending = PendingSend {
        id: String::new(), created: Instant::now(), kind: Kind::Mixed, path, destination, plan,
        // The drill dialog does not authorize paying in addition to an earlier uncertain payment.
        caution: false, sources: flags,
        creates_pq2: false, pq2: None, plan_address: account.template.address.clone(), rebuild: None,
    };
    if state.generation() != generation {
        return Err(Failure::new("locked"));
    }
    if !ask(crate::confirm::drill(state.dialog_locale(locale), largest.sats, pending.plan.fee)).await {
        return Err(Failure::new("cancelled"));
    }
    if pending.created.elapsed() > PLAN_LIFETIME {
        return Err(Failure::new("no_plan"));
    }
    let started = Instant::now();
    let signed = {
        let session = guard(&state.session);
        let session = session.as_ref().ok_or_else(|| Failure::new("locked"))?;
        if state.generation() != generation {
            return Err(Failure::new("locked"));
        }
        wallet::sign_plan(&pending.plan, &account, &session.keys)?
    };
    let sign_ms = started.elapsed().as_secs_f64() * 1000.0;
    let record = Sent { doubted: true, ..signed_record(&pending, &signed, sign_ms) };
    record_payment(state, &pending, &coins, &spending, generation, record)?;
    let verdict = sources.check(&signed.hex).await.value;
    // A check says nothing about broadcasting: keep the input protected even after a refusal or failure.
    let _ = edit_sent_at(state, generation, |sent| {
        if let Some(s) = sent.iter_mut().find(|s| s.txid == signed.txid && s.status == "submitting") {
            s.status = "unknown".into();
        }
        mark_replaced(sent);
    });
    still_generation(state, generation)?;
    Ok(DrillResult { verdict, signature: path, vsize: signed.sizes.vsize, size: signed.sizes.size, sign_ms })
}

// ---- small things ----

#[derive(Serialize)]
pub struct InputCost {
    kind: Kind,
    signature: Path,
    signature_bytes: usize,
    /// One input to one P2MR output, as built here.
    tx_vsize: usize,
    tx_size: usize,
}

#[derive(Serialize)]
pub struct AppInfo {
    version: &'static str,
    api: String,
    explorer: &'static str,
    faucet: &'static str,
    target: String,
    /// sat/vB, the rate every payment pays.
    fee_rate: u64,
    costs: Vec<InputCost>,
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    // Sizes of a one-in, one-out spend from each address and leaf: what each signature costs on chain.
    let (xonly, pk) = ([2u8; 32], [3u8; 1312]);
    let coin = Coin { txid: "00".repeat(32), vout: 0, sats: 100_000, height: 0 };
    let out = vec![(90_000u64, Template::schnorr(&xonly).script_pubkey)];
    let costs = [
        (Template::schnorr(&xonly), Path::Schnorr),
        (Template::mldsa44(&pk), Path::Mldsa44),
        (Template::mixed(&xonly, &pk), Path::Schnorr),
        (Template::mixed(&xonly, &pk), Path::Mldsa44),
        (Template::pq2(&pk, &xonly), Path::Slhdsa128s),
        (Template::pq2(&pk, &xonly), Path::Mldsa44),
    ]
    .into_iter()
    .map(|(t, path)| {
        let kind = t.kind;
        let a = Account::new(t, path).expect("each has the leaf");
        let s = wallet::measure(&a, std::slice::from_ref(&coin), &out, 0);
        let signature_bytes = match path {
            Path::Schnorr => 64,
            Path::Mldsa44 => MLDSA44_SIGNATURE_CHUNKS.iter().sum(),
            Path::Slhdsa128s => SLHDSA128S_SIGNATURE_CHUNKS.iter().sum(),
        };
        InputCost { kind, signature: path, signature_bytes, tx_vsize: s.vsize, tx_size: s.size }
    })
    .collect();
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        api: state.sources.bases(),
        explorer: EXPLORER,
        faucet: FAUCET,
        target: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        fee_rate: FEE_RATE,
        costs,
    }
}

#[tauri::command]
pub fn settings_get(state: State<'_, AppState>) -> Settings {
    guard(&state.settings).clone()
}

#[tauri::command]
pub fn settings_set(state: State<'_, AppState>, settings: Settings) -> Res<Settings> {
    if !settings.valid() {
        return Err(Failure::new("invalid_settings"));
    }
    store::save_settings(&state.dir.join("settings.json"), &settings)
        .map_err(|_| Failure::new("io"))?;
    *guard(&state.settings) = settings.clone();
    Ok(settings)
}

/// A QR code of an address, as SVG: dark modules on white, with the quiet zone.
#[tauri::command]
pub fn qr_svg(text: String) -> Res<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::with_error_correction_level(text.to_uppercase().as_bytes(), qrcode::EcLevel::M)
        .map_err(|_| Failure::new("qr"))?;
    Ok(code.render::<svg::Color>().min_dimensions(240, 240).dark_color(svg::Color("#0b0f14")).light_color(svg::Color("#ffffff")).build())
}

/// Opens one of the network's pages in the system browser: the faucet, with one of this wallet's own
/// addresses filled in or none, or the explorer at a transaction this wallet recorded or at one of its own
/// addresses. Nothing else can be opened from the interface, and no value it makes up reaches the browser.
#[tauri::command]
pub fn open_page(app: AppHandle, state: State<'_, AppState>, page: String, value: Option<String>) -> Res<()> {
    use tauri_plugin_opener::OpenerExt;
    let value = value.unwrap_or_default();
    let recorded = || store::load::<Vec<Sent>>(&state.sent_path()).iter().any(|s| s.txid == value);
    let own = || state.templates().is_ok_and(|(a, b, c)| [a, b, c].iter().any(|t| t.address == value)) || own_pq2(&state).contains(&value);
    let url = page_url(&page, &value, recorded, own).ok_or_else(|| Failure::new("invalid_page"))?;
    app.opener().open_url(url, None::<&str>).map_err(|_| Failure::new("io"))
}

/// The address of a page `open_page` may open, or None; `recorded` and `own` say whether the value is a
/// transaction this wallet recorded and one of its own addresses, and are asked only when it matters.
fn page_url(
    page: &str,
    value: &str,
    recorded: impl Fn() -> bool,
    own: impl Fn() -> bool,
) -> Option<String> {
    match page {
        "faucet" if value.is_empty() => Some(FAUCET.to_string()),
        "faucet" if own() => Some(format!("{FAUCET}?address={value}")),
        "explorer" => Some(format!("{EXPLORER}/")),
        "tx" if crate::api::is_txid(value) && recorded() => Some(format!("{EXPLORER}/tx/{value}")),
        "address" if own() => Some(format!("{EXPLORER}/address/{value}")),
        _ => None,
    }
}

// The privnet build against a private network (tools/privnet/README.md).
#[cfg(all(test, feature = "privnet"))]
#[path = "privnet_e2e.rs"]
mod privnet_e2e;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof;

    fn test_state(label: &str) -> AppState {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-{label}-{}", hex::encode(nonce)));
        std::fs::create_dir_all(&dir).unwrap();
        AppState::new(dir).unwrap()
    }

    #[test]
    fn cancellation_and_lock_drop_the_pending_new_wallet() {
        let state = test_state("cancel-new");
        let generation = state.generation();
        *guard(&state.new_wallet) = Some(NewWallet { secret: Secret::new_bip39().unwrap(), confirmed: true });
        state.cancel_new_wallet();
        assert!(guard(&state.new_wallet).is_none());
        assert_eq!(state.generation(), generation);
        *guard(&state.new_wallet) = Some(NewWallet { secret: Secret::new_bip39().unwrap(), confirmed: false });
        state.lock();
        assert!(guard(&state.new_wallet).is_none());
        assert_ne!(state.generation(), generation);
        assert_eq!(Failure::from(KeyError::Randomness).code, "randomness");
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn recovery_requires_password_native_confirmation_and_an_uninterrupted_session() {
        for legacy in [false, true] {
            let state = test_state("recovery-confirm");
            let secret = if legacy {
                Secret::Legacy { seed: crate::keys::SecretBytes(Zeroizing::new([7; 32])) }
            } else {
                Secret::new_bip39().unwrap()
            };
            vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
            let reveal = |password: &str, confirmed| {
                tauri::async_runtime::block_on(reveal_secret(&state, password.into(), Some("en"), |_| std::future::ready(confirmed)))
            };
            assert_eq!(reveal("correct horse", true).unwrap_err().code, "locked");
            state.open_session(&secret, state.generation(), false).unwrap();
            let wrong = tauri::async_runtime::block_on(reveal_secret(&state, "wrong password".into(), Some("en"), |_| async {
                panic!("a wrong password must not open a dialog")
            }));
            assert_eq!(wrong.unwrap_err().code, "wrong_password");
            assert_eq!(reveal("correct horse", false).unwrap_err().code, "cancelled");
            assert_eq!(reveal("correct horse", true).unwrap(), secret.recovery_text().as_str());
            let locked = tauri::async_runtime::block_on(reveal_secret(&state, "correct horse".into(), Some("en"), |_| {
                // Even unlocking again while the dialog is open cannot revive its earlier permission.
                state.lock();
                state.open_session(&secret, state.generation(), false).unwrap();
                std::future::ready(true)
            }));
            assert_eq!(locked.unwrap_err().code, "locked");
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn deletion_requires_password_native_confirmation_and_an_uninterrupted_session() {
        let state = test_state("delete-confirm");
        let secret = Secret::new_bip39().unwrap();
        vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
        std::fs::write(state.sent_path(), b"[]").unwrap();
        let original = std::fs::read(state.vault_path()).unwrap();
        let remove = |password: &str, confirmed| {
            tauri::async_runtime::block_on(remove_wallet(&state, password.into(), Some("en"), |_| std::future::ready(confirmed)))
        };
        let locked = tauri::async_runtime::block_on(remove_wallet(&state, "correct horse".into(), Some("en"), |_| async {
            panic!("a locked wallet must not open a dialog")
        }));
        assert_eq!(locked.unwrap_err().code, "locked");
        state.open_session(&secret, state.generation(), false).unwrap();
        let wrong = tauri::async_runtime::block_on(remove_wallet(&state, "wrong password".into(), Some("en"), |_| async {
            panic!("a wrong password must not open a dialog")
        }));
        assert_eq!(wrong.unwrap_err().code, "wrong_password");
        assert_eq!(remove("correct horse", false).unwrap_err().code, "cancelled");
        assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
        assert!(state.unlocked());
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), b"[]");
        let relocked = tauri::async_runtime::block_on(remove_wallet(&state, "correct horse".into(), Some("en"), |_| {
            state.lock();
            state.open_session(&secret, state.generation(), false).unwrap();
            std::future::ready(true)
        }));
        assert_eq!(relocked.unwrap_err().code, "locked");
        assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
        assert!(state.sent_path().is_file());
        remove("correct horse", true).unwrap();
        assert!(!vault::exists(&state.vault_path()));
        assert!(!state.sent_path().exists());
        assert!(!state.unlocked());
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn password_changes_require_password_native_confirmation_and_an_uninterrupted_session() {
        let state = test_state("password-confirm");
        let secret = Secret::new_bip39().unwrap();
        vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
        std::fs::write(state.sent_path(), b"[]").unwrap();
        let original = std::fs::read(state.vault_path()).unwrap();
        let change = |password: &str, confirmed| {
            tauri::async_runtime::block_on(change_wallet_password(&state, password.into(), "battery staple".into(), Some("en"), |_| std::future::ready(confirmed)))
        };
        let locked = tauri::async_runtime::block_on(change_wallet_password(&state, "correct horse".into(), "battery staple".into(), Some("en"), |_| async {
            panic!("a locked wallet must not open a dialog")
        }));
        assert_eq!(locked.unwrap_err().code, "locked");
        state.open_session(&secret, state.generation(), false).unwrap();
        let wrong = tauri::async_runtime::block_on(change_wallet_password(&state, "wrong password".into(), "battery staple".into(), Some("en"), |_| async {
            panic!("a wrong password must not open a dialog")
        }));
        assert_eq!(wrong.unwrap_err().code, "wrong_password");
        assert_eq!(change("correct horse", false).unwrap_err().code, "cancelled");
        assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
        let relocked = tauri::async_runtime::block_on(change_wallet_password(&state, "correct horse".into(), "battery staple".into(), Some("en"), |_| {
            state.lock();
            state.open_session(&secret, state.generation(), false).unwrap();
            std::future::ready(true)
        }));
        assert_eq!(relocked.unwrap_err().code, "locked");
        assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
        change("correct horse", true).unwrap();
        assert!(state.unlocked());
        assert_eq!(vault::open(&state.vault_path(), "correct horse").err(), Some(VaultError::WrongPassword));
        assert_eq!(vault::open(&state.vault_path(), "battery staple").unwrap().recovery_text(), secret.recovery_text());
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), b"[]");
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn locking_wakes_all_waiting_sensitive_requests_and_discards_late_answers() {
        use std::sync::atomic::AtomicUsize;
        use std::task::{Context, Wake, Waker};
        use tokio::sync::oneshot;

        struct Wakes(AtomicUsize);
        impl Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        for legacy in [false, true] {
            let state = test_state("lock-dialogs");
            let secret = if legacy {
                Secret::Legacy { seed: crate::keys::SecretBytes(Zeroizing::new([7; 32])) }
            } else {
                Secret::new_bip39().unwrap()
            };
            vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
            state.open_session(&secret, state.generation(), false).unwrap();
            std::fs::write(state.sent_path(), b"[]").unwrap();
            let original = std::fs::read(state.vault_path()).unwrap();
            let (recovery_answer, recovery_wait) = oneshot::channel();
            let (delete_answer, delete_wait) = oneshot::channel();
            let (password_answer, password_wait) = oneshot::channel();
            let recovery_wakes = Arc::new(Wakes(AtomicUsize::new(0)));
            let delete_wakes = Arc::new(Wakes(AtomicUsize::new(0)));
            let password_wakes = Arc::new(Wakes(AtomicUsize::new(0)));
            let recovery_waker = Waker::from(recovery_wakes.clone());
            let delete_waker = Waker::from(delete_wakes.clone());
            let password_waker = Waker::from(password_wakes.clone());
            let mut recovery = std::pin::pin!(reveal_secret(&state, "correct horse".into(), Some("en"), |_| async move {
                recovery_wait.await.unwrap_or(false)
            }));
            let mut delete = std::pin::pin!(remove_wallet(&state, "correct horse".into(), Some("en"), |_| async move {
                delete_wait.await.unwrap_or(false)
            }));
            let mut password = std::pin::pin!(change_wallet_password(&state, "correct horse".into(), "battery staple".into(), Some("en"), |_| async move {
                password_wait.await.unwrap_or(false)
            }));
            assert!(recovery.as_mut().poll(&mut Context::from_waker(&recovery_waker)).is_pending());
            assert!(delete.as_mut().poll(&mut Context::from_waker(&delete_waker)).is_pending());
            assert!(password.as_mut().poll(&mut Context::from_waker(&password_waker)).is_pending());
            state.lock();
            for wakes in [&recovery_wakes, &delete_wakes, &password_wakes] {
                assert!(wakes.0.load(Ordering::SeqCst) > 0, "locking must wake each request without a dialog answer");
            }
            // Reopening the wallet does not revive any of the earlier requests.
            state.open_session(&secret, state.generation(), false).unwrap();
            for result in [
                recovery.as_mut().poll(&mut Context::from_waker(&recovery_waker)).map(|r| r.map(|_| ())),
                delete.as_mut().poll(&mut Context::from_waker(&delete_waker)),
                password.as_mut().poll(&mut Context::from_waker(&password_waker)),
            ] {
                match result {
                    Poll::Ready(Err(error)) => assert_eq!(error.code, "locked"),
                    _ => panic!("locking must end every request before its dialog is answered"),
                }
            }
            assert!(recovery_answer.send(true).is_err());
            assert!(delete_answer.send(true).is_err());
            assert!(password_answer.send(true).is_err());
            assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
            assert_eq!(std::fs::read(state.sent_path()).unwrap(), b"[]");
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn forgetting_requires_a_locked_wallet_and_native_confirmation() {
        for record_exists in [false, true] {
            let state = test_state("forget-confirm");
            let secret = Secret::new_bip39().unwrap();
            vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
            std::fs::write(state.sent_path(), b"[]").unwrap();
            if !record_exists {
                std::fs::remove_file(state.sent_path()).unwrap();
            }
            let original = std::fs::read(state.vault_path()).unwrap();
            state.open_session(&secret, state.generation(), false).unwrap();
            let unlocked = tauri::async_runtime::block_on(forget_locked_wallet(&state, Some("en"), |_| async {
                panic!("an unlocked wallet must not open a removal dialog")
            }));
            assert_eq!(unlocked.unwrap_err().code, "unlocked");
            state.lock();
            let generation = state.generation();
            let cancelled = tauri::async_runtime::block_on(forget_locked_wallet(&state, Some("en"), |_| std::future::ready(false)));
            assert_eq!(cancelled.unwrap_err().code, "cancelled");
            assert_eq!(state.generation(), generation);
            assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
            assert_eq!(state.sent_path().exists(), record_exists);
            tauri::async_runtime::block_on(forget_locked_wallet(&state, Some("en"), |_| std::future::ready(true))).unwrap();
            assert_ne!(state.generation(), generation);
            assert!(!state.unlocked());
            assert!(!state.vault_path().exists());
            assert!(!state.sent_path().exists());
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn locking_wakes_all_waiting_forget_requests_and_discards_late_answers() {
        use std::sync::atomic::AtomicUsize;
        use std::task::{Context, Wake, Waker};
        use tokio::sync::oneshot;

        struct Wakes(AtomicUsize);
        impl Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        for scenario in ["lock", "idle", "answer"] {
            let state = test_state("forget-lock-dialogs");
            let secret = Secret::new_bip39().unwrap();
            vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
            std::fs::write(state.sent_path(), b"[]").unwrap();
            let original = std::fs::read(state.vault_path()).unwrap();
            let (mut answers, waits): (Vec<_>, Vec<_>) = (0..2).map(|_| oneshot::channel::<bool>()).unzip();
            let mut requests: Vec<_> = waits.into_iter().map(|wait| {
                Box::pin(forget_locked_wallet(&state, Some("en"), |_| async move { wait.await.unwrap_or(false) }))
            }).collect();
            let wakes: Vec<_> = (0..2).map(|_| Arc::new(Wakes(AtomicUsize::new(0)))).collect();
            let wakers: Vec<_> = wakes.iter().cloned().map(Waker::from).collect();
            for (request, waker) in requests.iter_mut().zip(&wakers) {
                assert!(request.as_mut().poll(&mut Context::from_waker(waker)).is_pending());
            }
            if scenario == "idle" {
                state.open_session(&secret, state.generation(), false).unwrap();
            }
            if scenario == "answer" {
                answers.remove(0).send(true).unwrap();
            }
            state.lock();
            state.open_session(&secret, state.generation(), false).unwrap();
            for ((request, waker), wakes) in requests.iter_mut().zip(&wakers).zip(&wakes) {
                assert!(wakes.0.load(Ordering::SeqCst) > 0, "locking must wake every forget request");
                match request.as_mut().poll(&mut Context::from_waker(waker)) {
                    Poll::Ready(Err(error)) => assert_eq!(error.code, "cancelled"),
                    _ => panic!("locking must end the forget request without an answer"),
                }
            }
            for answer in answers {
                assert!(answer.send(true).is_err());
            }
            assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
            assert_eq!(std::fs::read(state.sent_path()).unwrap(), b"[]");
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn forgetting_rechecks_changes_made_while_the_dialog_answers() {
        for change in ["lock", "unlock", "relock"] {
            let state = test_state("forget-answer");
            let secret = Secret::new_bip39().unwrap();
            vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
            std::fs::write(state.sent_path(), b"[]").unwrap();
            let original = std::fs::read(state.vault_path()).unwrap();
            let result = tauri::async_runtime::block_on(forget_locked_wallet(&state, Some("en"), |_| async {
                if change != "lock" {
                    state.open_session(&secret, state.generation(), false).unwrap();
                }
                if change != "unlock" {
                    state.lock();
                }
                true
            }));
            assert_eq!(result.unwrap_err().code, if change == "unlock" { "unlocked" } else { "cancelled" });
            assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
            assert_eq!(std::fs::read(state.sent_path()).unwrap(), b"[]");
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn forgetting_rechecks_under_vault_ops_after_the_answer() {
        use std::sync::mpsc;

        for lock_again in [false, true] {
            let state = test_state("forget-vault-ops");
            let secret = Secret::new_bip39().unwrap();
            vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
            std::fs::write(state.sent_path(), b"[]").unwrap();
            let original = std::fs::read(state.vault_path()).unwrap();
            std::thread::scope(|scope| {
                let vault_ops = guard(&state.vault_ops);
                let (answered, wait) = mpsc::channel();
                let state_ref = &state;
                let request = scope.spawn(move || {
                    tauri::async_runtime::block_on(forget_locked_wallet(state_ref, Some("en"), |_| async {
                        answered.send(()).unwrap();
                        true
                    }))
                });
                wait.recv().unwrap();
                if lock_again {
                    state.lock();
                } else {
                    state.open_session(&secret, state.generation(), false).unwrap();
                }
                drop(vault_ops);
                assert_eq!(request.join().unwrap().unwrap_err().code, if lock_again { "cancelled" } else { "unlocked" });
            });
            assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
            assert_eq!(std::fs::read(state.sent_path()).unwrap(), b"[]");
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn removals_leave_an_orphaned_record_that_blocks_creation_and_restore() {
        for (forgotten, restoring) in [(false, false), (false, true), (true, false), (true, true)] {
            let state = test_state("remove-record-io");
            let secret = Secret::new_bip39().unwrap();
            vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
            std::fs::write(state.sent_path(), b"[]").unwrap();
            std::fs::remove_file(state.sent_path()).unwrap();
            // A directory reliably fails remove_file on every platform, even when tests run as root.
            std::fs::create_dir(state.sent_path()).unwrap();
            let remove = || {
                if forgotten {
                    tauri::async_runtime::block_on(forget_locked_wallet(&state, Some("en"), |_| std::future::ready(true)))
                } else {
                    tauri::async_runtime::block_on(remove_wallet(&state, "correct horse".into(), Some("en"), |_| std::future::ready(true)))
                }
            };
            if !forgotten {
                state.open_session(&secret, state.generation(), false).unwrap();
            }
            let generation = state.generation();
            assert_eq!(remove().unwrap_err().code, "io");
            assert_ne!(state.generation(), generation);
            assert!(!state.unlocked());
            assert!(!state.vault_path().exists());
            assert!(state.sent_path().is_dir());
            let new_secret = Secret::new_bip39().unwrap();
            let recovery = new_secret.recovery_text().to_string();
            if !restoring {
                *guard(&state.new_wallet) = Some(NewWallet { secret: new_secret, confirmed: true });
            }
            let make = || {
                if restoring {
                    restore_wallet_from_text(&state, recovery.clone(), "battery staple".into())
                } else {
                    create_confirmed_wallet(&state, "battery staple".into())
                }
            };
            assert_eq!(make().unwrap_err().code, "io");
            assert!(!state.vault_path().exists());
            assert!(!state.unlocked());
            assert!(state.sent_path().is_dir());
            if !restoring { assert!(guard(&state.new_wallet).as_ref().unwrap().confirmed); }
            std::fs::remove_dir(state.sent_path()).unwrap();
            // A removable orphan is discarded before either kind of new wallet takes its place.
            store::save(&state.sent_path(), &vec![paid('1', "unknown", "schnorr", &['a'])]).unwrap();
            make().unwrap();
            assert!(state.vault_path().is_file());
            assert!(state.unlocked());
            assert_eq!(vault::open(&state.vault_path(), "battery staple").unwrap().recovery_text().as_str(), recovery);
            assert!(!state.sent_path().exists());
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn creating_and_restoring_keep_the_record_when_a_vault_path_exists() {
        for restoring in [false, true] {
            for directory in [false, true] {
                let state = test_state("create-existing-record");
                let secret = Secret::new_bip39().unwrap();
                let recovery = secret.recovery_text().to_string();
                if directory {
                    std::fs::create_dir(state.vault_path()).unwrap();
                } else {
                    vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
                }
                let original = if directory { Vec::new() } else { std::fs::read(state.vault_path()).unwrap() };
                store::save(&state.sent_path(), &vec![paid('1', "unknown", "schnorr", &['a'])]).unwrap();
                let record = std::fs::read(state.sent_path()).unwrap();
                *guard(&state.new_wallet) = Some(NewWallet { secret, confirmed: true });
                let result = if restoring {
                    restore_wallet_from_text(&state, recovery, "battery staple".into())
                } else {
                    create_confirmed_wallet(&state, "battery staple".into())
                };
                assert_eq!(result.unwrap_err().code, if directory { "io" } else { "exists" });
                assert_eq!(std::fs::read(state.sent_path()).unwrap(), record);
                if !directory { assert_eq!(std::fs::read(state.vault_path()).unwrap(), original); }
                std::fs::remove_dir_all(&state.dir).unwrap();
            }
        }
    }

    #[test]
    fn forgetting_keeps_the_record_when_the_vault_path_cannot_be_removed() {
        let state = test_state("remove-vault-directory");
        std::fs::create_dir(state.vault_path()).unwrap();
        std::fs::write(state.vault_path().join("held"), b"vault").unwrap();
        store::save(&state.sent_path(), &vec![paid('1', "unknown", "schnorr", &['a'])]).unwrap();
        let original = std::fs::read(state.sent_path()).unwrap();
        let result = tauri::async_runtime::block_on(forget_locked_wallet(&state, Some("en"), |_| std::future::ready(true)));
        assert_eq!(result.unwrap_err().code, "io");
        assert_eq!(std::fs::read(state.vault_path().join("held")).unwrap(), b"vault");
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), original);
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn removal_rechecks_the_password_before_deleting_the_record() {
        let state = test_state("remove-password-changed");
        let secret = Secret::new_bip39().unwrap();
        vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
        state.open_session(&secret, state.generation(), false).unwrap();
        std::fs::write(state.sent_path(), b"[]").unwrap();
        let result = tauri::async_runtime::block_on(remove_wallet(&state, "correct horse".into(), Some("en"), |_| {
            vault::change_password(&state.vault_path(), "correct horse", "battery staple").unwrap();
            std::future::ready(true)
        }));
        assert_eq!(result.unwrap_err().code, "wrong_password");
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), b"[]");
        assert!(state.unlocked());
        assert!(vault::open(&state.vault_path(), "battery staple").is_ok());
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn removals_report_io_for_read_only_and_unshared_payment_records() {
        use std::os::windows::fs::OpenOptionsExt;

        for forgotten in [false, true] {
            for read_only in [false, true] {
                let state = test_state("remove-windows-io");
                let secret = Secret::new_bip39().unwrap();
                vault::create(&state.vault_path(), "correct horse", &secret).unwrap();
                std::fs::write(state.sent_path(), b"[]").unwrap();
                let mut permissions = std::fs::metadata(state.sent_path()).unwrap().permissions();
                let held = if read_only {
                    permissions.set_readonly(true);
                    std::fs::set_permissions(state.sent_path(), permissions.clone()).unwrap();
                    None
                } else {
                    Some(std::fs::OpenOptions::new().read(true).share_mode(0).open(state.sent_path()).unwrap())
                };
                let result = if forgotten {
                    tauri::async_runtime::block_on(forget_locked_wallet(&state, Some("en"), |_| std::future::ready(true)))
                } else {
                    state.open_session(&secret, state.generation(), false).unwrap();
                    tauri::async_runtime::block_on(remove_wallet(&state, "correct horse".into(), Some("en"), |_| std::future::ready(true)))
                };
                assert_eq!(result.unwrap_err().code, "io");
                assert!(!state.unlocked());
                assert!(!state.vault_path().exists());
                let recovery = secret.recovery_text().to_string();
                *guard(&state.new_wallet) = Some(NewWallet { secret, confirmed: true });
                assert_eq!(create_confirmed_wallet(&state, "battery staple".into()).unwrap_err().code, "io");
                assert_eq!(restore_wallet_from_text(&state, recovery.clone(), "battery staple".into()).unwrap_err().code, "io");
                drop(held);
                permissions.set_readonly(false);
                std::fs::set_permissions(state.sent_path(), permissions).unwrap();
                assert_eq!(std::fs::read(state.sent_path()).unwrap(), b"[]");
                if forgotten {
                    restore_wallet_from_text(&state, recovery, "battery staple".into()).unwrap();
                } else {
                    create_confirmed_wallet(&state, "battery staple".into()).unwrap();
                }
                assert!(state.unlocked());
                assert!(state.vault_path().is_file());
                assert!(!state.sent_path().exists());
                std::fs::remove_dir_all(&state.dir).unwrap();
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn removals_keep_the_wallet_and_record_when_the_vault_cannot_be_removed() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        for forgotten in [false, true] {
            for read_only in [false, true] {
                let state = test_state("remove-vault-windows-io");
                vault::create(&state.vault_path(), "correct horse", &Secret::new_bip39().unwrap()).unwrap();
                store::save(&state.sent_path(), &vec![paid('1', "unknown", "schnorr", &['a'])]).unwrap();
                let original = std::fs::read(state.vault_path()).unwrap();
                let record = std::fs::read(state.sent_path()).unwrap();
                let mut permissions = std::fs::metadata(state.vault_path()).unwrap().permissions();
                let held = if read_only {
                    permissions.set_readonly(true);
                    std::fs::set_permissions(state.vault_path(), permissions.clone()).unwrap();
                    None
                } else {
                    Some(std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE).open(state.vault_path()).unwrap())
                };
                if !forgotten { unlock_wallet(&state, "correct horse".into()).unwrap(); }
                let remove = || {
                    if forgotten {
                        tauri::async_runtime::block_on(forget_locked_wallet(&state, Some("en"), |_| std::future::ready(true)))
                    } else {
                        tauri::async_runtime::block_on(remove_wallet(&state, "correct horse".into(), Some("en"), |_| std::future::ready(true)))
                    }
                };
                assert_eq!(remove().unwrap_err().code, "io");
                assert!(!state.unlocked());
                assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
                assert_eq!(std::fs::read(state.sent_path()).unwrap(), record);
                drop(held);
                permissions.set_readonly(false);
                std::fs::set_permissions(state.vault_path(), permissions).unwrap();
                unlock_wallet(&state, "correct horse".into()).unwrap();
                assert!(state.unlocked());
                if forgotten { state.lock(); }
                remove().unwrap();
                assert!(!state.vault_path().exists());
                assert!(!state.sent_path().exists());
                std::fs::remove_dir_all(&state.dir).unwrap();
            }
        }
    }

    #[test]
    fn an_unlock_started_after_the_removal_lock_cannot_reopen_a_deleted_wallet() {
        use std::sync::mpsc;

        let state = test_state("forget-unlock-race");
        vault::create(&state.vault_path(), "correct horse", &Secret::new_bip39().unwrap()).unwrap();
        std::fs::write(state.sent_path(), b"[]").unwrap();
        let mut locked = state.locked.subscribe();
        std::thread::scope(|scope| {
            // Stop removal after its lock but before either file is deleted.
            let sent_ops = guard(&state.sent_ops);
            let removal = scope.spawn(|| {
                tauri::async_runtime::block_on(forget_locked_wallet(&state, Some("en"), |_| std::future::ready(true)))
            });
            tauri::async_runtime::block_on(locked.changed()).unwrap();
            assert!(!state.unlocked());
            assert!(state.vault_path().is_file());
            assert!(matches!(state.vault_ops.try_lock(), Err(std::sync::TryLockError::WouldBlock)));
            let (started, wait) = mpsc::channel();
            let state_ref = &state;
            let opening = scope.spawn(move || {
                started.send(()).unwrap();
                unlock_wallet(state_ref, "correct horse".into())
            });
            wait.recv().unwrap();
            drop(sent_ops);
            removal.join().unwrap().unwrap();
            assert_eq!(opening.join().unwrap().unwrap_err().code, "io");
        });
        assert!(!state.unlocked());
        assert!(!state.vault_path().exists());
        assert!(!state.sent_path().exists());
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn drills_are_recorded_before_checking_and_keep_payment_protections() {
        use crate::api::tests::{response, serve, serve_with, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;
        use std::sync::atomic::AtomicUsize;

        for path in [Path::Schnorr, Path::Mldsa44] {
            for outcome in ["allowed", "rejected", "failed", "cancelled", "locked", "conflict", "mempool", "submitting", "io"] {
                let mut state = test_state("drill-record");
                let secret = Secret::new_bip39().unwrap();
                state.open_session(&secret, state.generation(), false).unwrap();
                let destination = state.templates().unwrap().2.address;
                let replies = vec![
                    response(200, &chain_state(40_000, true).to_string()),
                    response(200, &coins(vec![utxo('a', 0, 150_000_000), utxo('b', 0, 50_000)])),
                    response(200, &coins(vec![])),
                    response(200, &coins(vec![])),
                ];
                let sends = matches!(outcome, "allowed" | "rejected" | "failed");
                let mut left = replies.clone();
                let mut right = replies;
                if sends {
                    left.push(match outcome {
                        "allowed" => response(200, r#"{"allowed":true,"vsize":100,"fee":200}"#),
                        "rejected" => response(200, r#"{"allowed":false,"reason":"bad-input"}"#),
                        _ => response(500, "{}"),
                    });
                    if outcome == "failed" {
                        right.push(response(500, "{}"));
                    }
                }
                let seen = Arc::new(AtomicUsize::new(0));
                let requests_seen = seen.clone();
                let sent_path = state.sent_path();
                let (a, first) = serve_with(left, move || {
                    if requests_seen.fetch_add(1, Ordering::SeqCst) == 4 {
                        let sent: Vec<Sent> = store::load_existing(&sent_path).unwrap();
                        assert_eq!(sent.len(), 1);
                        assert_eq!(sent[0].status, "submitting");
                        assert!(sent[0].doubted);
                        assert_eq!(sent[0].outpoints, vec![coin('a', 0).outpoint()]);
                    }
                });
                let (b, second) = serve(right);
                state.sources = Arc::new(Sources::new(a, b));
                let result = tauri::async_runtime::block_on(run_drill(&state, path, Some("en"), |_| {
                    assert_eq!(seen.load(Ordering::SeqCst), 4);
                    assert!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap().is_empty());
                    // Changes made while the native dialog waits must be checked against the record too.
                    match outcome {
                        "locked" => state.lock(),
                        "conflict" => store::save(&state.sent_path(), &vec![paid('1', "unknown", "mixed", &['b'])]).unwrap(),
                        "mempool" => store::save(&state.sent_path(), &vec![paid('1', "mempool", "mixed", &['a'])]).unwrap(),
                        "submitting" => store::save(&state.sent_path(), &vec![paid('1', "submitting", "mixed", &['b'])]).unwrap(),
                        "io" => std::fs::write(state.sent_path(), b"not JSON").unwrap(),
                        _ => (),
                    }
                    std::future::ready(outcome != "cancelled")
                }));
                let first = first.join().unwrap();
                let second = second.join().unwrap();
                assert_eq!(first.len(), if sends { 5 } else { 4 });
                assert_eq!(second.len(), if outcome == "failed" { 5 } else { 4 });
                assert!(first.iter().chain(&second).all(|r| !r.starts_with("POST /api/broadcast")));
                if sends {
                    assert!(first.last().unwrap().starts_with("POST /api/check "));
                    let result = result.unwrap();
                    match outcome {
                        "allowed" => assert!(matches!(result.verdict, CheckResult::Allowed { .. })),
                        "rejected" => assert!(matches!(result.verdict, CheckResult::Rejected { .. })),
                        _ => assert!(matches!(result.verdict, CheckResult::Failed { .. })),
                    }
                    let sent: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
                    assert_eq!(sent.len(), 1);
                    let s = &sent[0];
                    assert_eq!((s.from.as_str(), s.to.as_str(), s.status.as_str()), ("mixed", destination.as_str(), "unknown"));
                    assert_eq!(s.send + s.fee, 150_000_000);
                    assert_eq!(s.signature, if path == Path::Schnorr { "schnorr" } else { "mldsa44" });
                    assert!(s.doubted && !s.proven());
                    let earlier = earlier_payments(&sent, "mixed", &[coin('a', 150_000_000), coin('b', 50_000)], &PendingCoins::default());
                    assert_eq!(earlier.required, vec![coin('a', 150_000_000)]);
                    assert!(earlier_payments(&sent, "schnorr", &[], &PendingCoins::default()).elsewhere);
                } else {
                    let expected = match outcome {
                        "conflict" | "mempool" => "coins_changed",
                        "submitting" => "sending",
                        _ => outcome,
                    };
                    assert_eq!(result.err().unwrap().code, expected);
                    if matches!(outcome, "cancelled" | "locked") {
                        assert!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap().is_empty());
                    }
                }
                std::fs::remove_dir_all(&state.dir).unwrap();
            }
        }
    }

    #[test]
    fn amounts_parse_like_the_web_wallet() {
        assert_eq!(parse_coins("1.5"), Some(150_000_000));
        assert_eq!(parse_coins("0.0001"), Some(10_000));
        assert_eq!(parse_coins(" 2 "), Some(200_000_000));
        assert_eq!(parse_coins("0.00000001"), Some(1));
        for bad in ["", "0", "0.0", "1.", ".5", "1.000000001", "-1", "1e3", "123456789", "1,5"] {
            assert_eq!(parse_coins(bad), None, "{bad}");
        }
    }

    fn record(txid: char, status: &str) -> Sent {
        Sent {
            txid: txid.to_string().repeat(64),
            created: 1,
            from: "mldsa44".into(),
            to: "tb1z".into(),
            send: 1_000,
            fee: 100,
            change: 0,
            vsize: 1,
            size: 1,
            signature: "mldsa44".into(),
            inputs: 1,
            sign_ms: 1.0,
            status: status.into(),
            confirmations: 0,
            proof_verified: false,
            reason: String::new(),
            outpoints: vec![format!("{}:0", txid.to_string().repeat(64))],
            doubted: false,
            lookup_mark: 0,
            address: String::new(),
        }
    }

    fn coin(c: char, sats: u64) -> Coin {
        Coin { txid: c.to_string().repeat(64), vout: 0, sats, height: 1 }
    }

    fn paid(txid: char, status: &str, from: &str, coins: &[char]) -> Sent {
        Sent { from: from.into(), outpoints: coins.iter().map(|&c| coin(c, 0).outpoint()).collect(), ..record(txid, status) }
    }

    #[test]
    fn earlier_payments_shape_a_new_one() {
        const NOW: u64 = 10_000_000;
        let spendable = [coin('a', 5_000), coin('b', 9_000), coin('c', 7_000)];
        let sent = [
            // No clear answer: its largest unspent coin is required, so that a retry cannot pay twice.
            paid('1', "unknown", "mldsa44", &['a', 'b']),
            // On its way, though the API still lists its coin: that coin is left alone.
            paid('2', "mempool", "mldsa44", &['c']),
            // Its only coin is reserved by the payment on its way: a new payment needs a warning.
            paid('4', "unknown", "mldsa44", &['c']),
            // Refused: the API may have passed it on all the same, so it is covered too, however old.
            Sent { created: NOW - 60, ..paid('5', "rejected", "mldsa44", &['b']) },
            paid('7', "failed", "mldsa44", &['a']),
            // Refused, and one of its coins spent by a later payment of the wallet: covered.
            paid('9', "rejected", "mldsa44", &['a', 'z']),
            Sent { confirmations: 6, proof_verified: true, ..paid('0', "confirmed", "mldsa44", &['z']) },
        ];
        let e = earlier_payments(&sent, "mldsa44", &spendable, &PendingCoins::default());
        assert_eq!(e.usable, vec![coin('a', 5_000), coin('b', 9_000)]);
        assert_eq!(e.required, vec![coin('b', 9_000), coin('a', 5_000)]);
        assert_eq!(e.replaces, vec!["1".repeat(64), "5".repeat(64), "7".repeat(64)]);
        assert!(e.spent && !e.elsewhere);
        // One whose coins are all spent, by none of the wallet's payments, has most likely gone out.
        let mut more = sent.to_vec();
        more.push(paid('6', "unknown", "mldsa44", &['e']));
        assert!(earlier_payments(&more, "mldsa44", &spendable, &PendingCoins::default()).spent);
        // A coin being spent by a transaction no record names: a payment made before a restore, or elsewhere.
        assert!(earlier_payments(&sent, "mldsa44", &spendable, &PendingCoins { coins: vec![coin('c', 7_000)], ..PendingCoins::default() }).unrecorded);
        let named = PendingCoins {
            coins: vec![coin('c', 7_000)], spent_by: HashMap::from([(coin('c', 0).outpoint(), HashSet::from(["2".repeat(64)]))]),
            ..PendingCoins::default()
        };
        assert!(!earlier_payments(&sent, "mldsa44", &spendable, &named).unrecorded);
        assert!(earlier_payments(&sent, "mldsa44", &spendable, &PendingCoins { coins: vec![coin('x', 7_000)], ..PendingCoins::default() }).unrecorded);
        // One from another address, or recorded without its coins, cannot be replaced from here: unclear
        // or refused, however old, it is warned about until a payment of the wallet covers it.
        for (other, warned) in [
            (paid('3', "unknown", "schnorr", &['a']), true),
            (paid('8', "unknown", "mldsa44", &[]), true),
            (Sent { created: NOW - 60, ..paid('3', "failed", "schnorr", &['y']) }, true),
            (paid('3', "failed", "schnorr", &['y']), true),
            (paid('3', "failed", "schnorr", &['y', 'z']), false),
        ] {
            let mut more = sent.to_vec();
            more.push(other);
            let e = earlier_payments(&more, "mldsa44", &spendable, &PendingCoins::default());
            assert_eq!((e.elsewhere, e.spent), (warned, true));
            assert_eq!(e.required.len(), 2);
        }
    }

    #[test]
    fn the_record_stays_under_its_read_cap() {
        const NOW: u64 = 100_000_000;
        // Full-width lookup marks exercise the pruning estimate with the new field too.
        let confirmed = |i: usize| Sent {
            txid: format!("{i:064x}"),
            created: 1_000 + i as u64,
            confirmations: 6,
            proof_verified: true,
            outpoints: vec![format!("{i:064x}:1")],
            lookup_mark: u64::MAX - i as u64,
            ..record('a', "confirmed")
        };
        let mut sent: Vec<Sent> = (0..6_000).map(confirmed).collect();
        // Payments not settled for good stay, however old: a refused one still uncovered among them, and one
        // covered only by a payment still in the mempool.
        sent[10] = paid('u', "unknown", "mldsa44", &['u']);
        sent[11] = paid('e', "mempool", "mldsa44", &['p']);
        sent[12] = paid('r', "rejected", "mldsa44", &['q']);
        sent[13] = paid('s', "rejected", "mldsa44", &['p']);
        // A recent refused payment covered by an old confirmed one keeps that one.
        sent.push(Sent { txid: "d".repeat(64), created: NOW - 60, outpoints: vec![format!("{:064x}:1", 1)], ..record('d', "rejected") });
        sent.push(Sent { txid: "f".repeat(64), created: NOW, outpoints: vec!["f:9".into()], ..confirmed(0) });
        prune(&mut sent, NOW);
        assert!(serde_json::to_vec_pretty(&sent).unwrap().len() <= PRUNE_ABOVE_BYTES);
        assert!(sent.iter().any(|s| s.status == "unknown") && sent.iter().any(|s| s.status == "mempool"));
        assert!(sent.iter().any(|s| s.txid == "r".repeat(64)) && sent.iter().any(|s| s.txid == "s".repeat(64)));
        assert!(sent.iter().any(|s| s.txid == "f".repeat(64)));
        assert!(sent.iter().any(|s| s.txid == "d".repeat(64)));
        // The oldest go first, but not one a remaining record depends on.
        assert!(!sent.iter().any(|s| s.txid == format!("{:064x}", 0)));
        assert!(sent.iter().any(|s| s.txid == format!("{:064x}", 1)));
        assert!(sent.iter().any(|s| s.txid == format!("{:064x}", 5_999)));
    }

    #[test]
    fn unproven_confirmations_require_coverage_or_a_warning_until_proven() {
        let spendable = [coin('a', 5_000), coin('b', 90_000)];
        // Five may also come from a version that already lowered an old count to five.
        for confirmations in [4, 5, 6, 100] {
            let mut old = Sent { confirmations, ..paid('1', "confirmed", "mldsa44", &['a']) };
            prepare_record(&mut old);
            assert!(old.doubted && !old.proven());
            assert!(surfaced(&[old.clone()]));
            let mut sent = vec![old.clone(), paid('2', "unknown", "mldsa44", &['a'])];
            mark_replaced(&mut sent);
            assert_eq!(sent[0].status, "confirmed");
            assert_eq!(sent[1].status, "unknown");
            let e = earlier_payments(&sent, "mldsa44", &spendable, &PendingCoins::default());
            assert_eq!(e.usable, spendable.to_vec());
            assert_eq!(e.required, vec![coin('a', 5_000)]);
            assert_eq!(e.replaces, vec![old.txid.clone(), sent[1].txid.clone()]);
            assert!(!e.spent && !e.elsewhere);
            assert!(earlier_payments(&[old.clone()], "mldsa44", &spendable[1..], &PendingCoins::default()).spent);
            assert!(earlier_payments(&[old.clone()], "schnorr", &spendable, &PendingCoins::default()).elsewhere);
            let mut without_coins = old.clone();
            without_coins.outpoints.clear();
            assert!(earlier_payments(&[without_coins], "mldsa44", &spendable, &PendingCoins::default()).elsewhere);

            // Only a verified settlement covers other unclear payments and ends those protections.
            let (status, verified) = confirmed_status(100, REQUIRED_BLOCKS);
            let TxStatus::Confirmed { confirmations } = status else { panic!("confirmed") };
            sent[0] = Sent { confirmations, proof_verified: verified, ..old };
            mark_replaced(&mut sent);
            assert_eq!(sent[1].status, "replaced");
            assert!(!surfaced(&sent));
            let e = earlier_payments(&sent, "mldsa44", &spendable, &PendingCoins::default());
            assert!(e.required.is_empty() && e.replaces.is_empty());
            assert!(!e.spent && !e.elsewhere);
        }
    }

    #[test]
    fn recording_a_retry_rechecks_coverage_and_the_unproven_warning() {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-unproven-retry-{}", hex::encode(nonce)));
        let state = AppState::new(dir.clone()).unwrap();
        let old = Sent { confirmations: 100, ..paid('1', "confirmed", "schnorr", &['a']) };
        store::save(&state.sent_path(), &vec![old.clone()]).unwrap();
        let coins = Coins { spendable: vec![coin('a', 50_000), coin('b', 90_000)], ..Coins::default() };
        let account = Account::new(Template::schnorr(&[3; 32]), Path::Schnorr).unwrap();
        let destination = parse_destination(&Template::schnorr(&[5; 32]).address).unwrap();
        let plan = wallet::plan_spend(&account, &coins.spendable, &[], &destination, Amount::Sats(10_000), 0).unwrap();
        assert_eq!(plan.coins, vec![coin('b', 90_000)]);
        let mut pending = PendingSend {
            id: "retry".into(), created: Instant::now(), kind: Kind::Schnorr, path: Path::Schnorr,
            destination, plan, caution: true, sources: Flags::default(),
            creates_pq2: false, pq2: None, plan_address: account.template.address.clone(), rebuild: None,
        };
        let record_for = |p: &PendingSend| Sent {
            outpoints: p.plan.coins.iter().map(Coin::outpoint).collect(),
            ..paid('2', "submitting", "schnorr", &[])
        };
        // A larger coin could pay, but must not get round the cover the old payment requires.
        let rejected = record_payment(&state, &pending, &coins, &PendingCoins::default(), state.generation(), record_for(&pending)).unwrap_err();
        assert_eq!(rejected.code, "coins_changed");
        let earlier = earlier_payments(&[old], "schnorr", &coins.spendable, &PendingCoins::default());
        pending.plan = wallet::plan_spend(&account, &earlier.usable, &earlier.required, &pending.destination, Amount::Sats(10_000), 0).unwrap();
        assert_eq!(pending.plan.coins, vec![coin('a', 50_000)]);
        pending.caution = false;
        let rejected = record_payment(&state, &pending, &coins, &PendingCoins::default(), state.generation(), record_for(&pending)).unwrap_err();
        assert_eq!(rejected.code, "coins_changed");
        let saved: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
        assert_eq!(saved.len(), 1);
        assert!(saved[0].doubted && !saved[0].proven());
        pending.caution = true;
        let new = record_for(&pending);
        record_payment(&state, &pending, &coins, &PendingCoins::default(), state.generation(), new.clone()).unwrap();
        assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap()[0], new);
        edit_sent(&state, |sent| {
            sent[0].status = "unknown".into();
            sent[0].doubted = true;
            sent[0].lookup_mark = 9;
        }).unwrap();
        record_payment(&state, &pending, &coins, &PendingCoins::default(), state.generation(), new.clone()).unwrap();
        assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap()[0], Sent { doubted: true, lookup_mark: 9, ..new });
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn only_a_proven_payment_replaces_an_unclear_one() {
        let mut sent = vec![
            paid('1', "unknown", "mldsa44", &['a']),
            paid('2', "mempool", "mldsa44", &['a', 'f']),
            paid('3', "unknown", "mldsa44", &['g']),
            paid('4', "rejected", "mldsa44", &['a']),
            Sent { confirmations: 6, proof_verified: true, ..paid('5', "confirmed", "schnorr", &['h']) },
            paid('6', "unknown", "schnorr", &['h']),
            paid('8', "replaced", "mldsa44", &['k']),
        ];
        mark_replaced(&mut sent);
        let statuses: Vec<&str> = sent.iter().map(|s| s.status.as_str()).collect();
        assert_eq!(statuses, ["unknown", "mempool", "unknown", "rejected", "confirmed", "replaced", "unknown"]);
        assert!(sent[6].doubted);
        sent[1].status = "confirmed".into();
        sent[1].confirmations = REQUIRED_BLOCKS;
        mark_replaced(&mut sent);
        assert_eq!(sent[0].status, "unknown");
        sent[1].proof_verified = true;
        mark_replaced(&mut sent);
        assert_eq!(sent[0].status, "replaced");
        // A lost proof restores the protection, including for records from older versions.
        sent[1].proof_verified = false;
        mark_replaced(&mut sent);
        assert_eq!(sent[0].status, "unknown");
        assert!(sent[0].doubted);
    }

    #[test]
    fn a_mempool_retry_keeps_the_originals_remaining_coin_required() {
        let mut sent = vec![
            Sent { doubted: true, ..paid('1', "unknown", "schnorr", &['a', 'b']) },
            paid('2', "mempool", "schnorr", &['a', 'd']),
        ];
        mark_replaced(&mut sent);
        let spendable = [coin('a', 50_000), coin('b', 60_000), coin('c', 90_000)];
        let earlier = earlier_payments(&sent, "schnorr", &spendable, &PendingCoins::default());
        assert_eq!(sent[0].status, "unknown");
        assert!(sent[0].doubted && !settled(&sent[0]));
        assert_eq!(earlier.required, vec![coin('b', 60_000)]);
        assert_eq!(earlier.replaces, vec![sent[0].txid.clone()]);
        assert!(earlier.spent);
        let account = Account::new(Template::schnorr(&[3; 32]), Path::Schnorr).unwrap();
        let destination = parse_destination(&Template::schnorr(&[5; 32]).address).unwrap();
        let plan = wallet::plan_spend(&account, &earlier.usable, &earlier.required, &destination, Amount::Sats(10_000), 0).unwrap();
        assert_eq!(plan.coins, vec![coin('b', 60_000)]);
    }

    #[test]
    fn a_mempool_retry_with_a_remaining_coin_warns_until_either_payment_is_proven() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;

        for winner in 0..2 {
            let mut nonce = [0; 8];
            getrandom::fill(&mut nonce).unwrap();
            let dir = std::env::temp_dir().join(format!("pqw-retry-remaining-{}", hex::encode(nonce)));
            let mut state = AppState::new(dir.clone()).unwrap();
            *guard(&state.session) = Some(Session::new(&Secret::new_bip39().unwrap()).unwrap());
            let original = Sent { doubted: true, ..paid('1', "unknown", "schnorr", &['a', 'b']) };
            let retry = paid('2', "mempool", "schnorr", &['a', 'd']);
            store::save(&state.sent_path(), &vec![original, retry]).unwrap();
            let mut replies = Vec::new();
            // Review and confirmation recheck: b remains usable, but B and a payment spending b can both go through.
            for _ in 0..2 {
                replies.extend([
                    response(200, &chain_state(40_000, false).to_string()),
                    response(200, &coins(vec![utxo('b', 0, 60_000), utxo('c', 0, 90_000)])),
                    response(200, r#"{"status":"unknown"}"#),
                    response(200, r#"{"status":"mempool"}"#),
                    response(200, &coins(vec![])), response(200, &coins(vec![])),
                ]);
            }
            // Once A or B is proven, b is either spent or free; c can pay without covering either payment.
            let spendable = if winner == 0 {
                vec![utxo('c', 0, 90_000)]
            } else {
                vec![utxo('b', 0, 60_000), utxo('c', 0, 90_000)]
            };
            replies.extend([
                response(200, &chain_state(40_000, false).to_string()),
                response(200, &coins(spendable)),
                response(200, &coins(vec![])), response(200, &coins(vec![])),
            ]);
            let (a, first) = serve(replies.clone());
            let (b, second) = serve(replies);
            state.sources = Arc::new(Sources::new(a, b));
            let to = state.templates().unwrap().0.address;
            let (view, mut pending, (_, coins, spending)) = tauri::async_runtime::block_on(async {
                let view = plan_payment(&state, Kind::Schnorr, to.clone(), "0.0001".into()).await.unwrap();
                let mut pending = guard(&state.pending).take().unwrap();
                let checked = recheck_payment(&state, &state.snapshot().unwrap(), &mut pending).await.unwrap();
                (view, pending, checked)
            });
            assert!(view.went_out && pending.caution);
            assert_eq!(view.replaces, 1);
            assert!(!view.unclear_elsewhere && !view.unrecorded && !view.one_source && !view.sources_disagree);
            assert_eq!(pending.plan.coins, vec![Coin { height: 10, ..coin('b', 60_000) }]);
            // Covering A does not replace B: the record guard requires the dialog's warning too.
            pending.caution = false;
            let new = Sent { outpoints: pending.plan.coins.iter().map(Coin::outpoint).collect(),
                ..paid('3', "submitting", "schnorr", &[]) };
            assert_eq!(record_payment(&state, &pending, &coins, &spending, state.generation(), new).unwrap_err().code, "coins_changed");
            edit_sent(&state, |sent| {
                assert_eq!(sent[0].status, "unknown");
                assert!(sent[0].doubted && !settled(&sent[0]));
                assert!(!surfaced(sent));
                sent[1 - winner].status = "unknown".into();
                sent[winner].status = "confirmed".into();
                sent[winner].confirmations = REQUIRED_BLOCKS;
                sent[winner].proof_verified = true;
                mark_replaced(sent);
                assert!(sent[winner].proven());
                assert_eq!(sent[1 - winner].status, "replaced");
            }).unwrap();
            let free = tauri::async_runtime::block_on(plan_payment(&state, Kind::Schnorr, to, "0.0001".into())).unwrap();
            assert_eq!(free.replaces, 0);
            assert!(!free.went_out && !free.unclear_elsewhere && !free.unrecorded);
            let pending = guard(&state.pending).take().unwrap();
            assert!(!pending.caution);
            assert_eq!(pending.plan.coins, vec![Coin { height: 10, ..coin('c', 90_000) }]);
            assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (16, 16));
            drop(state);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn an_unrecorded_retry_warns_and_keeps_the_remaining_coin_required() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;

        for status in ["unknown", "rejected"] {
            let mut state = test_state("unrecorded-retry");
            state.open_session(&Secret::new_bip39().unwrap(), state.generation(), true).unwrap();
            store::save(&state.sent_path(), &vec![paid('1', status, "schnorr", &['a', 'b'])]).unwrap();
            let mut a = utxo('a', 0, 50_000);
            a["spent_in_mempool"] = serde_json::json!(true);
            a["spent_by"] = serde_json::json!("2".repeat(64));
            let mut replies = Vec::new();
            for _ in 0..2 {
                replies.extend([
                    response(200, &chain_state(40_000, false).to_string()),
                    response(200, &coins(vec![a.clone(), utxo('b', 0, 6_000), utxo('c', 0, 90_000)])),
                    response(200, r#"{"status":"unknown"}"#),
                    response(200, &coins(vec![])), response(200, &coins(vec![])),
                ]);
            }
            let (a, first) = serve(replies.clone());
            let (b, second) = serve(replies);
            state.sources = Arc::new(Sources::new(a, b));
            let to = state.templates().unwrap().0.address;
            let (view, mut pending, (_, coins, spending)) = tauri::async_runtime::block_on(async {
                let view = plan_payment(&state, Kind::Schnorr, to, "0.0001".into()).await.unwrap();
                let mut pending = guard(&state.pending).take().unwrap();
                let checked = recheck_payment(&state, &state.snapshot().unwrap(), &mut pending).await.unwrap();
                (view, pending, checked)
            });
            assert!(view.went_out && view.unrecorded && pending.caution);
            assert_eq!(view.replaces, 1);
            assert!(!view.unclear_elsewhere && !view.one_source && !view.sources_disagree);
            assert_eq!(pending.plan.coins.iter().map(Coin::outpoint).collect::<Vec<_>>(), vec![coin('b', 0).outpoint(), coin('c', 0).outpoint()]);
            let sent: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
            let earlier = earlier_payments(&sent, "schnorr", &coins.spendable, &spending);
            assert!(earlier.spent && earlier.unrecorded);
            assert_eq!(earlier.required, vec![Coin { height: 10, ..coin('b', 6_000) }]);
            let dialog = crate::confirm::payment("en", pending.plan.send, &pending.destination.address, pending.plan.fee, pending.plan.change, pending.caution, pending.sources);
            assert!(dialog.body().contains("an earlier payment"));
            let new = Sent { outpoints: pending.plan.coins.iter().map(Coin::outpoint).collect(), ..paid('3', "submitting", "schnorr", &[]) };
            pending.caution = false;
            assert_eq!(record_payment(&state, &pending, &coins, &spending, state.generation(), new.clone()).unwrap_err().code, "coins_changed");
            assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap(), sent);
            pending.caution = true;
            record_payment(&state, &pending, &coins, &spending, state.generation(), new).unwrap();
            assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (10, 10));
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn a_proven_cover_does_not_hide_an_unrecorded_spender_of_the_remaining_coin() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;

        for unnamed in [false, true] {
            for reverse in [false, true] {
                let mut state = test_state("covered-pending-spender");
                state.open_session(&Secret::new_bip39().unwrap(), state.generation(), true).unwrap();
                // P proves that a is spent, replacing R on {a, d}; B may still spend d.
                let sent = vec![
                    Sent { confirmations: REQUIRED_BLOCKS, proof_verified: true, ..paid('1', "confirmed", "schnorr", &['a']) },
                    Sent { doubted: true, ..paid('2', "replaced", "schnorr", &['a', 'd']) },
                ];
                store::save(&state.sent_path(), &sent).unwrap();
                let replies = |by: Option<char>| {
                    let mut d = utxo('d', 0, 50_000);
                    d["spent_in_mempool"] = serde_json::json!(true);
                    if let Some(by) = by { d["spent_by"] = serde_json::json!(by.to_string().repeat(64)); }
                    let mut replies = Vec::new();
                    for _ in 0..2 {
                        replies.extend([
                            response(200, &chain_state(40_000, false).to_string()),
                            response(200, &coins(vec![utxo('c', 0, 90_000), d.clone()])),
                            response(200, &coins(vec![])), response(200, &coins(vec![])),
                        ]);
                    }
                    replies
                };
                let a = replies(Some('2'));
                let b = replies(if unnamed { None } else { Some('3') });
                let (a, b) = if reverse { (b, a) } else { (a, b) };
                let (a, first) = serve(a);
                let (b, second) = serve(b);
                state.sources = Arc::new(Sources::new(a, b));
                let to = state.templates().unwrap().0.address;
                let (view, mut pending, (_, coins, spending)) = tauri::async_runtime::block_on(async {
                    let view = plan_payment(&state, Kind::Schnorr, to, "0.0001".into()).await.unwrap();
                    let mut pending = guard(&state.pending).take().unwrap();
                    let checked = recheck_payment(&state, &state.snapshot().unwrap(), &mut pending).await.unwrap();
                    (view, pending, checked)
                });
                assert!(view.unrecorded && view.sources_disagree && pending.caution);
                assert!(!view.went_out && !view.unclear_elsewhere && !view.one_source);
                assert_eq!(view.replaces, 0);
                assert_eq!(pending.plan.coins, vec![Coin { height: 10, ..coin('c', 90_000) }]);
                let dialog = crate::confirm::payment("en", pending.plan.send, &pending.destination.address, pending.plan.fee, pending.plan.change, pending.caution, pending.sources);
                assert!(dialog.body().contains("an earlier payment"));
                let new = paid('4', "submitting", "schnorr", &['c']);
                pending.caution = false;
                assert_eq!(record_payment(&state, &pending, &coins, &spending, state.generation(), new.clone()).unwrap_err().code, "coins_changed");
                assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap(), sent);
                pending.caution = true;
                record_payment(&state, &pending, &coins, &spending, state.generation(), new).unwrap();
                assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (8, 8));
                std::fs::remove_dir_all(&state.dir).unwrap();
            }
        }
    }

    #[test]
    fn a_pending_coin_is_recorded_by_its_spender() {
        let settled = Sent { confirmations: REQUIRED_BLOCKS, proof_verified: true, ..paid('1', "confirmed", "schnorr", &['b']) };
        let mut pending = PendingCoins {
            coins: vec![coin('a', 50_000)],
            spent_by: HashMap::from([(coin('a', 0).outpoint(), HashSet::from(["2".repeat(64)]))]),
            ..PendingCoins::default()
        };
        assert!(earlier_payments(&[settled.clone()], "schnorr", &[], &pending).unrecorded);
        let mempool = paid('2', "mempool", "schnorr", &['a']);
        assert!(!earlier_payments(&[settled.clone(), mempool.clone()], "schnorr", &[], &pending).unrecorded);
        // A known in-flight input does not stand in for a different, explicitly named spender.
        pending.spent_by.get_mut(&coin('a', 0).outpoint()).unwrap().insert("3".repeat(64));
        assert!(earlier_payments(&[settled.clone(), mempool], "schnorr", &[], &pending).unrecorded);
        for status in ["unknown", "rejected", "failed", "replaced", "confirmed", "mempool", "submitting"] {
            let sent = [settled.clone(), paid('2', status, "schnorr", &['a'])];
            pending.spent_by.insert(coin('a', 0).outpoint(), HashSet::from(["2".repeat(64)]));
            assert!(!earlier_payments(&sent, "schnorr", &[], &pending).unrecorded, "{status}");
            pending.unnamed_spenders.insert(coin('a', 0).outpoint());
            assert!(earlier_payments(&sent, "schnorr", &[], &pending).unrecorded, "{status}");
            pending.unnamed_spenders.clear();
            pending.spent_by.clear();
            assert!(earlier_payments(&sent, "schnorr", &[], &pending).unrecorded, "{status}");
        }
        pending.spent_by.insert(coin('a', 0).outpoint(), HashSet::from(["2".repeat(64)]));
        // Naming a recorded transaction is not enough: its record must spend this coin.
        assert!(earlier_payments(&[paid('2', "mempool", "schnorr", &['b'])], "schnorr", &[], &pending).unrecorded);
    }

    #[test]
    fn pending_spenders_are_collected_from_every_address() {
        use crate::api::tests::{response, serve, utxo};
        use crate::sources::tests::coins;

        let state = test_state("pending-spenders");
        state.open_session(&Secret::new_bip39().unwrap(), state.generation(), true).unwrap();
        let (a, b, c) = state.templates().unwrap();
        let own = [a, b, c];
        let replies: Vec<_> = [('b', '2'), ('c', '3')].iter().map(|&(coin, txid)| {
            let mut u = utxo(coin, 0, 50_000);
            u["spent_in_mempool"] = serde_json::json!(true);
            u["spent_by"] = serde_json::json!(txid.to_string().repeat(64));
            response(200, &coins(vec![u]))
        }).collect();
        let (a, first) = serve(replies.clone());
        let (b, second) = serve(replies);
        let sources = Sources::new(a, b);
        let coins = Coins { pending: vec![coin('a', 50_000)], spent_by: HashMap::from([(coin('a', 0).outpoint(), HashSet::from(["1".repeat(64)]))]), ..Coins::default() };
        let mut pending = tauri::async_runtime::block_on(pending_everywhere(&sources, &coins, &own, &own[0].address, None, &mut Flags::default())).unwrap();
        assert_eq!(pending.coins.len(), 3);
        assert_eq!(pending.spent_by.len(), 3);
        let sent = [paid('1', "mempool", "schnorr", &['a']), paid('2', "mempool", "mldsa44", &['b']), paid('3', "mempool", "mixed", &['c'])];
        assert!(!earlier_payments(&sent, "schnorr", &[], &pending).unrecorded);
        for c in ['a', 'b', 'c'] {
            let known = pending.spent_by.insert(coin(c, 0).outpoint(), HashSet::from(["4".repeat(64)])).unwrap();
            assert!(earlier_payments(&sent, "schnorr", &[], &pending).unrecorded);
            pending.spent_by.insert(coin(c, 0).outpoint(), known);
        }
        assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (2, 2));
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn pending_spenders_are_merged_when_addresses_repeat_a_coin() {
        use crate::api::tests::{response, serve, utxo};
        use crate::sources::tests::coins;

        for unnamed in [false, true] {
            let own = [Template::schnorr(&[2; 32]), Template::schnorr(&[3; 32]), Template::schnorr(&[4; 32])];
            let mut u = utxo('a', 0, 50_000);
            u["spent_in_mempool"] = serde_json::json!(true);
            u["spent_by"] = serde_json::json!("1".repeat(64));
            let replies = vec![response(200, &coins(vec![u])); 2];
            let (a, first) = serve(replies.clone());
            let (b, second) = serve(replies);
            let sources = Sources::new(a, b);
            let mut coins = Coins { pending: vec![coin('a', 50_000)], ..Coins::default() };
            if unnamed {
                coins.unnamed_spenders.insert(coin('a', 0).outpoint());
            } else {
                coins.spent_by.insert(coin('a', 0).outpoint(), HashSet::from(["9".repeat(64)]));
            }
            let pending = tauri::async_runtime::block_on(pending_everywhere(&sources, &coins, &own, &own[0].address, None, &mut Flags::default())).unwrap();
            let expected = if unnamed { HashSet::from(["1".repeat(64)]) } else { HashSet::from(["1".repeat(64), "9".repeat(64)]) };
            assert_eq!(pending.spent_by[&coin('a', 0).outpoint()], expected);
            assert_eq!(pending.unnamed_spenders.contains(&coin('a', 0).outpoint()), unnamed);
            assert!(earlier_payments(&[paid('1', "mempool", "schnorr", &['a'])], "schnorr", &[], &pending).unrecorded);
            assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (2, 2));
        }
    }

    #[test]
    fn proven_inputs_do_not_warn_or_block_a_drill_when_sources_lag() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;

        for unnamed in [false, true] {
            let mut state = test_state("proven-pending-input");
            state.open_session(&Secret::new_bip39().unwrap(), state.generation(), true).unwrap();
            store::save(&state.sent_path(), &vec![
                Sent { confirmations: REQUIRED_BLOCKS, proof_verified: true, ..paid('1', "confirmed", "mixed", &['a']) },
                paid('2', "replaced", "mixed", &['a', 'd']),
            ]).unwrap();
            let mut a = utxo('a', 0, 50_000);
            a["spent_in_mempool"] = serde_json::json!(true);
            if !unnamed { a["spent_by"] = serde_json::json!("9".repeat(64)); }
            let replies = |lagging| {
                let mut replies = Vec::new();
                for _ in 0..2 {
                    let mut utxos = vec![utxo('c', 0, 150_000_000)];
                    if lagging { utxos.push(a.clone()); }
                    replies.extend([
                        response(200, &chain_state(40_000, false).to_string()),
                        response(200, &coins(utxos)),
                        response(200, &coins(vec![])), response(200, &coins(vec![])),
                    ]);
                }
                replies
            };
            let mut left = replies(true);
            left.push(response(200, r#"{"allowed":true,"vsize":100,"fee":200}"#));
            let (a, first) = serve(left);
            let (b, second) = serve(replies(false));
            state.sources = Arc::new(Sources::new(a, b));
            let to = state.templates().unwrap().2.address;
            tauri::async_runtime::block_on(async {
                let view = plan_payment(&state, Kind::Mixed, to, "0.0001".into()).await.unwrap();
                assert!(!view.unrecorded && !view.went_out && !view.unclear_elsewhere);
                assert!(view.sources_disagree);
                assert!(!guard(&state.pending).as_ref().unwrap().caution);
                let result = run_drill(&state, Path::Schnorr, Some("en"), |_| std::future::ready(true)).await.unwrap();
                assert!(matches!(result.verdict, CheckResult::Allowed { .. }));
            });
            let sent: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
            assert_eq!(sent.len(), 3);
            assert_eq!(sent[0].outpoints, vec![coin('c', 0).outpoint()]);
            assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (9, 8));
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn legacy_doubt_is_restored_before_the_first_mempool_lookup() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;

        let mut state = test_state("legacy-doubt");
        state.open_session(&Secret::new_bip39().unwrap(), state.generation(), true).unwrap();
        let mut old = serde_json::to_value(vec![paid('1', "unknown", "schnorr", &['a']), paid('2', "rejected", "schnorr", &['b'])]).unwrap();
        for s in old.as_array_mut().unwrap() { s.as_object_mut().unwrap().remove("doubted"); }
        store::write_atomic(&state.sent_path(), &serde_json::to_vec(&old).unwrap()).unwrap();
        let replies = vec![
            response(200, &chain_state(40_000, false).to_string()),
            response(200, &coins(vec![utxo('c', 0, 90_000)])),
            response(200, r#"{"status":"mempool"}"#), response(200, r#"{"status":"mempool"}"#),
            response(200, &coins(vec![])), response(200, &coins(vec![])),
        ];
        let (a, first) = serve(replies.clone());
        let (b, second) = serve(replies);
        state.sources = Arc::new(Sources::new(a, b));
        let to = state.templates().unwrap().0.address;
        let view = tauri::async_runtime::block_on(plan_payment(&state, Kind::Schnorr, to, "0.0001".into())).unwrap();
        assert!(view.went_out && !view.unclear_elsewhere && !view.unrecorded);
        assert!(guard(&state.pending).as_ref().unwrap().caution);
        let saved: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
        assert_eq!(saved.len(), 2);
        assert!(saved.iter().all(|s| s.status == "mempool" && s.doubted));
        for status in ["unknown", "rejected", "failed", "replaced"] {
            let mut s = paid('3', status, "schnorr", &['d']);
            assert!(prepare_record(&mut s));
            assert!(s.doubted);
            assert!(!prepare_record(&mut s));
        }
        assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (6, 6));
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn a_proven_payment_releases_every_conflicting_attempt() {
        for status in ["mempool", "confirmed"] {
            let mut sent = [
                Sent { confirmations: REQUIRED_BLOCKS, proof_verified: true, ..paid('1', "confirmed", "schnorr", &['a', 'b']) },
                Sent { doubted: true, confirmations: if status == "confirmed" { 4 } else { 0 }, ..paid('2', status, "schnorr", &['a', 'd']) },
                paid('3', "rejected", "schnorr", &['a']),
                paid('4', "submitting", "schnorr", &['a']),
            ];
            mark_replaced(&mut sent);
            assert!(sent[0].proven());
            assert_eq!(sent[1].status, "replaced");
            assert!(sent[1].doubted);
            assert_eq!(sent[2].status, "rejected");
            assert_eq!(sent[3].status, "submitting");
            assert!(!surfaced(&sent));
            let earlier = earlier_payments(&sent, "schnorr", &[coin('d', 70_000)], &PendingCoins::default());
            assert_eq!(earlier.usable, vec![coin('d', 70_000)]);
            assert!(earlier.required.is_empty() && earlier.replaces.is_empty());
            assert!(!earlier.spent && !earlier.elsewhere && !earlier.unrecorded);
        }
    }

    #[test]
    fn lookup_batches_favor_unlooked_up_records_and_uncovered_refusals_stay_due() {
        use crate::api::tests::{response, serve};

        let mut state = test_state("lookup-batches");
        let mut records: Vec<_> = (1..=25).map(|i| Sent {
            txid: format!("{i:064x}"), outpoints: vec![format!("{i:064x}:0")],
            ..record('1', if i % 2 == 0 { "rejected" } else { "failed" })
        }).collect();
        records.extend([
            paid('e', "rejected", "schnorr", &['f']),
            Sent { confirmations: REQUIRED_BLOCKS, proof_verified: true, ..paid('f', "confirmed", "schnorr", &['f']) },
        ]);
        assert!(records.iter().all(|s| !recent(s, now())));
        store::save(&state.sent_path(), &records).unwrap();
        let replies = vec![response(200, r#"{"status":"unknown"}"#); 40];
        let (a, first) = serve(replies.clone());
        let (b, second) = serve(replies);
        state.sources = Arc::new(Sources::new(a, b));
        tauri::async_runtime::block_on(async {
            for _ in 0..2 { refresh_sent(&state, state.generation(), |_| false, &mut Flags::default()).await; }
        });
        let requests = first.join().unwrap();
        let peer_requests = second.join().unwrap();
        assert_eq!(peer_requests.iter().map(|r| r.lines().next().unwrap()).collect::<Vec<_>>(), requests.iter().map(|r| r.lines().next().unwrap()).collect::<Vec<_>>());
        assert_eq!(requests.len(), 40);
        for (request, s) in requests[..20].iter().zip(&records[..20]) {
            assert!(request.starts_with(&format!("GET /api/tx?txid={} ", s.txid)));
        }
        assert!(requests[20].starts_with(&format!("GET /api/tx?txid={} ", records[20].txid)));
        let queried: HashSet<_> = requests.iter().map(|r| r.lines().next().unwrap()).collect();
        assert_eq!(queried.len(), 25);
        let saved: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
        assert!(saved[..25].iter().all(|s| refused(s) && s.doubted));
        assert!(saved[26].proven());
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn two_due_records_keep_their_lookup_marks_even_when_a_lookup_fails() {
        use crate::api::tests::{response, serve};

        let mut state = test_state("lookup-budget-rotation");
        let sent = vec![paid('1', "unknown", "schnorr", &['a']), paid('2', "unknown", "schnorr", &['b'])];
        store::save(&state.sent_path(), &sent).unwrap();
        // A lookup that fails still counts as started and must not starve the next record.
        let replies = vec![response(500, "{}"), response(200, r#"{"status":"unknown"}"#)];
        let (a, first) = serve(replies.clone());
        let (b, second) = serve(replies);
        state.sources = Arc::new(Sources::new(a, b));
        tauri::async_runtime::block_on(async {
            refresh_sent(&state, state.generation(), |_| false, &mut Flags::default()).await;
            assert!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap().iter().all(|s| s.lookup_mark == 0));
            let at = Instant::now();
            let mut ticks = [at, at + LOOKUP_BUDGET + Duration::from_secs(1)].into_iter();
            refresh_sent_with_clock(&state, state.generation(), |_| true, &mut Flags::default(), || ticks.next().unwrap()).await;
            assert!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap().iter().all(|s| s.lookup_mark == 0));
            for started in 1..=2 {
                let at = Instant::now();
                // The first lookup consumes the whole budget without a wall-clock delay in the test.
                let mut ticks = [at, at, at + LOOKUP_BUDGET + Duration::from_secs(1)].into_iter();
                refresh_sent_with_clock(&state, state.generation(), |_| true, &mut Flags::default(), || ticks.next().unwrap()).await;
                let saved: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
                assert_eq!(saved.iter().map(|s| s.lookup_mark).collect::<Vec<_>>(), if started == 1 { vec![1, 0] } else { vec![1, 2] });
                assert!(guard(&state.sent_lookups).is_empty());
            }
        });
        let requests = first.join().unwrap();
        let peer_requests = second.join().unwrap();
        assert_eq!((requests.len(), peer_requests.len()), (2, 2));
        for requests in [&requests, &peer_requests] {
            for (request, s) in requests.iter().zip(&sent) {
                assert!(request.starts_with(&format!("GET /api/tx?txid={} ", s.txid)));
            }
        }
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn forty_due_records_are_all_looked_up_within_two_refreshes() {
        use crate::api::tests::{response, serve};

        let mut state = test_state("lookup-forty");
        let records: Vec<_> = (1..=40).map(|i| Sent {
            txid: format!("{i:064x}"), outpoints: vec![format!("{i:064x}:0")], ..record('1', "unknown")
        }).collect();
        store::save(&state.sent_path(), &records).unwrap();
        let replies = vec![response(200, r#"{"status":"unknown"}"#); 40];
        let (a, first) = serve(replies.clone());
        let (b, second) = serve(replies);
        state.sources = Arc::new(Sources::new(a, b));
        tauri::async_runtime::block_on(async {
            let at = Instant::now();
            for round in 1..=2 {
                let sent = refresh_sent_with_clock(&state, state.generation(), |_| true, &mut Flags::default(), || at).await;
                assert_eq!(sent.iter().filter(|s| s.lookup_mark > 0).count(), round * 20);
            }
        });
        for requests in [first.join().unwrap(), second.join().unwrap()] {
            assert_eq!(requests.len(), 40);
            for (request, s) in requests.iter().zip(&records) {
                assert!(request.starts_with(&format!("GET /api/tx?txid={} ", s.txid)));
            }
        }
        let saved: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
        assert_eq!(saved.iter().map(|s| s.lookup_mark).collect::<Vec<_>>(), (1..=40).collect::<Vec<_>>());
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn complete_refreshes_keep_record_order_including_equal_lookup_marks() {
        use crate::api::tests::{response, serve};

        let mut state = test_state("lookup-record-order");
        // Neither the txid nor the wall clock determines the order.
        let records: Vec<_> = ['d', 'a', 'c', 'b'].into_iter().enumerate().map(|(i, txid)| Sent {
            created: 100 - i as u64, ..record(txid, "mempool")
        }).collect();
        store::save(&state.sent_path(), &records).unwrap();
        let replies = vec![response(200, r#"{"status":"mempool"}"#); 8];
        let (a, first) = serve(replies.clone());
        let (b, second) = serve(replies);
        state.sources = Arc::new(Sources::new(a, b));
        tauri::async_runtime::block_on(async {
            let at = Instant::now();
            for round in 0..2 {
                let sent = refresh_sent_with_clock(&state, state.generation(), |_| true, &mut Flags::default(), || at).await;
                assert_eq!(sent.iter().map(|s| &s.txid).collect::<Vec<_>>(), records.iter().map(|s| &s.txid).collect::<Vec<_>>());
                assert_eq!(sent.iter().map(|s| s.lookup_mark).collect::<Vec<_>>(), (round * 4 + 1..=round * 4 + 4).collect::<Vec<_>>());
            }
        });
        for requests in [first.join().unwrap(), second.join().unwrap()] {
            assert_eq!(requests.len(), 8);
            for (request, s) in requests.iter().zip(records.iter().cycle()) {
                assert!(request.starts_with(&format!("GET /api/tx?txid={} ", s.txid)));
            }
        }
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn lookup_marks_use_compact_json_only_when_pretty_json_does_not_fit() {
        use crate::api::tests::{response, serve};

        for count in [2, 8_000] {
            let mut state = test_state("lookup-record-size");
            // Mempool payments cannot be pruned, however old they are.
            let mut records: Vec<Sent> = (0..count).map(|i| Sent {
                txid: format!("{i:064x}"), outpoints: vec![format!("{i:064x}:0")], ..record('a', "mempool")
            }).collect();
            let mut legacy = serde_json::to_value(&records).unwrap();
            for s in legacy.as_array_mut().unwrap() { s.as_object_mut().unwrap().remove("lookup_mark"); }
            let original = serde_json::to_vec_pretty(&legacy).unwrap();
            assert!(original.len() as u64 <= store::MAX_FILE_BYTES);
            assert!(serde_json::to_vec(&records).unwrap().len() as u64 <= store::MAX_FILE_BYTES);
            store::write_atomic(&state.sent_path(), &original).unwrap();
            let replies = vec![response(200, r#"{"status":"mempool"}"#); 2];
            let (a, first) = serve(replies.clone());
            let (b, second) = serve(replies);
            state.sources = Arc::new(Sources::new(a, b));
            for started in 1..=2 {
                let at = Instant::now();
                let mut ticks = [at, at, at + LOOKUP_BUDGET + Duration::from_secs(1)].into_iter();
                let sent = tauri::async_runtime::block_on(refresh_sent_with_clock(&state, state.generation(), |_| true, &mut Flags::default(), || ticks.next().unwrap()));
                records[started - 1].lookup_mark = started as u64;
                assert_eq!(sent, records);
                assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap(), records);
                let pretty = serde_json::to_vec_pretty(&records).unwrap();
                assert_eq!(pretty.len() as u64 > store::MAX_FILE_BYTES, count == 8_000);
                let expected = if count == 8_000 { serde_json::to_vec(&records).unwrap() } else { pretty };
                assert_eq!(std::fs::read(state.sent_path()).unwrap(), expected);
            }
            for requests in [first.join().unwrap(), second.join().unwrap()] {
                assert_eq!(requests.len(), 2);
                for (request, s) in requests.iter().zip(&records) {
                    assert!(request.starts_with(&format!("GET /api/tx?txid={} ", s.txid)));
                }
            }
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn lookup_order_survives_a_restart_and_older_records_load_without_marks() {
        use crate::api::tests::{response, serve};

        let mut state = test_state("lookup-restart");
        let records = vec![record('a', "mempool"), record('b', "mempool")];
        let mut legacy = serde_json::to_value(&records).unwrap();
        for s in legacy.as_array_mut().unwrap() { s.as_object_mut().unwrap().remove("lookup_mark"); }
        store::save(&state.sent_path(), &legacy).unwrap();
        let loaded: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
        assert_eq!(loaded, records);
        let replies = vec![response(200, r#"{"status":"mempool"}"#); 2];
        let (a, first) = serve(replies.clone());
        let (b, second) = serve(replies);
        let sources = Arc::new(Sources::new(a, b));
        state.sources = sources.clone();
        let at = Instant::now();
        let mut ticks = [at, at, at + LOOKUP_BUDGET + Duration::from_secs(1)].into_iter();
        let sent = tauri::async_runtime::block_on(refresh_sent_with_clock(&state, state.generation(), |_| true, &mut Flags::default(), || ticks.next().unwrap()));
        assert_eq!(sent.iter().map(|s| s.lookup_mark).collect::<Vec<_>>(), vec![1, 0]);
        let dir = state.dir.clone();
        drop(state);
        let mut state = AppState::new(dir.clone()).unwrap();
        state.sources = sources;
        let at = Instant::now();
        let mut ticks = [at, at, at + LOOKUP_BUDGET + Duration::from_secs(1)].into_iter();
        let sent = tauri::async_runtime::block_on(refresh_sent_with_clock(&state, state.generation(), |_| true, &mut Flags::default(), || ticks.next().unwrap()));
        assert_eq!(sent.iter().map(|s| s.lookup_mark).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap(), sent);
        for requests in [first.join().unwrap(), second.join().unwrap()] {
            assert_eq!(requests.len(), 2);
            for (request, s) in requests.iter().zip(&records) {
                assert!(request.starts_with(&format!("GET /api/tx?txid={} ", s.txid)));
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn overlapping_refreshes_share_work_with_both_the_budget_and_the_cap() {
        use crate::api::tests::{response, serve, serve_with};
        use std::sync::mpsc;

        for (count, same_kind) in [(4, true), (4, false), (40, true), (40, false)] {
            let mut state = test_state("lookup-overlap");
            let records: Vec<_> = (1..=count).map(|i| Sent {
                txid: format!("{i:064x}"), outpoints: vec![format!("{i:064x}:0")], ..paid('1', "unknown", "schnorr", &[])
            }).collect();
            store::save(&state.sent_path(), &records).unwrap();
            let requests_count = if count == 4 { 6 } else { 40 };
            let replies = vec![response(200, r#"{"status":"unknown"}"#); requests_count];
            let (release, wait) = mpsc::channel();
            let calls = AtomicU64::new(0);
            let (a, first) = serve_with(replies.clone(), move || {
                if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                    wait.recv_timeout(Duration::from_secs(5)).unwrap();
                }
            });
            let (b, second) = serve(replies);
            state.sources = Arc::new(Sources::new(a, b));
            tauri::async_runtime::block_on(async {
                let at = Instant::now();
                // With four records, each lookup takes eight seconds; with forty, the cap stops them.
                let ticks = [at, at, at + Duration::from_secs(8), at + Duration::from_secs(16)];
                let mut left_ticks = ticks.into_iter();
                let mut right_ticks = ticks.map(|tick| tick + Duration::from_secs(1)).into_iter();
                let mut left_flags = Flags::default();
                let mut right_flags = Flags::default();
                let mut left = Box::pin(refresh_sent_with_clock(&state, state.generation(), |_| true, &mut left_flags, || {
                    if count == 4 { left_ticks.next().unwrap() } else { at }
                }));
                poll_fn(|cx| {
                    assert!(left.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                }).await;
                let mut right = Box::pin(refresh_sent_with_clock(&state, state.generation(), |s| same_kind || s.from == "schnorr", &mut right_flags, || {
                    if count == 4 { right_ticks.next().unwrap() } else { at + Duration::from_secs(1) }
                }));
                poll_fn(|cx| {
                    assert!(right.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                }).await;
                assert_eq!(*guard(&state.sent_lookups), HashSet::from([records[0].txid.clone(), records[1].txid.clone()]));
                let saved: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
                assert_eq!(saved[..2].iter().map(|s| s.lookup_mark).collect::<Vec<_>>(), vec![1, 2]);
                assert!(saved[2..].iter().all(|s| s.lookup_mark == 0));
                release.send(()).unwrap();
                let (mut left_result, mut right_result) = (None, None);
                poll_fn(|cx| {
                    if left_result.is_none() {
                        if let Poll::Ready(sent) = left.as_mut().poll(cx) { left_result = Some(sent); }
                    }
                    if right_result.is_none() {
                        if let Poll::Ready(sent) = right.as_mut().poll(cx) { right_result = Some(sent); }
                    }
                    if left_result.is_some() && right_result.is_some() { Poll::Ready(()) } else { Poll::Pending }
                }).await;
                assert!(guard(&state.sent_lookups).is_empty());
                let saved: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
                assert!(saved.iter().all(|s| s.lookup_mark > 0));
                if count == 4 {
                    // D must be reached by the next round even when two refreshes started a second apart.
                    let mut next_ticks = ticks.into_iter();
                    refresh_sent_with_clock(&state, state.generation(), |_| true, &mut Flags::default(), || next_ticks.next().unwrap()).await;
                }
            });
            for requests in [first.join().unwrap(), second.join().unwrap()] {
                assert_eq!(requests.len(), requests_count);
                let first_round: HashSet<_> = requests[..count].iter().map(|r| r.lines().next().unwrap()).collect();
                assert_eq!(first_round.len(), count);
                assert!(requests.iter().any(|r| r.starts_with(&format!("GET /api/tx?txid={} ", records[3].txid))));
            }
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn lookup_marks_are_saved_by_txid_even_if_the_status_changed_during_a_failed_lookup() {
        use crate::api::tests::{response, serve, serve_with};
        use std::sync::mpsc;

        for failed in [false, true] {
            let mut state = test_state("lookup-changed-status");
            let records = vec![record('a', "mempool"), Sent {
                confirmations: REQUIRED_BLOCKS, proof_verified: true, lookup_mark: 40, ..record('b', "confirmed")
            }];
            store::save(&state.sent_path(), &records).unwrap();
            let reply = if failed { response(500, "{}") } else { response(200, r#"{"status":"unknown"}"#) };
            let (release, wait) = mpsc::channel();
            let (a, first) = serve_with(vec![reply.clone()], move || { wait.recv_timeout(Duration::from_secs(5)).unwrap(); });
            let (b, second) = serve(vec![reply]);
            state.sources = Arc::new(Sources::new(a, b));
            let sent = tauri::async_runtime::block_on(async {
                let at = Instant::now();
                let mut ticks = [at, at, at + LOOKUP_BUDGET + Duration::from_secs(1)].into_iter();
                let mut flags = Flags::default();
                let mut refresh = Box::pin(refresh_sent_with_clock(&state, state.generation(), |s| !s.proven(), &mut flags, || ticks.next().unwrap()));
                poll_fn(|cx| {
                    assert!(refresh.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                }).await;
                edit_sent(&state, |sent| {
                    let mut changed = sent.remove(0);
                    changed.status = "rejected".into();
                    changed.lookup_mark = 0;
                    sent.push(changed);
                }).unwrap();
                release.send(()).unwrap();
                refresh.await
            });
            assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (1, 1));
            assert_eq!(sent[0], records[1]);
            assert_eq!(sent[1].txid, records[0].txid);
            assert_eq!(sent[1].status, "rejected");
            assert_eq!(sent[1].lookup_mark, 41);
            assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap(), sent);
            assert!(guard(&state.sent_lookups).is_empty());
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn cancelling_a_refresh_releases_its_claims_and_keeps_the_start_mark() {
        use crate::api::tests::idle;

        let mut state = test_state("lookup-cancelled");
        store::save(&state.sent_path(), &vec![record('a', "mempool")]).unwrap();
        let (a, _first_socket) = idle();
        let (b, _second_socket) = idle();
        state.sources = Arc::new(Sources::new(a, b));
        tauri::async_runtime::block_on(async {
            let mut flags = Flags::default();
            let mut refresh = Box::pin(refresh_sent(&state, state.generation(), |_| true, &mut flags));
            poll_fn(|cx| {
                assert!(refresh.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            }).await;
            assert!(guard(&state.sent_lookups).contains(&"a".repeat(64)));
            drop(refresh);
            assert!(guard(&state.sent_lookups).is_empty());
        });
        assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap()[0].lookup_mark, 1);
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn payment_and_activity_lookups_share_the_order_when_each_uses_the_budget() {
        use crate::api::tests::{response, serve};
        use crate::sources::tests::synthetic_sources;

        let mut state = test_state("lookup-rule-rotation");
        let proof = proof::tests::chain(REQUIRED_BLOCKS);
        // R, A, B, S, P: P covers R and S, but neither the refusal A nor the other address's payment B.
        let mut records = vec![
            paid('1', "replaced", "schnorr", &['a']),
            paid('2', "rejected", "schnorr", &['b']),
            Sent { txid: proof["txid"].as_str().unwrap().into(), ..paid('3', "unknown", "mldsa44", &['c']) },
            paid('4', "replaced", "schnorr", &['d']),
            Sent { confirmations: REQUIRED_BLOCKS, proof_verified: true, ..paid('5', "confirmed", "schnorr", &['a', 'd']) },
        ];
        let at = now();
        for s in &mut records { s.created = at; }
        store::save(&state.sent_path(), &records).unwrap();
        assert!(earlier_payments(&records, "schnorr", &[coin('b', 50_000)], &PendingCoins::default()).elsewhere);
        // B becomes proven on the third lookup, despite the different candidate lists.
        let unknown = response(200, r#"{"status":"unknown"}"#);
        let replies = vec![unknown.clone(), unknown.clone(), response(200, r#"{"status":"confirmed","confirmations":100}"#), unknown];
        let mut left = replies.clone();
        left.insert(3, response(200, &proof.to_string()));
        let (a, first) = serve(left);
        let (b, second) = serve(replies);
        state.sources = Arc::new(synthetic_sources(a, b));
        tauri::async_runtime::block_on(async {
            for started in 1..=2 {
                let start = Instant::now();
                // Each refresh can start only one lookup, without a wall-clock delay in the test.
                let ticks = [start, start, start + LOOKUP_BUDGET + Duration::from_secs(1)];
                let mut payment_ticks = ticks.into_iter();
                let sent = refresh_sent_with_clock(&state, state.generation(), |s| {
                    matches!(s.status.as_str(), "mempool" | "unknown") || (s.status == "confirmed" && !s.proven()) || (refused(s) && recent(s, at))
                }, &mut Flags::default(), || payment_ticks.next().unwrap()).await;
                assert_eq!(sent[2].proven(), started == 2);
                assert_eq!(earlier_payments(&sent, "schnorr", &[coin('b', 50_000)], &PendingCoins::default()).elsewhere, started != 2);
                let mut activity_ticks = ticks.into_iter();
                let sent = refresh_sent_with_clock(&state, state.generation(),
                    |s| !s.proven() && (!settled(s) || recent(s, at)),
                    &mut Flags::default(), || activity_ticks.next().unwrap()).await;
                assert_eq!(sent[2].proven(), started == 2);
                assert_eq!(earlier_payments(&sent, "schnorr", &[coin('b', 50_000)], &PendingCoins::default()).elsewhere, started != 2);
            }
        });
        let requests = first.join().unwrap();
        let peer_requests = second.join().unwrap();
        assert_eq!((requests.len(), peer_requests.len()), (5, 4));
        // The shared order reaches B, clearing its warning: A, R, B, S.
        let expected = [&records[1], &records[0], &records[2], &records[3]];
        for requests in [&requests, &peer_requests] {
            for (request, s) in requests.iter().filter(|r| r.starts_with("GET /api/tx?")).zip(&expected) {
                assert!(request.starts_with(&format!("GET /api/tx?txid={} ", s.txid)));
            }
        }
        assert!(requests[3].starts_with(&format!("GET /api/proof?txid={} ", records[2].txid)));
        let saved: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
        assert!(saved[2].proven());
        assert_eq!(saved.iter().map(|s| s.lookup_mark).collect::<Vec<_>>(), vec![2, 1, 3, 4, 0]);
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn one_source_adds_its_dialog_note_without_a_payment_warning() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;

        let mut state = test_state("one-source-note");
        state.open_session(&Secret::new_bip39().unwrap(), state.generation(), true).unwrap();
        let mut replies = Vec::new();
        for _ in 0..2 {
            replies.extend([
                response(200, &chain_state(40_000, false).to_string()),
                response(200, &coins(vec![utxo('c', 0, 90_000)])),
                response(200, &coins(vec![])), response(200, &coins(vec![])),
            ]);
        }
        let mut left = replies.clone();
        left[0] = response(500, "{}");
        let (a, first) = serve(left);
        let (b, second) = serve(replies);
        state.sources = Arc::new(Sources::new(a, b));
        let to = state.templates().unwrap().0.address;
        let (view, pending, (_, coins, spending)) = tauri::async_runtime::block_on(async {
            let view = plan_payment(&state, Kind::Schnorr, to, "0.0001".into()).await.unwrap();
            let mut pending = guard(&state.pending).take().unwrap();
            assert!(!pending.caution);
            let checked = recheck_payment(&state, &state.snapshot().unwrap(), &mut pending).await.unwrap();
            (view, pending, checked)
        });
        assert!(view.one_source && pending.sources.one_source);
        assert!(!view.went_out && !view.unclear_elsewhere && !view.unrecorded && !pending.caution);
        let dialog = crate::confirm::payment("en", pending.plan.send, &pending.destination.address, pending.plan.fee, pending.plan.change, pending.caution, pending.sources);
        assert!(dialog.body().contains("only one node answered"));
        assert!(!dialog.body().contains("an earlier payment"));
        let new = Sent { outpoints: pending.plan.coins.iter().map(Coin::outpoint).collect(), ..paid('3', "submitting", "schnorr", &[]) };
        record_payment(&state, &pending, &coins, &spending, state.generation(), new).unwrap();
        assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (8, 8));
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn the_payment_note_disappears_when_the_risk_ends_before_recheck() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;

        let mut state = test_state("risk-ended");
        state.open_session(&Secret::new_bip39().unwrap(), state.generation(), true).unwrap();
        store::save(&state.sent_path(), &vec![paid('1', "unknown", "schnorr", &['a'])]).unwrap();
        let mut replies = Vec::new();
        for round in 0..2 {
            replies.extend([
                response(200, &chain_state(40_000, false).to_string()),
                response(200, &coins(vec![utxo('c', 0, 90_000)])),
            ]);
            if round == 0 { replies.push(response(200, r#"{"status":"unknown"}"#)); }
            replies.extend([response(200, &coins(vec![])), response(200, &coins(vec![]))]);
        }
        let (a, first) = serve(replies.clone());
        let (b, second) = serve(replies);
        state.sources = Arc::new(Sources::new(a, b));
        let to = state.templates().unwrap().0.address;
        tauri::async_runtime::block_on(async {
            let view = plan_payment(&state, Kind::Schnorr, to, "0.0001".into()).await.unwrap();
            let mut pending = guard(&state.pending).take().unwrap();
            assert!(view.went_out && pending.caution);
            edit_sent(&state, |sent| {
                sent[0].status = "confirmed".into();
                sent[0].confirmations = REQUIRED_BLOCKS;
                sent[0].proof_verified = true;
            }).unwrap();
            let (_, coins, spending) = recheck_payment(&state, &state.snapshot().unwrap(), &mut pending).await.unwrap();
            assert!(!pending.caution);
            let dialog = crate::confirm::payment("en", pending.plan.send, &pending.destination.address, pending.plan.fee, pending.plan.change, pending.caution, pending.sources);
            assert!(!dialog.body().contains("an earlier payment"));
            let new = Sent { outpoints: pending.plan.coins.iter().map(Coin::outpoint).collect(), ..paid('3', "submitting", "schnorr", &[]) };
            record_payment(&state, &pending, &coins, &spending, state.generation(), new).unwrap();
        });
        assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (9, 9));
        std::fs::remove_dir_all(&state.dir).unwrap();
    }

    #[test]
    fn a_risk_appearing_at_recheck_needs_the_dialog_warning() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;

        for during_dialog in [false, true] {
            let mut state = test_state("risk-appeared");
            state.open_session(&Secret::new_bip39().unwrap(), state.generation(), true).unwrap();
            let mut replies = Vec::new();
            for round in 0..2 {
                replies.extend([
                    response(200, &chain_state(40_000, false).to_string()),
                    response(200, &coins(vec![utxo('c', 0, 90_000)])),
                ]);
                if round == 1 && !during_dialog { replies.push(response(200, r#"{"status":"mempool"}"#)); }
                replies.extend([response(200, &coins(vec![])), response(200, &coins(vec![]))]);
            }
            let (a, first) = serve(replies.clone());
            let (b, second) = serve(replies);
            state.sources = Arc::new(Sources::new(a, b));
            let to = state.templates().unwrap().0.address;
            tauri::async_runtime::block_on(async {
                let view = plan_payment(&state, Kind::Schnorr, to, "0.0001".into()).await.unwrap();
                let mut pending = guard(&state.pending).take().unwrap();
                assert!(!view.went_out && !pending.caution);
                let old = paid('1', "unknown", "schnorr", &['a']);
                if !during_dialog { store::save(&state.sent_path(), &vec![old.clone()]).unwrap(); }
                let (_, coins, spending) = recheck_payment(&state, &state.snapshot().unwrap(), &mut pending).await.unwrap();
                assert_eq!(pending.caution, !during_dialog);
                let dialog = crate::confirm::payment("en", pending.plan.send, &pending.destination.address, pending.plan.fee, pending.plan.change, pending.caution, pending.sources);
                assert_eq!(dialog.body().contains("an earlier payment"), !during_dialog);
                if during_dialog { store::save(&state.sent_path(), &vec![old]).unwrap(); }
                let new = Sent { outpoints: pending.plan.coins.iter().map(Coin::outpoint).collect(), ..paid('3', "submitting", "schnorr", &[]) };
                pending.caution = false;
                assert_eq!(record_payment(&state, &pending, &coins, &spending, state.generation(), new.clone()).unwrap_err().code, "coins_changed");
                if !during_dialog {
                    pending.caution = true;
                    record_payment(&state, &pending, &coins, &spending, state.generation(), new).unwrap();
                }
            });
            let count = if during_dialog { 8 } else { 9 };
            assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (count, count));
            std::fs::remove_dir_all(&state.dir).unwrap();
        }
    }

    #[test]
    fn a_chain_of_retries_warns_when_one_is_in_the_mempool() {
        let sent = [
            paid('1', "unknown", "schnorr", &['a', 'b']),
            Sent { doubted: true, ..paid('2', "unknown", "schnorr", &['a', 'd']) },
            paid('3', "mempool", "schnorr", &['b', 'd']),
        ];
        let earlier = earlier_payments(&sent, "schnorr", &[coin('a', 50_000), coin('b', 60_000), coin('c', 90_000), coin('d', 70_000)], &PendingCoins::default());
        assert!(earlier.spent && !surfaced(&sent));
        assert_eq!(earlier.required, vec![coin('a', 50_000)]);
        assert_eq!(earlier.replaces, vec![sent[0].txid.clone(), sent[1].txid.clone()]);
    }

    #[test]
    fn a_refused_original_warns_when_a_retry_is_in_the_mempool() {
        let sent = [
            paid('1', "rejected", "schnorr", &['a', 'b']),
            paid('2', "mempool", "schnorr", &['a', 'd']),
        ];
        let earlier = earlier_payments(&sent, "schnorr", &[coin('a', 50_000), coin('b', 60_000), coin('c', 90_000)], &PendingCoins::default());
        assert!(earlier.spent);
        assert_eq!(earlier.required, vec![coin('b', 60_000)]);
        assert_eq!(earlier.replaces, vec![sent[0].txid.clone()]);
    }

    #[test]
    fn a_retry_warns_in_review_and_confirmation_until_either_payment_is_proven() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;
        use serde_json::json;

        for retry_status in ["mempool", "confirmed"] {
            for winner in 0..2 {
                let mut nonce = [0; 8];
                getrandom::fill(&mut nonce).unwrap();
                let dir = std::env::temp_dir().join(format!("pqw-retry-settlement-{}", hex::encode(nonce)));
                let mut state = AppState::new(dir.clone()).unwrap();
                *guard(&state.session) = Some(Session::new(&Secret::new_bip39().unwrap()).unwrap());
                let original = Sent { doubted: true, ..paid('1', "unknown", "schnorr", &['a']) };
                let retry = Sent { confirmations: if retry_status == "confirmed" { 4 } else { 0 },
                    ..paid('2', retry_status, "schnorr", &['a']) };
                store::save(&state.sent_path(), &vec![original, retry]).unwrap();
                let mut replies = Vec::new();
                // Review and confirmation recheck, while B has no verified settlement.
                for _ in 0..2 {
                    replies.extend([
                        response(200, &chain_state(40_000, false).to_string()),
                        response(200, &coins(vec![utxo('b', 0, 90_000)])),
                        response(200, r#"{"status":"unknown"}"#),
                        response(200, &json!({"status": retry_status, "confirmations": 4}).to_string()),
                        response(200, &coins(vec![])), response(200, &coins(vec![])),
                    ]);
                }
                // Once either A or B is proven, neither needs another lookup while planning C.
                replies.extend([
                    response(200, &chain_state(40_000, false).to_string()),
                    response(200, &coins(vec![utxo('b', 0, 90_000)])),
                    response(200, &coins(vec![])), response(200, &coins(vec![])),
                ]);
                let (a, first) = serve(replies.clone());
                let (b, second) = serve(replies);
                state.sources = Arc::new(Sources::new(a, b));
                let to = state.templates().unwrap().0.address;
                let (view, mut pending, (_, coins, spending)) = tauri::async_runtime::block_on(async {
                    let view = plan_payment(&state, Kind::Schnorr, to.clone(), "0.0001".into()).await.unwrap();
                    let mut pending = guard(&state.pending).take().unwrap();
                    let checked = recheck_payment(&state, &state.snapshot().unwrap(), &mut pending).await.unwrap();
                    (view, pending, checked)
                });
                assert!(view.went_out && pending.caution);
                assert_eq!(view.replaces, 0);
                assert!(!view.unclear_elsewhere && !view.unrecorded && !view.one_source && !view.sources_disagree);
                assert_eq!(pending.plan.coins, vec![Coin { height: 10, ..coin('b', 90_000) }]);
                // The record guard also refuses this independent payment without the dialog's warning.
                pending.caution = false;
                let new = Sent { outpoints: pending.plan.coins.iter().map(Coin::outpoint).collect(),
                    ..paid('3', "submitting", "schnorr", &[]) };
                assert_eq!(record_payment(&state, &pending, &coins, &spending, state.generation(), new).unwrap_err().code, "coins_changed");
                edit_sent(&state, |sent| {
                    assert_eq!(sent[0].status, "unknown");
                    assert!(sent[0].doubted && !settled(&sent[0]));
                    // The other transaction loses the race, even when the original A is mined first.
                    sent[1 - winner].status = "unknown".into();
                    sent[winner].status = "confirmed".into();
                    sent[winner].confirmations = REQUIRED_BLOCKS;
                    sent[winner].proof_verified = true;
                    mark_replaced(sent);
                    assert!(sent[winner].proven());
                    assert_eq!(sent[1 - winner].status, "replaced");
                    assert!(settled(&sent[1 - winner]));
                    assert!(sent[0].doubted);
                }).unwrap();
                let free = tauri::async_runtime::block_on(plan_payment(&state, Kind::Schnorr, to, "0.0001".into())).unwrap();
                assert_eq!(free.replaces, 0);
                assert!(!free.went_out && !free.unclear_elsewhere && !free.unrecorded);
                assert!(!guard(&state.pending).as_ref().unwrap().caution);
                assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (16, 16));
                drop(state);
                std::fs::remove_dir_all(dir).unwrap();
            }
        }
    }

    /// A payment the app stopped in the middle of sending is unknown once it starts again.
    #[test]
    fn a_send_cut_short_is_unknown_after_a_restart() {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-app-test-{}", hex::encode(nonce)));
        store::save(&dir.join("sent.json"), &vec![record('a', "submitting"), record('b', "mempool")]).unwrap();
        let state = AppState::new(dir.clone()).unwrap();
        let sent: Vec<Sent> = store::load(&state.sent_path());
        assert_eq!(sent.iter().map(|s| s.status.as_str()).collect::<Vec<_>>(), ["unknown", "mempool"]);
        assert_eq!(sent[0].outpoints, record('a', "unknown").outpoints);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_restores_legacy_replaced_records_without_a_proven_cover() {
        for proven in [false, true] {
            let mut nonce = [0; 8];
            getrandom::fill(&mut nonce).unwrap();
            let dir = std::env::temp_dir().join(format!("pqw-replaced-restart-{}", hex::encode(nonce)));
            let original = paid('1', "replaced", "schnorr", &['a']);
            let retry = Sent { confirmations: if proven { REQUIRED_BLOCKS } else { 0 }, proof_verified: proven,
                ..paid('2', if proven { "confirmed" } else { "mempool" }, "schnorr", &['a']) };
            let mut legacy = serde_json::to_value(vec![original, retry]).unwrap();
            legacy[0].as_object_mut().unwrap().remove("proof_verified");
            legacy[0].as_object_mut().unwrap().remove("doubted");
            store::save(&dir.join("sent.json"), &legacy).unwrap();
            let state = AppState::new(dir.clone()).unwrap();
            let sent: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
            assert_eq!(sent[0].status, if proven { "replaced" } else { "unknown" });
            assert_eq!(settled(&sent[0]), proven);
            assert!(sent[0].doubted);
            let earlier = earlier_payments(&sent, "schnorr", &[coin('b', 90_000)], &PendingCoins::default());
            assert_eq!(earlier.spent, !proven);
            drop(state);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn wallet_lock_child_process() {
        let Some(dir) = std::env::var_os("PQW_LOCK_TEST_DIR") else { return };
        let result = AppState::new(PathBuf::from(dir));
        if std::env::var_os("PQW_LOCK_TEST_HELD").is_some() {
            assert!(matches!(result, Err(std::fs::TryLockError::WouldBlock)));
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn a_second_process_cannot_read_or_migrate_the_wallet_until_the_first_exits() {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-process-lock-{}", hex::encode(nonce)));
        let state = AppState::new(dir.clone()).unwrap();
        let original = serde_json::to_vec_pretty(&vec![record('a', "submitting")]).unwrap();
        store::write_atomic(&state.sent_path(), &original).unwrap();
        let child = |held| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", "app::tests::wallet_lock_child_process", "--nocapture"])
                .env("PQW_LOCK_TEST_DIR", &dir).env_remove("PQW_LOCK_TEST_HELD");
            if held { command.env("PQW_LOCK_TEST_HELD", "1"); }
            assert!(command.status().unwrap().success());
        };
        child(true);
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), original);
        assert!(matches!(AppState::new(dir.clone()), Err(std::fs::TryLockError::WouldBlock)));
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), original);
        drop(state);
        child(false);
        let reopened = AppState::new(dir.clone()).unwrap();
        let sent: Vec<Sent> = store::load_existing(&reopened.sent_path()).unwrap();
        assert_eq!(sent[0].status, "unknown");
        assert!(sent[0].doubted);
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_confirmations_are_rechecked_and_only_six_proven_blocks_settle() {
        for count in 1..=REQUIRED_BLOCKS {
            let verified = proof::tests::synthetic_count(count);
            let (status, proof_verified) = confirmed_status(100, verified);
            let TxStatus::Confirmed { confirmations } = status else { panic!("confirmed") };
            let s = Sent { confirmations, proof_verified, doubted: true, ..record('a', "confirmed") };
            assert_eq!(s.confirmations, if count == 6 { 100 } else { 5 });
            assert_eq!(s.proven(), count == 6);
            assert_eq!(surfaced(&[s]), count < 6);
        }
        let mut old = serde_json::to_value(Sent { confirmations: 100, ..record('a', "confirmed") }).unwrap();
        old.as_object_mut().unwrap().remove("proof_verified");
        let mut s: Sent = serde_json::from_value(old).unwrap();
        assert!(!s.proven());
        assert!(prepare_record(&mut s));
        assert_eq!(s.confirmations, 5);
        assert_eq!(s.status, "confirmed");
        assert!(s.doubted);
        assert_eq!(s.outpoints, record('a', "confirmed").outpoints);
        assert!(!prepare_record(&mut s));
        let mut proven = Sent { confirmations: 100, proof_verified: true, ..record('b', "confirmed") };
        assert!(!prepare_record(&mut proven));
        assert!(proven.proven());
        let mut submitting = record('c', "submitting");
        assert!(!prepare_record(&mut submitting));
        assert_eq!(submitting.status, "submitting");
    }

    #[test]
    fn unproven_records_are_never_pruned_as_final() {
        let mut sent: Vec<Sent> = (0..6000).map(|i| Sent {
            txid: format!("{i:064x}"), confirmations: 100, outpoints: vec![format!("{i:064x}:0")],
            ..record('a', "confirmed")
        }).collect();
        sent.push(Sent { outpoints: sent[0].outpoints.clone(), ..record('b', "unknown") });
        sent.push(Sent { outpoints: sent[0].outpoints.clone(), ..record('c', "rejected") });
        prune(&mut sent, 100_000_000);
        assert_eq!(sent.len(), 6002);
        assert_eq!(sent[6000].status, "unknown");
        assert_eq!(sent[6001].status, "rejected");
    }

    #[test]
    fn a_failed_proof_makes_a_previously_undoubted_payment_unclear() {
        use crate::api::tests::{response, serve};
        let confirmed = r#"{"status":"confirmed","confirmations":100}"#;
        let (api, first) = serve(vec![response(200, confirmed), response(200, "{}")]);
        let (peer, second) = serve(vec![response(200, confirmed), response(404, r#"{"error":"not_found"}"#)]);
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-failed-proof-{}", hex::encode(nonce)));
        let mut state = AppState::new(dir.clone()).unwrap();
        state.sources = Arc::new(Sources::new(api, peer));
        let old = paid('1', "mempool", "mldsa44", &['a']);
        store::save(&state.sent_path(), &vec![old.clone()]).unwrap();
        let sent = tauri::async_runtime::block_on(refresh_sent(&state, state.generation(), |_| true, &mut Flags::default()));
        assert_eq!((first.join().unwrap().len(), second.join().unwrap().len()), (2, 2));
        assert_eq!(sent[0].status, "confirmed");
        assert_eq!(sent[0].confirmations, 5);
        assert_eq!(sent[0].outpoints, old.outpoints);
        assert!(sent[0].doubted && !sent[0].proof_verified);
        assert!(surfaced(&sent));
        let e = earlier_payments(&sent, "mldsa44", &[coin('a', 5_000), coin('b', 90_000)], &PendingCoins::default());
        assert_eq!(e.required, vec![coin('a', 5_000)]);
        assert_eq!(store::load::<Vec<Sent>>(&state.sent_path()), sent);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refresh_uses_a_longer_peer_proof_and_keeps_protection_when_both_are_short() {
        use crate::api::tests::{response, serve};
        use crate::sources::tests::synthetic_sources;
        use serde_json::json;

        let full = proof::tests::chain(REQUIRED_BLOCKS);
        let txid = full["txid"].as_str().unwrap();
        let mut short = full.clone();
        short["tip"] = short["height"].clone();
        short["blocks"].as_array_mut().unwrap().truncate(1);
        let confirmed = r#"{"status":"confirmed","confirmations":100}"#;
        for count in [REQUIRED_BLOCKS, REQUIRED_BLOCKS - 1] {
            let mut peer_proof = full.clone();
            peer_proof["tip"] = json!(peer_proof["height"].as_u64().unwrap() + u64::from(count) - 1);
            peer_proof["blocks"].as_array_mut().unwrap().truncate(count as usize);
            let (api, first) = serve(vec![response(200, confirmed), response(200, &short.to_string())]);
            let (peer, second) = serve(vec![response(200, confirmed), response(200, &peer_proof.to_string())]);
            let mut nonce = [0; 8];
            getrandom::fill(&mut nonce).unwrap();
            let dir = std::env::temp_dir().join(format!("pqw-peer-proof-{}", hex::encode(nonce)));
            let mut state = AppState::new(dir.clone()).unwrap();
            state.sources = Arc::new(synthetic_sources(api, peer));
            let old = Sent { txid: txid.into(), doubted: true, ..paid('1', "mempool", "mldsa44", &['a']) };
            store::save(&state.sent_path(), &vec![old.clone()]).unwrap();
            let mut flags = Flags::default();
            let sent = tauri::async_runtime::block_on(refresh_sent(&state, state.generation(), |_| true, &mut flags));
            let first = first.join().unwrap();
            let second = second.join().unwrap();
            assert_eq!((first.len(), second.len()), (2, 2));
            assert!(first[1].starts_with("GET /api/proof?"));
            assert!(second[1].starts_with("GET /api/proof?"));
            assert_eq!(flags, Flags { one_source: true, disagree: false });
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].status, "confirmed");
            assert_eq!(sent[0].outpoints, old.outpoints);
            let proven = count == REQUIRED_BLOCKS;
            assert_eq!(sent[0].confirmations, if proven { 100 } else { 5 });
            assert_eq!(sent[0].proof_verified, proven);
            assert_eq!(sent[0].proven(), proven);
            assert_eq!(surfaced(&sent), !proven);
            let e = earlier_payments(&sent, "mldsa44", &[coin('a', 5_000), coin('b', 90_000)], &PendingCoins::default());
            assert_eq!(e.required, if proven { vec![] } else { vec![coin('a', 5_000)] });
            assert_eq!(e.replaces, if proven { vec![] } else { vec![txid.to_string()] });
            assert_eq!(store::load::<Vec<Sent>>(&state.sent_path()), sent);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn refresh_keeps_the_record_on_bad_or_missing_proofs_and_caps_short_proofs() {
        use crate::api::tests::{response, serve};
        let proof = proof::tests::real_proof();
        let txid = proof["txid"].as_str().unwrap().to_string();
        let confirmed = r#"{"status":"confirmed","confirmations":100}"#;
        let mut bad = proof.clone();
        bad["blocks"][0]["coinbase_branch"] = serde_json::json!(["ab".repeat(32)]);
        let (api, server) = serve(vec![
            response(200, confirmed), response(200, &proof.to_string()),
            response(200, confirmed), response(200, &bad.to_string()),
            response(200, confirmed), response(404, r#"{"error":"not_confirmed"}"#),
            response(200, confirmed), response(404, r#"{"error":"not_found"}"#),
            response(200, r#"{"status":"mempool"}"#),
            response(200, r#"{"status":"confirmed","confirmations":4}"#),
        ]);
        let (peer, other) = serve(vec![
            response(200, confirmed), response(404, r#"{"error":"not_confirmed"}"#),
            response(200, confirmed), response(404, r#"{"error":"not_confirmed"}"#),
            response(200, confirmed), response(404, r#"{"error":"not_confirmed"}"#),
            response(200, confirmed), response(404, r#"{"error":"not_found"}"#),
            response(200, r#"{"status":"mempool"}"#),
            response(200, r#"{"status":"confirmed","confirmations":4}"#),
        ]);
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-proof-test-{}", hex::encode(nonce)));
        let mut state = AppState::new(dir.clone()).unwrap();
        state.sources = Arc::new(Sources::new(api, peer));
        store::save(&state.sent_path(), &vec![Sent { txid: txid.clone(), doubted: true, ..record('a', "unknown") }]).unwrap();
        let results = tauri::async_runtime::block_on(async {
            let mut results = Vec::new();
            for _ in 0..6 { results.push(refresh_sent(&state, state.generation(), |_| true, &mut Flags::default()).await); }
            results
        });
        let requests = server.join().unwrap();
        assert_eq!(other.join().unwrap().len(), 10);
        assert_eq!(requests.len(), 10);
        assert_eq!(results[0][0].status, "confirmed");
        assert_eq!(results[0][0].confirmations, 5);
        assert!(!results[0][0].proof_verified);
        assert!(surfaced(&results[0]));
        // Each refresh starts one more lookup; apart from its mark the record stays as it was.
        let unmarked = |sent: &[Sent]| sent.iter().map(|s| Sent { lookup_mark: 0, ..s.clone() }).collect::<Vec<_>>();
        for (i, result) in results.iter().enumerate() { assert_eq!(result[0].lookup_mark, i as u64 + 1); }
        for result in &results[1..4] { assert_eq!(unmarked(result), unmarked(&results[0])); }
        assert_eq!(results[4][0].status, "mempool");
        assert_eq!(results[4][0].confirmations, 0);
        assert_eq!(results[5][0].status, "confirmed");
        assert_eq!(results[5][0].confirmations, 4);
        assert!(!results[5][0].proof_verified);
        let saved: Vec<Sent> = store::load(&state.sent_path());
        assert_eq!(saved, results[5]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restart_caps_old_records_but_preserves_verified_ones() {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-proof-restart-{}", hex::encode(nonce)));
        let records = vec![
            Sent { confirmations: 100, ..record('a', "confirmed") },
            Sent { confirmations: 100, proof_verified: true, ..record('b', "confirmed") },
        ];
        store::save(&dir.join("sent.json"), &records).unwrap();
        let state = AppState::new(dir.clone()).unwrap();
        let saved: Vec<Sent> = store::load(&state.sent_path());
        assert_eq!(saved[0].confirmations, 5);
        assert!(!saved[0].proven());
        assert!(saved[0].doubted);
        assert_eq!(saved[0].status, "confirmed");
        assert_eq!(saved[0].outpoints, records[0].outpoints);
        assert!(saved[1].proven());
        assert_eq!(saved[1].confirmations, 100);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn startup_migration_prunes_only_records_settled_by_verified_proofs() {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-pruned-migration-{}", hex::encode(nonce)));
        let mut records: Vec<Sent> = (0..6000).map(|i| Sent {
            txid: format!("{i:064x}"), confirmations: 100, proof_verified: true,
            outpoints: vec![format!("{i:064x}:0")], ..record('a', "confirmed")
        }).collect();
        records[0].proof_verified = false;
        let bytes = serde_json::to_vec_pretty(&records).unwrap();
        assert!(bytes.len() > PRUNE_ABOVE_BYTES && bytes.len() as u64 <= store::MAX_FILE_BYTES);
        store::write_atomic(&dir.join("sent.json"), &bytes).unwrap();
        let state = AppState::new(dir.clone()).unwrap();
        let saved: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
        assert!(std::fs::metadata(state.sent_path()).unwrap().len() <= PRUNE_ABOVE_BYTES as u64);
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), serde_json::to_vec_pretty(&saved).unwrap());
        assert!(saved.len() < records.len());
        let unproven = saved.iter().find(|s| s.txid == records[0].txid).unwrap();
        assert!(unproven.doubted && !unproven.proven());
        assert_eq!(unproven.outpoints, records[0].outpoints);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_migration_that_cannot_fit_preserves_the_readable_original() {
        let mut old = serde_json::to_value(Sent { confirmations: 100, ..record('a', "confirmed") }).unwrap();
        old.as_object_mut().unwrap().remove("proof_verified");
        let one = serde_json::to_vec(&vec![old.clone()]).unwrap().len();
        let count = (store::MAX_FILE_BYTES as usize - 1) / (one - 1);
        let original = serde_json::to_vec(&vec![old; count]).unwrap();
        assert!(original.len() as u64 <= store::MAX_FILE_BYTES);
        let mut migrated: Vec<Sent> = serde_json::from_slice(&original).unwrap();
        for s in &mut migrated { prepare_record(s); }
        assert!(serde_json::to_vec_pretty(&migrated).unwrap().len() as u64 > store::MAX_FILE_BYTES);
        assert!(serde_json::to_vec(&migrated).unwrap().len() as u64 > store::MAX_FILE_BYTES);
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-full-migration-{}", hex::encode(nonce)));
        store::write_atomic(&dir.join("sent.json"), &original).unwrap();
        let state = AppState::new(dir.clone()).unwrap();
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), original);
        assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap().len(), count);
        assert_eq!(edit_sent(&state, |_| ()).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        // When the record cannot be written, the fallback read must still restore the protection in memory.
        let view = tauri::async_runtime::block_on(refresh_sent(&state, state.generation(), |_| false, &mut Flags::default()));
        assert_eq!(view, migrated);
        assert!(surfaced(&view));
        assert_eq!(earlier_payments(&view, "mldsa44", &[coin('a', 5_000)], &PendingCoins::default()).required, vec![coin('a', 5_000)]);
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), original);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn every_payment_lookup_carries_its_flags_through_review_recheck_and_recording() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;
        use serde_json::json;

        // Fail one query of the plan or of the recheck at a time, so that no other warning covers for it.
        for fault_round in 0..2 {
            for operation in 0..5 {
                for one_source in [false, true] {
                    let mut left = Vec::new();
                    let mut right = Vec::new();
                    for round in 0..2 {
                        for step in 0..5 {
                            let body = match step {
                                0 => chain_state(40_000, false).to_string(),
                                1 => coins(vec![utxo('a', 0, 100_000)]),
                                2 => json!({"status": "mempool"}).to_string(),
                                _ => coins(vec![]),
                            };
                            right.push(response(200, &body));
                            let answer = if round == fault_round && step == operation {
                                if one_source {
                                    response(500, "{}")
                                } else {
                                    let different = match step {
                                        0 => chain_state(40_007, false).to_string(),
                                        1 => coins(vec![utxo('a', 0, 100_000), utxo('b', 0, 1000)]),
                                        2 => json!({"status": "unknown"}).to_string(),
                                        _ => coins(vec![utxo('b', 0, 1000)]),
                                    };
                                    response(200, &different)
                                }
                            } else {
                                response(200, &body)
                            };
                            left.push(answer);
                        }
                    }
                    let mut nonce = [0; 8];
                    getrandom::fill(&mut nonce).unwrap();
                    let dir = std::env::temp_dir().join(format!("pqw-sources-test-{}", hex::encode(nonce)));
                    let mut state = AppState::new(dir.clone()).unwrap();
                    *guard(&state.session) = Some(Session::new(&Secret::new_bip39().unwrap()).unwrap());
                    // The old payment is in the mempool of another address and not in doubt: on its own it sets no caution.
                    let old = paid('1', "mempool", "mldsa44", &['c']);
                    store::save(&state.sent_path(), &vec![old.clone()]).unwrap();
                    let to = state.templates().unwrap().0.address;
                    let (a, first) = serve(left);
                    let (b, second) = serve(right);
                    state.sources = Arc::new(Sources::new(a, b));
                    let (view, pending, checked) = tauri::async_runtime::block_on(async {
                        let view = plan_payment(&state, Kind::Schnorr, to, "0.0001".into()).await.unwrap();
                        assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap()[0].lookup_mark, 1);
                        let mut pending = guard(&state.pending).take().unwrap();
                        let checked = recheck_payment(&state, &state.snapshot().unwrap(), &mut pending).await.unwrap();
                        assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap()[0].lookup_mark, 2);
                        (view, pending, checked)
                    });
                    let first = first.join().unwrap();
                    let second = second.join().unwrap();
                    assert_eq!((first.len(), second.len()), (10, 10));
                    assert_eq!(view.one_source, fault_round == 0 && one_source);
                    assert_eq!(view.sources_disagree, fault_round == 0 && !one_source);
                    assert!(!view.went_out && !view.unclear_elsewhere && !view.unrecorded);
                    let wire = serde_json::to_value(&view).unwrap();
                    assert_eq!(wire["one_source"], json!(view.one_source));
                    assert_eq!(wire["sources_disagree"], json!(view.sources_disagree));
                    assert_eq!(pending.sources, Flags { one_source, disagree: !one_source });
                    assert!(!pending.caution);
                    let (_, coins, spending) = checked;
                    let new = Sent {
                        from: "schnorr".into(),
                        outpoints: pending.plan.coins.iter().map(Coin::outpoint).collect(),
                        ..record('2', "submitting")
                    };
                    // Source notices alone do not require the earlier-payment warning.
                    record_payment(&state, &pending, &coins, &spending, state.generation(), new.clone()).unwrap();
                    let saved: Vec<Sent> = store::load(&state.sent_path());
                    assert_eq!(saved[0], new);
                    std::fs::remove_dir_all(dir).unwrap();
                }
            }
        }
    }

    #[test]
    fn a_missing_peer_cannot_make_a_mempool_record_unknown() {
        use crate::api::tests::{response, serve};
        let unknown = response(200, r#"{"status":"unknown"}"#);
        let (a, first) = serve(vec![unknown.clone(), unknown.clone()]);
        let (b, second) = serve(vec![response(500, "{}"), unknown]);
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-missing-peer-{}", hex::encode(nonce)));
        let mut state = AppState::new(dir.clone()).unwrap();
        state.sources = Arc::new(Sources::new(a, b));
        let old = record('a', "mempool");
        store::save(&state.sent_path(), &vec![old.clone()]).unwrap();
        let mut flags = Flags::default();
        let results = tauri::async_runtime::block_on(async {
            let first = refresh_sent(&state, state.generation(), |_| true, &mut flags).await;
            let second = refresh_sent(&state, state.generation(), |_| true, &mut Flags::default()).await;
            (first, second)
        });
        first.join().unwrap();
        second.join().unwrap();
        assert_eq!(results.0, vec![Sent { lookup_mark: 1, ..old }]);
        assert!(flags.one_source);
        assert_eq!(results.1[0].status, "unknown");
        assert!(results.1[0].doubted);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn higher_confirmations_need_a_proof_and_can_use_the_other_nodes_proof() {
        use crate::api::tests::{response, serve};
        let proof = proof::tests::real_proof();
        let txid = proof["txid"].as_str().unwrap();
        let (a, first) = serve(vec![response(200, r#"{"status":"mempool"}"#), response(200, "{}"),
            response(200, r#"{"status":"confirmed","confirmations":2}"#)]);
        let (b, second) = serve(vec![response(200, r#"{"status":"confirmed","confirmations":100}"#), response(200, &proof.to_string()),
            response(200, r#"{"status":"mempool"}"#)]);
        let sources = Sources::new(a, b);
        let mut flags = Flags::default();
        let mut short_flags = Flags::default();
        let (proven, short) = tauri::async_runtime::block_on(async {
            (lookup_sent(&sources, txid, &mut flags).await, lookup_sent(&sources, txid, &mut short_flags).await)
        });
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_eq!((first.len(), second.len()), (3, 3));
        assert_eq!(proven, Ok((TxStatus::Confirmed { confirmations: 5 }, false)));
        assert_eq!(flags, Flags { one_source: true, disagree: true });
        assert_eq!(short, Ok((TxStatus::Confirmed { confirmations: 2 }, false)));
        assert_eq!(short_flags, Flags { one_source: false, disagree: true });
        assert!(first[1].starts_with("GET /api/proof?"));
        assert!(second[1].starts_with("GET /api/proof?"));
    }

    #[test]
    fn pages_open_only_for_this_wallets_own_values() {
        let own_address = "tb1zown";
        let recorded_txid = "ab".repeat(32);
        let url = |page: &str, value: &str| {
            page_url(
                page,
                value,
                || value == recorded_txid,
                || value == own_address,
            )
        };
        assert_eq!(
            url("faucet", "").as_deref(),
            Some("https://faucet.ark0.si/")
        );
        assert_eq!(
            url("faucet", own_address).as_deref(),
            Some("https://faucet.ark0.si/?address=tb1zown")
        );
        assert_eq!(url("faucet", "tb1zsomeoneelse"), None);
        assert_eq!(
            url("explorer", "").as_deref(),
            Some("https://explorer.ark0.si/")
        );
        assert_eq!(
            url("tx", &recorded_txid),
            Some(format!("https://explorer.ark0.si/tx/{recorded_txid}"))
        );
        assert_eq!(url("tx", &"cd".repeat(32)), None);
        assert_eq!(
            url("address", own_address).as_deref(),
            Some("https://explorer.ark0.si/address/tb1zown")
        );
        assert_eq!(url("address", "tb1zsomeoneelse"), None);
        assert_eq!(url("settings", ""), None);
    }
}

#[cfg(test)]
mod pq2_tests {
    use super::*;
    use crate::api::tests::{response, routed};
    use crate::chain::tests::{m4_state, state as m3_state};
    use crate::chain::H4T;
    use serde_json::{json, Value};
    use std::sync::atomic::AtomicBool;

    /// What both fake APIs answer, changed by the test as it goes.
    #[derive(Clone, Default)]
    struct Net {
        state: Arc<Mutex<Value>>,
        /// Unspent outputs by address, as /api/utxos lists them.
        utxos: Arc<Mutex<HashMap<String, Vec<Value>>>>,
        /// Payments on their way, by address.
        incoming: Arc<Mutex<HashMap<String, Vec<Value>>>>,
        /// The broadcast answer: (HTTP status, body); the default accepts.
        refuse: Arc<Mutex<Option<String>>>,
        /// Run when a broadcast arrives (the node's state may change with it).
        on_broadcast: Arc<Mutex<Option<Value>>>,
        broadcasts: Arc<Mutex<Vec<String>>>,
        /// /api/tx answers by txid; unknown otherwise.
        txs: Arc<Mutex<HashMap<String, Value>>>,
        /// /api/history: the height from which each address has history (none: never used).
        history: Arc<Mutex<HashMap<String, u32>>>,
        /// /api/history answers this instead, when set: (HTTP status, body).
        history_fails: Arc<Mutex<Option<(u16, String)>>>,
        /// The `from` of every history request.
        history_from: Arc<Mutex<Vec<u32>>>,
        /// Tips the history answers give, one per request, before falling back to the state's `blocks`.
        history_tips: Arc<Mutex<std::collections::VecDeque<u32>>>,
        /// When set, history requests beyond this many fail (503 busy).
        history_ok: Arc<Mutex<Option<usize>>>,
        /// Paths answered once "too many requests" (429 limit, Retry-After 2) before they are answered.
        limited_once: Arc<Mutex<Vec<String>>>,
        /// When set, the deployed site's limits, on a clock of this unit per second.
        limits: Arc<Mutex<Option<SiteLimits>>>,
        /// The address of every /api/utxos request.
        asked: Arc<Mutex<Vec<String>>>,
        /// When set, what the second source answers to /api/state (the first answers `state`).
        state_b: Arc<Mutex<Option<Value>>>,
        /// When set, the second source's confirmed outputs by address, instead of `utxos`.
        utxos_b: Arc<Mutex<Option<HashMap<String, Vec<Value>>>>>,
    }

    /// The deployed site's limits (web/ark0web/wallet.py): /api/utxos 20 at once and 1 a second per visitor
    /// (429 limit, Retry-After 5), the node's scans 10 at once and 2 a second for all (503 busy, Retry-After
    /// 5), /api/history 20 at once and 1 a second per visitor. Both test sources share them: stricter than
    /// two sites.
    struct SiteLimits {
        unit: Duration,
        utxos: Bucket,
        scans: Bucket,
        history: Bucket,
        /// Requests refused, by path kind.
        refused: Vec<String>,
    }

    struct Bucket {
        tokens: f64,
        burst: f64,
        rate: f64,
        at: Instant,
    }

    impl Bucket {
        fn new(burst: f64, rate: f64) -> Bucket {
            Bucket { tokens: burst, burst, rate, at: Instant::now() }
        }

        fn take(&mut self, unit: Duration) -> bool {
            let now = Instant::now();
            self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() / unit.as_secs_f64() * self.rate).min(self.burst);
            self.at = now;
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                true
            } else {
                false
            }
        }
    }

    impl SiteLimits {
        fn deployed(unit: Duration) -> SiteLimits {
            SiteLimits { unit, utxos: Bucket::new(20.0, 1.0), scans: Bucket::new(10.0, 2.0), history: Bucket::new(20.0, 1.0), refused: Vec::new() }
        }
    }

    struct Wallet {
        state: AppState,
        net: Net,
        dir: PathBuf,
        stops: Vec<Arc<AtomicBool>>,
    }

    impl Drop for Wallet {
        fn drop(&mut self) {
            for s in &self.stops {
                s.store(true, Ordering::SeqCst);
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn answer(net: &Net, first: &str, body: &str) -> String {
        let path = first.split(' ').nth(1).unwrap_or("");
        {
            let mut limited = guard(&net.limited_once);
            if let Some(i) = limited.iter().position(|p| path.starts_with(p.as_str())) {
                limited.remove(i);
                return crate::api::tests::response_with(429, "Retry-After: 2\r\n", r#"{"error":"limit"}"#);
            }
        }
        if let Some(limits) = guard(&net.limits).as_mut() {
            let unit = limits.unit;
            let refusal = if path.starts_with("/api/utxos") {
                if !limits.utxos.take(unit) {
                    Some((429, r#"{"error":"limit"}"#))
                } else if !limits.scans.take(unit) {
                    Some((503, r#"{"error":"busy"}"#))
                } else {
                    None
                }
            } else if path.starts_with("/api/history") && !limits.history.take(unit) {
                Some((429, r#"{"error":"limit"}"#))
            } else {
                None
            };
            if let Some((status, body)) = refusal {
                limits.refused.push(format!("{status} {}", path.split('?').next().unwrap_or("")));
                return crate::api::tests::response_with(status, "Retry-After: 5\r\n", body);
            }
        }
        if path == "/api/state" {
            return response(200, &guard(&net.state).to_string());
        }
        if let Some(address) = path.strip_prefix("/api/utxos?address=") {
            guard(&net.asked).push(address.to_string());
            let utxos = guard(&net.utxos).get(address).cloned().unwrap_or_default();
            let incoming = guard(&net.incoming).get(address).cloned().unwrap_or_default();
            return response(200, &json!({"utxos": utxos, "unconfirmed": incoming, "unconfirmed_complete": true, "truncated": false}).to_string());
        }
        if let Some(txid) = path.strip_prefix("/api/tx?txid=") {
            let answer = guard(&net.txs).get(txid).cloned().unwrap_or(json!({"status": "unknown"}));
            return response(200, &answer.to_string());
        }
        if let Some(query) = path.strip_prefix("/api/history?") {
            if let Some((status, body)) = guard(&net.history_fails).clone() {
                return response(status, &body);
            }
            if let Some(left) = guard(&net.history_ok).as_mut() {
                if *left == 0 {
                    return response(503, r#"{"error":"busy"}"#);
                }
                *left -= 1;
            }
            let mut from = 0;
            let mut addresses = Vec::new();
            for pair in query.split('&') {
                match pair.split_once('=') {
                    Some(("from", f)) => from = f.parse().unwrap(),
                    Some(("address", a)) => addresses.push(a.to_string()),
                    _ => return response(400, r#"{"error":"request"}"#),
                }
            }
            guard(&net.history_from).push(from);
            let tip = guard(&net.history_tips).pop_front().map_or_else(|| guard(&net.state)["blocks"].as_u64().unwrap(), u64::from);
            let history = guard(&net.history).clone();
            let entries: Vec<Value> = addresses.iter()
                .map(|a| json!({"address": a, "used": history.get(a).is_some_and(|h| u64::from(*h) >= u64::from(from) && u64::from(*h) <= tip)}))
                .collect();
            // Above the tip nothing is used (the site's answer after its tip went below `from`).
            return response(200, &json!({"tip_height": tip, "tip_hash": "ab".repeat(32), "from": from, "addresses": entries}).to_string());
        }
        if path.starts_with("/api/proof?") {
            return response(404, r#"{"error":"not_confirmed"}"#);
        }
        if path == "/api/broadcast" {
            let hex: Value = serde_json::from_str(body).unwrap();
            let hex = hex["hex"].as_str().unwrap().to_string();
            guard(&net.broadcasts).push(hex.clone());
            if let Some(next) = guard(&net.on_broadcast).take() {
                *guard(&net.state) = next;
            }
            if let Some(reason) = guard(&net.refuse).clone() {
                return response(422, &json!({"error": "rejected", "reason": reason}).to_string());
            }
            let bytes = hex::decode(&hex).unwrap();
            // The txid of a segwit transaction: hash of the serialization without marker, flag and witness.
            let txid = txid_of(&bytes);
            return response(200, &json!({"txid": txid}).to_string());
        }
        response(404, "{}")
    }

    /// The txid of a signed transaction the wallet built (its inputs have empty scriptSigs, and every
    /// input of a pq2 spend has a witness).
    fn txid_of(signed: &[u8]) -> String {
        let tx = decode(signed);
        crate::tx::display_hex(&tx.txid())
    }

    /// Enough of BIP-144 to read back what the wallet broadcast.
    fn decode(b: &[u8]) -> crate::tx::Transaction {
        use crate::tx::{OutPoint, Transaction, TxIn, TxOut};
        let mut at = 0;
        let mut take = |n: usize| { let s = &b[at..at + n]; at += n; s.to_vec() };
        fn compact(take: &mut dyn FnMut(usize) -> Vec<u8>) -> usize {
            let first = take(1)[0];
            match first {
                0xfd => u16::from_le_bytes(take(2).try_into().unwrap()) as usize,
                0xfe => u32::from_le_bytes(take(4).try_into().unwrap()) as usize,
                n => n as usize,
            }
        }
        let version = u32::from_le_bytes(take(4).try_into().unwrap());
        let mut n = compact(&mut take);
        let segwit = n == 0;
        if segwit {
            take(1);
            n = compact(&mut take);
        }
        let mut inputs = Vec::new();
        for _ in 0..n {
            let txid: [u8; 32] = take(32).try_into().unwrap();
            let vout = u32::from_le_bytes(take(4).try_into().unwrap());
            let script = compact(&mut take);
            take(script);
            let sequence = u32::from_le_bytes(take(4).try_into().unwrap());
            inputs.push(TxIn { prevout: OutPoint { txid, vout }, sequence, witness: vec![] });
        }
        let mut outputs = Vec::new();
        for _ in 0..compact(&mut take) {
            let sats = u64::from_le_bytes(take(8).try_into().unwrap());
            let len = compact(&mut take);
            outputs.push(TxOut { sats, script_pubkey: take(len) });
        }
        if segwit {
            for input in &mut inputs {
                for _ in 0..compact(&mut take) {
                    let len = compact(&mut take);
                    input.witness.push(take(len));
                }
            }
        }
        let lock_time = u32::from_le_bytes(take(4).try_into().unwrap());
        Transaction { version, inputs, outputs, lock_time }
    }

    fn wallet(label: &str, secret: Secret, made_here: bool, chain: Value) -> Wallet {
        wallet_waiting(label, secret, made_here, chain, None)
    }

    /// A wallet whose two APIs wait `unit` per second a "try later" answer asks (None: they ask once).
    fn wallet_waiting(label: &str, secret: Secret, made_here: bool, chain: Value, unit: Option<Duration>) -> Wallet {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-pq2-{label}-{}", hex::encode(nonce)));
        let mut state = AppState::new(dir.clone()).unwrap();
        let net = Net::default();
        *guard(&net.state) = chain;
        let (a, stop_a) = { let n = net.clone(); routed(move |first, body| answer(&n, first, body)) };
        let (b, stop_b) = {
            let n = net.clone();
            routed(move |first, body| {
                let path = first.split(' ').nth(1).unwrap_or("");
                if let Some(state) = guard(&n.state_b).clone().filter(|_| path == "/api/state") {
                    return response(200, &state.to_string());
                }
                if let (Some(address), Some(utxos)) = (path.strip_prefix("/api/utxos?address="), guard(&n.utxos_b).clone()) {
                    let listed = utxos.get(address).cloned().unwrap_or_default();
                    return response(200, &json!({"utxos": listed, "unconfirmed": [], "unconfirmed_complete": true, "truncated": false}).to_string());
                }
                answer(&n, first, body)
            })
        };
        let (a, b) = match unit {
            Some(unit) => (crate::api::tests::waiting(a, unit), crate::api::tests::waiting(b, unit)),
            None => (a, b),
        };
        state.sources = Arc::new(Sources::new(a, b));
        state.open_session(&secret, state.generation(), made_here).unwrap();
        Wallet { state, net, dir, stops: vec![stop_a, stop_b] }
    }

    fn words(byte: u8) -> Secret {
        Secret::Bip39 { entropy: crate::keys::SecretBytes(Zeroizing::new([byte; 32])) }
    }

    fn utxo(txid: char, vout: u32, sats: u64, height: u32) -> Value {
        json!({"txid": txid.to_string().repeat(64), "vout": vout, "sats": sats, "height": height, "spent_in_mempool": false})
    }

    fn block<T>(f: impl Future<Output = T>) -> T {
        tauri::async_runtime::block_on(f)
    }

    fn pq2_address(w: &Wallet, chain: u32, index: u32) -> String {
        w.state.pq2_template(chain, index).unwrap().address
    }

    #[test]
    fn pq2_addresses_wait_for_h4t_plus_six_are_issued_once_and_stop_at_the_gap_limit() {
        let w = wallet("issue", words(0x11), true, m4_state(H4T + 5, false));
        // H4T + 5: why not yet, and no address.
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_waiting");
        let o = block(overview_of(&w.state)).unwrap();
        let p = o.pq2.unwrap();
        assert_eq!((p.blocked, p.allowed, p.opens_at), (Some("waiting"), false, H4T + 6));
        assert!(p.addresses.is_empty());
        // H4T + 6: index 0, then 1; never the same one twice.
        *guard(&w.net.state) = m4_state(H4T + 6, false);
        let first = block(new_pq2_address(&w.state)).unwrap();
        assert_eq!((first.index, first.address.clone()), (0, pq2_address(&w, 0, 0)));
        let second = block(new_pq2_address(&w.state)).unwrap();
        assert_eq!(second.index, 1);
        assert_ne!(first.address, second.address);
        for i in 2..GAP_LIMIT {
            assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, i);
        }
        // Twenty handed out, none paid: no more.
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_gap_limit");
        assert_eq!(block(overview_of(&w.state)).unwrap().pq2.unwrap().blocked, Some("gap_limit"));
        // A payment seen on its way to index 3 makes it used, and the wallet records it.
        guard(&w.net.incoming).insert(pq2_address(&w, 0, 3), vec![json!({"txid": "ab".repeat(32), "vout": 0, "sats": 5_000})]);
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert_eq!(p.blocked, None);
        assert_eq!(p.addresses.len(), 1);
        assert_eq!(p.addresses[0].coins[0].status, Pq2Status::Pending);
        assert!(w.state.book().unwrap().chains[0].used.contains(&3));
        guard(&w.net.incoming).clear();
        // Used stays used once the payment is gone from the API's view.
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, GAP_LIMIT);
        // A reorganization back below H4T + 6 pauses issuance.
        *guard(&w.net.state) = m4_state(H4T + 3, false);
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_waiting");
        // Unknown state: no address.
        let mut unknown = m4_state(H4T + 50, false);
        unknown["tripwire"]["lattice"]["mldsa_disabled_next_block"] = json!(null);
        *guard(&w.net.state) = unknown;
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_unknown_state");
        // A node without the M4 rules: nothing about pq2 at all.
        *guard(&w.net.state) = m3_state(H4T + 50, false);
        assert!(block(overview_of(&w.state)).unwrap().pq2.is_none());
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "address_not_ready");
    }

    #[test]
    fn a_backup_code_wallet_gets_no_pq2_and_is_told_why() {
        let code = "ark0w1-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f-630dcd29";
        let w = wallet("legacy", Secret::from_backup_code(code).unwrap(), false, m4_state(H4T + 10, false));
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert_eq!((p.blocked, p.allowed), (Some("legacy"), false));
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_legacy");
        assert_eq!(block(scan_pq2(&w.state, false)).unwrap_err().code, "pq2_unavailable");
        assert!(!w.state.pq2_path().exists());
    }

    #[test]
    fn a_restored_wallet_scans_both_chains_and_never_hands_out_a_scanned_address() {
        let w = wallet("scan", words(0x22), false, m4_state(H4T + 10, false));
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_scan_needed");
        assert_eq!(block(overview_of(&w.state)).unwrap().pq2.unwrap().blocked, Some("scan_needed"));
        // Another copy of the wallet was paid at receiving index 2 and change index 0.
        guard(&w.net.utxos).insert(pq2_address(&w, 0, 2), vec![utxo('a', 0, 10_000, H4T + 1)]);
        guard(&w.net.utxos).insert(pq2_address(&w, 1, 0), vec![utxo('b', 1, 20_000, H4T + 2)]);
        let r = block(scan_pq2(&w.state, false)).unwrap();
        assert_eq!(r.found, 2);
        // Stopped after 20 unused in a row (20 at a time); everything up to the highest used plus 20 is issued.
        assert_eq!((r.scanned, r.issued), ([40, 40], [23, 21]));
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, 23);
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert_eq!(p.addresses.len(), 2);
        assert_eq!(p.spendable, 30_000);
        // Coins beyond the scanned range need the wider scan.
        guard(&w.net.utxos).insert(pq2_address(&w, 0, 60), vec![utxo('c', 0, 7_000, H4T + 3)]);
        let r = block(scan_pq2(&w.state, true)).unwrap();
        assert_eq!(r.found, 1);
        assert_eq!(r.issued[0], 81);
        assert!(r.scanned[0] >= 140 && r.scanned[1] >= 140);
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, 81);
    }

    #[test]
    fn recovery_goes_by_history_and_never_hands_out_an_emptied_address() {
        let w = wallet("history", words(0x55), false, m4_state(H4T + 100, false));
        // Indices 0 to 39 received and were emptied; 40 holds coins now.
        for i in 0..40 {
            guard(&w.net.history).insert(pq2_address(&w, 0, i), H4T + 10 + i);
        }
        guard(&w.net.utxos).insert(pq2_address(&w, 0, 40), vec![utxo('a', 0, 9_000, H4T + 60)]);
        // A payment on its way (no history yet) counts too, on the change chain.
        guard(&w.net.incoming).insert(pq2_address(&w, 1, 3), vec![json!({"txid": "bc".repeat(32), "vout": 0, "sats": 2_000})]);
        let r = block(scan_pq2(&w.state, false)).unwrap();
        assert_eq!(r.found, 42);
        assert_eq!(r.issued, [61, 24]);
        // The first address handed out comes after all of them, and the coins at 40 are shown.
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, 61);
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert!(p.addresses.iter().any(|a| a.index == 40 && a.spendable == 9_000));
    }

    #[test]
    fn without_an_answer_about_history_the_scan_does_not_complete() {
        for (status, body) in [(404, r#"{"error":"not_found"}"#.to_string()), (503, r#"{"error":"busy"}"#.to_string()), (503, r#"{"error":"unavailable"}"#.to_string()),
            (200, json!({"tip_height": 1, "tip_hash": "ab".repeat(32), "from": 0, "addresses": []}).to_string())] {
            let w = wallet("history-fails", words(0x56), false, m4_state(H4T + 100, false));
            *guard(&w.net.history_fails) = Some((status, body.clone()));
            assert_eq!(block(scan_pq2(&w.state, false)).unwrap_err().code, "history_unavailable", "{status} {body}");
            // Still waiting for a scan: no address is handed out.
            assert!(w.state.book().unwrap().scan_needed);
            assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_scan_needed");
            *guard(&w.net.history_fails) = None;
            assert!(block(scan_pq2(&w.state, false)).is_ok());
            assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, GAP_LIMIT);
        }
    }

    /// The heights the reserved addresses' histories were checked to, each once.
    fn watermarks(book: &Book) -> Vec<u32> {
        let mut v: Vec<u32> = book.chains.iter().flat_map(|c| c.checked.values().copied()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    #[test]
    fn a_late_payment_to_a_reserved_address_is_seen() {
        let w = wallet("reserved", words(0x57), false, m4_state(H4T + 100, false));
        let r = block(scan_pq2(&w.state, false)).unwrap();
        assert_eq!((r.found, r.issued), (0, [20, 20]));
        assert_eq!(watermarks(&w.state.book().unwrap()), vec![H4T + 100]);
        // Index 0 was reserved, never handed out here; another copy of the wallet hands it out and it is
        // paid in a later block.
        *guard(&w.net.state) = m4_state(H4T + 110, false);
        let address = pq2_address(&w, 0, 0);
        guard(&w.net.history).insert(address.clone(), H4T + 105);
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('c', 1, 12_000, H4T + 105)]);
        guard(&w.net.history_from).clear();
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        // One cheap check from six blocks below the last tip, for the reserved addresses of both chains.
        assert_eq!(*guard(&w.net.history_from), vec![H4T + 94, H4T + 94, H4T + 94, H4T + 94]);
        assert!(p.addresses.iter().any(|a| a.index == 0 && a.spendable == 12_000));
        let book = w.state.book().unwrap();
        assert!(book.chains[0].used.contains(&0));
        assert_eq!(watermarks(&book), vec![H4T + 110]);
        // The next refresh asks from the new tip only.
        guard(&w.net.history_from).clear();
        block(overview_of(&w.state)).unwrap();
        assert!(guard(&w.net.history_from).iter().all(|f| *f == H4T + 104));
    }

    #[test]
    fn a_payment_in_blocks_a_reorganization_replaced_is_seen() {
        let w = wallet("reorg", words(0x59), false, m4_state(H4T + 100, false));
        block(scan_pq2(&w.state, false)).unwrap();
        assert_eq!(watermarks(&w.state.book().unwrap()), vec![H4T + 100]);
        // The last six blocks are replaced by a chain of the same height whose block H4T + 97 pays reserved
        // index 4: asking from the last tip would miss it.
        let address = pq2_address(&w, 0, 4);
        guard(&w.net.history).insert(address.clone(), H4T + 97);
        guard(&w.net.utxos).insert(address, vec![utxo('e', 0, 7_000, H4T + 97)]);
        guard(&w.net.history_from).clear();
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert!(guard(&w.net.history_from).iter().all(|f| *f == H4T + 94));
        assert!(p.complete && p.addresses.iter().any(|a| a.index == 4 && a.spendable == 7_000));
        assert!(w.state.book().unwrap().chains[0].used.contains(&4));
    }

    #[test]
    fn a_tip_below_from_is_asked_again_from_below_it() {
        let w = wallet("tip-lower", words(0x5a), false, m4_state(H4T + 100, false));
        block(scan_pq2(&w.state, false)).unwrap();
        // A reorganization took the tip down to H4T + 90; the new chain pays reserved index 7 at H4T + 88.
        *guard(&w.net.state) = m4_state(H4T + 90, false);
        let address = pq2_address(&w, 0, 7);
        guard(&w.net.history).insert(address.clone(), H4T + 88);
        guard(&w.net.utxos).insert(address, vec![utxo('f', 0, 3_000, H4T + 88)]);
        guard(&w.net.history_from).clear();
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        // Asked from H4T + 94, answered with tip H4T + 90 and nothing used; asked again from H4T + 84.
        // Two requests per question (one to each API), for each of the two groups of reserved addresses.
        let asked = guard(&w.net.history_from).clone();
        assert_eq!(asked, [H4T + 94, H4T + 94, H4T + 84, H4T + 84].repeat(2));
        assert!(p.complete && p.addresses.iter().any(|a| a.index == 7 && a.spendable == 3_000));
        assert_eq!(watermarks(&w.state.book().unwrap()), vec![H4T + 90]);
        // The second answer still below its `from`: the check is not answered, and nothing moves.
        let w = wallet("tip-lower-twice", words(0x5b), false, m4_state(H4T + 100, false));
        block(scan_pq2(&w.state, false)).unwrap();
        guard(&w.net.history).insert(pq2_address(&w, 0, 7), H4T + 50);
        // Asked from H4T + 94: tip H4T + 90; asked again from H4T + 84: tip H4T + 60, still below.
        guard(&w.net.history_tips).extend([H4T + 90, H4T + 90, H4T + 60, H4T + 60]);
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert!(!p.complete);
        let book = w.state.book().unwrap();
        assert!(!book.chains[0].used.contains(&7));
        assert_eq!(watermarks(&book), vec![H4T + 100]);
    }

    #[test]
    fn the_history_watermark_waits_until_a_payment_found_is_saved() {
        let w = wallet("watermark", words(0x5d), false, m4_state(H4T + 100, false));
        block(scan_pq2(&w.state, false)).unwrap();
        // Reserved index 3 is paid at H4T + 101; the check finds it, but saving that fails once.
        *guard(&w.net.state) = m4_state(H4T + 110, false);
        guard(&w.net.history).insert(pq2_address(&w, 0, 3), H4T + 101);
        w.state.fail_book_writes.store(1, Ordering::SeqCst);
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert!(!p.complete);
        let book = w.state.book().unwrap();
        assert_eq!(watermarks(&book), vec![H4T + 100], "the watermark did not move past the unsaved payment");
        assert!(!book.chains[0].used.contains(&3));
        // The next check still covers H4T + 101 and saves it.
        *guard(&w.net.state) = m4_state(H4T + 120, false);
        block(overview_of(&w.state)).unwrap();
        let book = w.state.book().unwrap();
        assert!(book.chains[0].used.contains(&3));
        assert_eq!(watermarks(&book), vec![H4T + 120]);
    }

    #[test]
    fn every_operation_on_the_address_book_holds_it_across_its_waits_on_the_network() {
        let w = wallet("one-op", words(0x64), false, m4_state(H4T + 100, false));
        let held = Arc::new(Mutex::new(Vec::new()));
        let h = held.clone();
        *guard(&w.state.after_network_answer) = Some(Box::new(move |state: &AppState| guard(&h).push(state.book_ops.try_lock().is_err())));
        block(scan_pq2(&w.state, false)).unwrap();
        assert!(guard(&held).len() > 20 && guard(&held).iter().all(|h| *h), "the scan");
        guard(&held).clear();
        block(new_pq2_address(&w.state)).unwrap();
        assert!(!guard(&held).is_empty() && guard(&held).iter().all(|h| *h), "a new address");
        // A refresh: every answer to its history check comes while it holds the book (the coin lookups
        // after it do not need the book).
        *guard(&w.net.state) = m4_state(H4T + 110, false);
        guard(&held).clear();
        guard(&w.net.history_from).clear();
        block(overview_of(&w.state)).unwrap();
        // Two requests per question, one to each API.
        let questions = guard(&w.net.history_from).len() / 2;
        assert_eq!(questions, 2);
        assert_eq!(guard(&held).iter().filter(|h| **h).count(), questions);
    }

    #[test]
    fn a_refresh_during_another_operation_on_the_book_skips_its_history_check() {
        for during_scan in [true, false] {
            let w = wallet("skip", words(0x65), false, m4_state(H4T + 100, false));
            block(scan_pq2(&w.state, false)).unwrap();
            *guard(&w.net.state) = m4_state(H4T + 110, false);
            // Reserved index 6 was paid at H4T + 105.
            guard(&w.net.history).insert(pq2_address(&w, 0, 6), H4T + 105);
            let asked = w.net.history_from.clone();
            let inner: Arc<Mutex<Option<(bool, usize)>>> = Arc::new(Mutex::new(None));
            let seen = inner.clone();
            // At the first answer of a scan, or of a refresh's history check, another refresh runs.
            *guard(&w.state.after_network_answer) = Some(Box::new(move |state: &AppState| {
                if guard(&seen).is_some() || state.book_ops.try_lock().is_ok() {
                    return;
                }
                let before = guard(&asked).len();
                let p = std::thread::scope(|s| s.spawn(|| block(overview_of(state))).join().unwrap()).unwrap().pq2.unwrap();
                *guard(&seen) = Some((p.complete, guard(&asked).len() - before));
            }));
            if during_scan {
                block(scan_pq2(&w.state, false)).unwrap();
            } else {
                block(overview_of(&w.state)).unwrap();
            }
            *guard(&w.state.after_network_answer) = None;
            // The inner refresh asked nothing about history and says it is not complete.
            assert_eq!(*guard(&inner), Some((false, 0)), "during a scan: {during_scan}");
            let book = w.state.book().unwrap();
            assert!(book.chains[0].used.contains(&6), "during a scan: {during_scan}");
            assert_eq!(watermarks(&book), vec![H4T + 110], "during a scan: {during_scan}");
        }
    }

    #[test]
    fn each_reserved_address_keeps_its_own_watermark() {
        let w = wallet("own-watermark", words(0x66), false, m4_state(H4T + 100, false));
        block(scan_pq2(&w.state, false)).unwrap();
        // The change chain's addresses were never checked (as after a scan that reserved them without an
        // answer about their history); the receiving chain's were, to H4T + 100. Change index 3 was paid
        // at H4T + 50, receiving index 4 at H4T + 102.
        w.state.edit_book(|b| b.chains[1].checked.clear()).unwrap();
        guard(&w.net.history).insert(pq2_address(&w, 1, 3), H4T + 50);
        guard(&w.net.history).insert(pq2_address(&w, 0, 4), H4T + 102);
        *guard(&w.net.state) = m4_state(H4T + 110, false);
        // The site answers the first question only: the change chain's, from block 0.
        *guard(&w.net.history_ok) = Some(2);
        guard(&w.net.history_from).clear();
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert!(!p.complete);
        assert_eq!(guard(&w.net.history_from)[..2], [0, 0]);
        let book = w.state.book().unwrap();
        // Only the addresses asked about moved, and what they had was found.
        assert!(book.chains[1].used.contains(&3) && !book.chains[0].used.contains(&4));
        assert!(book.chains[1].checked.values().all(|h| *h == H4T + 110));
        assert!(book.chains[0].checked.values().all(|h| *h == H4T + 100));
        // The next check asks each group from its own watermark, and finds the receiving payment.
        *guard(&w.net.history_ok) = None;
        guard(&w.net.history_from).clear();
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert!(p.complete);
        let mut asked = guard(&w.net.history_from).clone();
        asked.dedup();
        assert_eq!(asked, vec![H4T + 94, H4T + 104]);
        let book = w.state.book().unwrap();
        assert!(book.chains[0].used.contains(&4));
        assert_eq!(watermarks(&book), vec![H4T + 110]);
    }

    #[test]
    fn a_book_with_one_watermark_for_all_is_checked_from_block_0() {
        let w = wallet("old-watermark", words(0x67), false, m4_state(H4T + 100, false));
        block(scan_pq2(&w.state, false)).unwrap();
        // The book as the version with one watermark wrote it: that watermark, and none per address.
        let mut old = serde_json::to_value(w.state.book().unwrap()).unwrap();
        for c in old["chains"].as_array_mut().unwrap() {
            c.as_object_mut().unwrap().remove("checked");
        }
        old["history_tip"] = json!(H4T + 100);
        std::fs::write(w.state.pq2_path(), old.to_string()).unwrap();
        w.state.lock();
        w.state.open_session(&words(0x67), w.state.generation(), false).unwrap();
        // Reserved index 5 was paid at H4T + 50, below that watermark.
        guard(&w.net.history).insert(pq2_address(&w, 0, 5), H4T + 50);
        guard(&w.net.history_from).clear();
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert!(p.complete);
        assert!(guard(&w.net.history_from).iter().all(|f| *f == 0));
        let book = w.state.book().unwrap();
        assert!(book.chains[0].used.contains(&5));
        assert_eq!(watermarks(&book), vec![H4T + 100]);
    }

    #[test]
    fn an_address_two_copies_showed_is_watched_for_every_payment_to_it() {
        // This copy showed receiving index 0; another copy of the wallet showed it too. Both payers pay it.
        let w = wallet("two-copies", words(0x68), true, m4_state(H4T + 10, false));
        let address = block(new_pq2_address(&w.state)).unwrap().address;
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('a', 0, 4_000, H4T + 8), utxo('b', 1, 6_000, H4T + 9)]);
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert!(p.addresses.iter().any(|a| a.address == address && a.spendable == 10_000 && a.coins.len() == 2));
        // A use of an index this device showed does not stop it showing addresses.
        let book = w.state.book().unwrap();
        assert!(book.chains[0].used.contains(&0) && !book.scan_needed && book.chains[0].issued == 1);
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, 1);
    }

    #[test]
    fn a_command_waiting_for_the_book_stays_with_the_wallet_it_was_called_for() {
        for scan in [false, true] {
            let w = wallet("wait-book", words(0x6b), true, m4_state(H4T + 10, false));
            // Another operation holds the book (A's history check, say) while the command is called for A.
            let held = w.state.book_ops.try_lock().unwrap();
            std::thread::scope(|s| {
                let state = &w.state;
                let command = s.spawn(move || {
                    if scan { block(scan_pq2(state, false)).map(|_| ()) } else { block(new_pq2_address(state)).map(|_| ()) }
                });
                std::thread::sleep(Duration::from_millis(1_000));
                assert!(!command.is_finished());
                // A is removed and B is opened; then the book is free.
                state.lock();
                state.open_session(&words(0x6c), state.generation(), !scan).unwrap();
                drop(held);
                assert_eq!(command.join().unwrap().unwrap_err().code, "locked", "scan: {scan}");
            });
            // Nothing written into B's book.
            let book = w.state.book().unwrap();
            assert_eq!(book.wallet, pq2_address(&w, 0, 0));
            assert_eq!(book.scan_needed, scan, "scan: {scan}");
            assert!(book.chains.iter().all(|c| c.issued == 0 && c.scanned == 0 && c.addresses.is_empty()), "scan: {scan}");
            assert_eq!(book.scan_revision, 0, "scan: {scan}");
        }
    }

    #[test]
    fn a_book_is_never_written_larger_than_the_wallet_reads() {
        let w = wallet("book-full", words(0x6f), true, m4_state(H4T + 10, false));
        let limit = store::MAX_FILE_BYTES as usize;
        // A book of many used change addresses, a few bytes short of the limit.
        let fill = |n: u32, extra: usize| {
            let mut b = w.state.book().unwrap();
            let c = &mut b.chains[1];
            c.issued = n;
            c.used = (0..n).collect();
            c.addresses = (0..n).map(|i| (i, format!("tb1z{:060}", i))).collect();
            if n > 0 {
                c.addresses.insert(0, format!("tb1z{}", "q".repeat(60 + extra)));
            }
            b
        };
        let size = |b: &Book| serde_json::to_vec_pretty(b).unwrap().len();
        let (mut low, mut high) = (0u32, 100_000u32);
        while low + 1 < high {
            let mid = (low + high) / 2;
            if size(&fill(mid, 0)) <= limit { low = mid } else { high = mid }
        }
        let gap = limit - size(&fill(low, 0));
        let book = fill(low, gap.saturating_sub(8));
        assert!(size(&book) <= limit && size(&book) + 50 > limit);
        std::fs::write(w.state.pq2_path(), serde_json::to_vec_pretty(&book).unwrap()).unwrap();
        let before = std::fs::read(w.state.pq2_path()).unwrap();
        assert_eq!(w.state.book().unwrap(), book, "the wallet reads it");
        // One more address would make it larger than the wallet reads: refused, and the old file stays.
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_book_full");
        assert_eq!(std::fs::read(w.state.pq2_path()).unwrap(), before);
        assert_eq!(w.state.book().unwrap(), book);
    }

    #[test]
    fn a_create_or_restore_begun_before_a_lock_writes_nothing() {
        for restoring in [true, false] {
            let w = wallet("stale-setup", words(0x74), true, m4_state(H4T + 10, false));
            w.state.lock();
            std::fs::remove_file(w.state.pq2_path()).unwrap();
            let password = "a long enough password".to_string();
            // The request has derived its keys; then the wallet is locked (its removal confirmed).
            *guard(&w.state.before_set_up) = Some(Box::new(|state: &AppState| state.lock()));
            let result = if restoring {
                restore_wallet_from_text(&w.state, words(0x75).recovery_text().to_string(), password.clone())
            } else {
                *guard(&w.state.new_wallet) = Some(NewWallet { secret: words(0x76), confirmed: true });
                create_confirmed_wallet(&w.state, password.clone())
            };
            assert_eq!(result.unwrap_err().code, "locked", "restoring: {restoring}");
            // Nothing on disk, no session; the next wallet is made as if the stale request never ran.
            assert!(!vault::exists(&w.state.vault_path()) && !w.state.pq2_path().exists(), "restoring: {restoring}");
            assert!(guard(&w.state.session).is_none());
            restore_wallet_from_text(&w.state, words(0x77).recovery_text().to_string(), password).unwrap();
            assert_eq!(w.state.book().unwrap().wallet, pq2_address(&w, 0, 0));
        }
    }

    #[test]
    fn nothing_comes_between_a_new_session_and_its_first_book() {
        let w = wallet("setup", words(0x70), true, m4_state(H4T + 10, false));
        // Wallet A's set-up pauses right after its session is installed.
        let (installed, paused) = std::sync::mpsc::channel();
        *guard(&w.state.after_session_installed) = Some(Box::new(move |_: &AppState| {
            installed.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(500));
        }));
        std::thread::scope(|s| {
            let state = &w.state;
            state.lock();
            let generation = state.generation();
            let a = s.spawn(move || state.open_session(&words(0x71), generation, true));
            paused.recv().unwrap();
            // Meanwhile A is locked away, B restored and given an address.
            state.lock();
            state.open_session(&words(0x72), state.generation(), true).unwrap();
            block(new_pq2_address(state)).unwrap();
            a.join().unwrap().unwrap();
        });
        // B keeps its book, and the address it handed out.
        let book = w.state.book().unwrap();
        assert_eq!(book.wallet, pq2_address(&w, 0, 0));
        assert!(book.chains[0].handed_out.contains(&0));
        // A set-up begun before a lock writes nothing and ends locked.
        let before = std::fs::read(w.state.pq2_path()).unwrap();
        let generation = w.state.generation();
        w.state.lock();
        assert_eq!(w.state.open_session(&words(0x73), generation, true).unwrap_err().code, "locked");
        assert_eq!(std::fs::read(w.state.pq2_path()).unwrap(), before);
        assert!(guard(&w.state.session).is_none());
    }

    #[test]
    fn a_command_waits_for_a_busy_site_and_a_lock_meanwhile_ends_it_locked() {
        let unit = Duration::from_millis(200);
        // The node's state is answered "too many requests" once on each source: the command waits 2 x 200 ms
        // with no lock of the wallet's held, then goes on.
        let w = wallet_waiting("wait-ok", words(0x78), true, m4_state(H4T + 10, false), Some(unit));
        guard(&w.net.limited_once).extend(["/api/state".to_string(), "/api/state".to_string()]);
        let started = Instant::now();
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, 0);
        assert!(started.elapsed() >= unit * 2);
        assert!(guard(&w.net.limited_once).is_empty());
        // Locked while it waits: lock() does not wait for it, and the command ends locked with nothing handed out.
        let w = wallet_waiting("wait-lock", words(0x79), true, m4_state(H4T + 10, false), Some(unit));
        guard(&w.net.limited_once).extend(["/api/state".to_string(), "/api/state".to_string()]);
        std::thread::scope(|s| {
            let state = &w.state;
            let command = s.spawn(move || block(new_pq2_address(state)));
            std::thread::sleep(unit / 2);
            let locking = Instant::now();
            state.lock();
            assert!(locking.elapsed() < unit / 2, "lock() waited {:?}", locking.elapsed());
            assert!(!command.is_finished());
            assert_eq!(command.join().unwrap().unwrap_err().code, "locked");
        });
        let book: Book = serde_json::from_slice(&std::fs::read(w.state.pq2_path()).unwrap()).unwrap();
        assert!(book.chains.iter().all(|c| c.handed_out.is_empty() && c.issued == 0));
    }

    #[test]
    fn a_restored_wallet_completes_its_scan_within_the_sites_limits() {
        let unit = Duration::from_millis(10);
        let w = wallet_waiting("scan-limits", words(0x7a), false, m4_state(H4T + 100, false), Some(unit));
        // Coins on receiving indices 0 and 5 (one confirmed long ago, one on its way) and change index 2.
        guard(&w.net.history).insert(pq2_address(&w, 0, 0), H4T + 20);
        guard(&w.net.utxos).insert(pq2_address(&w, 0, 0), vec![utxo('a', 0, 10_000, H4T + 20)]);
        guard(&w.net.incoming).insert(pq2_address(&w, 0, 5), vec![json!({"txid": "b".repeat(64), "vout": 1, "sats": 20_000})]);
        guard(&w.net.history).insert(pq2_address(&w, 1, 2), H4T + 30);
        guard(&w.net.utxos).insert(pq2_address(&w, 1, 2), vec![utxo('c', 0, 30_000, H4T + 30)]);
        *guard(&w.net.limits) = Some(SiteLimits::deployed(unit));
        let r = block(scan_pq2(&w.state, false)).unwrap();
        let refused = guard(&w.net.limits).as_ref().unwrap().refused.clone();
        // Every coin found, the site refused along the way and the wallet waited instead of failing.
        assert_eq!(r.found, 3);
        let book = w.state.book().unwrap();
        assert!(book.chains[0].used.contains(&0) && book.chains[0].used.contains(&5) && book.chains[1].used.contains(&2));
        assert!(!book.scan_needed);
        assert!(refused.iter().any(|r| r.starts_with("503")) && refused.iter().any(|r| r.starts_with("429")), "{refused:?}");
        // Then an address is handed out, past the reserved range.
        *guard(&w.net.limits) = None;
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, r.issued[0]);
    }

    #[test]
    fn a_plan_and_its_confirmation_look_up_only_the_address_they_pay_from() {
        let (w, address) = funded("asked");
        // Two more pq2 addresses, and a coin of the ML-DSA-44 account that a payment no record names spends.
        block(new_pq2_address(&w.state)).unwrap();
        block(new_pq2_address(&w.state)).unwrap();
        let mldsa44 = w.state.templates().unwrap().1.address;
        guard(&w.net.utxos).insert(mldsa44, vec![held_by('9', 0, 40_000, 'e')]);
        // The refresh looks up every address (3 accounts, 3 pq2 addresses, on both sources).
        block(overview_of(&w.state)).unwrap();
        assert_eq!(guard(&w.net.asked).len(), 12);
        guard(&w.net.asked).clear();
        let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), None, None)).unwrap();
        assert!(guard(&w.net.asked).iter().all(|a| *a == address), "the plan asked for {:?}", guard(&w.net.asked));
        // The warning of a coin spent by a payment no record names still comes, from the refresh's answer.
        assert!(view.unrecorded);
        // The confirmation's re-check still looks up every address afresh (a risk that appears after the plan
        // sends it back to review), before and after its dialog.
        guard(&w.net.asked).clear();
        let own = w.state.own_templates().unwrap();
        let result = block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true))).unwrap();
        assert!(matches!(result.result, BroadcastResult::Sent { .. }));
        assert!(own.iter().all(|t| guard(&w.net.asked).contains(&t.address)), "the confirmation asked for {:?}", guard(&w.net.asked));
        // Answers older than a minute are asked for again; a lock forgets them all.
        for (_, (at, _)) in guard(&w.state.seen_coins).iter_mut() {
            *at -= SEEN_FOR + Duration::from_secs(1);
        }
        guard(&w.net.asked).clear();
        let funded_again = utxo('f', 0, 90_000, H4T + 9);
        guard(&w.net.utxos).insert(address.clone(), vec![funded_again]);
        block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.0001".into(), None, None)).unwrap();
        // Every address asked again, the change address the payment handed out included, on both sources.
        assert_eq!(guard(&w.net.asked).len(), 2 * w.state.own_templates().unwrap().len(), "every address asked again");
        w.state.lock();
        assert!(guard(&w.state.seen_coins).is_empty());
    }

    #[test]
    fn a_source_that_has_not_upgraded_is_named_as_the_reason() {
        let w = wallet("not-upgraded", words(0x7b), true, m4_state(H4T + 10, false));
        // The second node lists neither M4 deployment, nor the lattice state.
        let mut old = m4_state(H4T + 10, false);
        for name in ["p2mr_slhdsa128s", "p2mr_lattice_tripwire"] {
            old["deployments"].as_object_mut().unwrap().remove(name);
        }
        old["tripwire"].as_object_mut().unwrap().remove("lattice");
        *guard(&w.net.state_b) = Some(old.clone());
        let p = block(overview_of(&w.state)).unwrap().pq2.expect("a pq2 view that says why");
        assert_eq!((p.blocked, p.allowed, p.spend_allowed, p.opens_at), (Some("source_not_upgraded"), false, false, H4T + crate::chain::MARGIN));
        assert!(p.addresses.is_empty() && !p.complete);
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_source_not_upgraded");
        // A node of the release before M4-T lists OP_CHECKSLHDSA128S alone: the same reason.
        let mut m4s = m4_state(H4T + 10, false);
        m4s["deployments"].as_object_mut().unwrap().remove("p2mr_lattice_tripwire");
        m4s["tripwire"].as_object_mut().unwrap().remove("lattice");
        *guard(&w.net.state_b) = Some(m4s);
        assert_eq!(block(overview_of(&w.state)).unwrap().pq2.unwrap().blocked, Some("source_not_upgraded"));
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_source_not_upgraded");
        // The lattice tripwire without OP_CHECKSLHDSA128S is no node's: no pq2 view, as before.
        let mut odd = m4_state(H4T + 10, false);
        odd["deployments"].as_object_mut().unwrap().remove("p2mr_slhdsa128s");
        *guard(&w.net.state_b) = Some(odd);
        assert!(block(overview_of(&w.state)).unwrap().pq2.is_none());
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "address_not_ready");
        // Both upgraded: an address, as before.
        *guard(&w.net.state_b) = None;
        assert_eq!(block(overview_of(&w.state)).unwrap().pq2.unwrap().blocked, None);
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, 0);
    }

    #[test]
    fn a_command_locked_while_it_waits_writes_nothing_and_ends_locked() {
        for lookup_succeeds in [true, false] {
            let unit = Duration::from_millis(if lookup_succeeds { 200 } else { 20 });
            let w = wallet_waiting("locked-wait", words(0x7c), true, m4_state(H4T + 10, false), Some(unit));
            let from = w.state.templates().unwrap().1.address;
            guard(&w.net.utxos).insert(from.clone(), vec![utxo('9', 0, 500_000, 9_000)]);
            // A payment of the wallet's whose outcome is unknown: a plan looks it up again (refresh_sent).
            let unknown = ml_record(&w, &from, &"7d".repeat(32), "unknown", &[format!("{}:1", "8".repeat(64))]);
            let mark = |w: &Wallet| store::load::<Vec<Sent>>(&w.state.sent_path()).iter().find(|s| s.txid == unknown.txid).unwrap().lookup_mark;
            let before = mark(&w);
            if lookup_succeeds {
                // The lookup of the address it pays from is refused once on each source, then answered.
                let path = format!("/api/utxos?address={from}");
                guard(&w.net.limited_once).extend([path.clone(), path]);
            } else {
                // Refused until the call's deadline.
                let mut limits = SiteLimits::deployed(unit);
                limits.utxos = Bucket { tokens: 0.0, burst: 0.0, rate: 0.0, at: Instant::now() };
                *guard(&w.net.limits) = Some(limits);
            }
            std::thread::scope(|s| {
                let state = &w.state;
                let to = elsewhere();
                let command = s.spawn(move || block(plan_payment(state, Kind::Mldsa44, to, "0.001".into())));
                std::thread::sleep(unit / 2);
                state.lock();
                assert_eq!(command.join().unwrap().unwrap_err().code, "locked", "lookup succeeds: {lookup_succeeds}");
            });
            // Nothing written after the lock: no cached lookup, no lookup mark, no plan.
            assert!(guard(&w.state.seen_coins).is_empty(), "lookup succeeds: {lookup_succeeds}");
            assert_eq!(mark(&w), before, "lookup succeeds: {lookup_succeeds}");
            assert!(guard(&w.state.pending).is_none());
        }
    }

    #[test]
    fn a_payment_to_an_own_pq2_address_waits_for_pq2_whatever_account_pays() {
        // At 54998 a restored wallet's scan keeps its empty pq2 addresses; its fixed accounts hold coins.
        let w = wallet("own-pq2-gate", words(0x7d), false, m4_state(H4T - 2, false));
        block(scan_pq2(&w.state, false)).unwrap();
        let kept = pq2_address(&w, 0, 3);
        assert!(w.state.book().unwrap().chains[0].addresses.values().any(|a| *a == kept));
        let (schnorr, mldsa44, mixed) = w.state.templates().unwrap();
        for (t, c) in [(&schnorr, '7'), (&mldsa44, '8'), (&mixed, '9')] {
            guard(&w.net.utxos).insert(t.address.clone(), vec![utxo(c, 0, 500_000, 9_000)]);
        }
        // Planning: no payment from any account creates a pq2 output before the gate.
        for kind in [Kind::Schnorr, Kind::Mldsa44, Kind::Mixed] {
            assert_eq!(block(plan_payment(&w.state, kind, kept.clone(), "0.001".into())).unwrap_err().code, "destination_not_ready", "{kind:?}");
        }
        // Confirming: a plan made before the book knew its destination is refused once a scan has kept it.
        let later = pq2_address(&w, 0, 30);
        let view = block(plan_payment(&w.state, Kind::Mldsa44, later.clone(), "0.001".into())).unwrap();
        assert_ne!(guard(&w.state.pending).as_ref().unwrap().plan.lock_time, H4T);
        w.state.edit_book(|b| { b.chains[0].issued = 31; b.chains[0].addresses.insert(30, later.clone()); }).unwrap();
        assert_eq!(block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true))).unwrap_err().code, "chain_changed");
        assert!(guard(&w.net.broadcasts).is_empty());
        // Once pq2 is open, every account pays an own pq2 address with nLockTime H4T.
        *guard(&w.net.state) = m4_state(H4T + 10, false);
        for kind in [Kind::Schnorr, Kind::Mldsa44, Kind::Mixed] {
            block(plan_payment(&w.state, kind, kept.clone(), "0.001".into())).unwrap();
            let pending = guard(&w.state.pending).take().unwrap();
            assert!(pending.creates_pq2, "{kind:?}");
            assert_eq!(pending.plan.lock_time, H4T, "{kind:?}");
        }
        let from = pq2_address(&w, 0, 1);
        guard(&w.net.utxos).insert(from.clone(), vec![utxo('6', 0, 500_000, H4T + 7)]);
        block(plan_pq2_payment(&w.state, from, kept, "0.001".into(), None, None)).unwrap();
        assert_eq!(guard(&w.state.pending).take().unwrap().plan.lock_time, H4T);
    }

    #[test]
    fn a_coin_one_source_does_not_list_yet_stays_in_view_and_is_never_spent() {
        // A watched pq2 address with one confirmed output; the second source, a block behind, lists nothing.
        let w = wallet("one-source-coin", words(0x7e), true, m4_state(H4T + 10, false));
        let address = block(new_pq2_address(&w.state)).unwrap().address;
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('a', 0, 100_000, H4T + 9)]);
        *guard(&w.net.utxos_b) = Some(HashMap::new());
        let o = block(overview_of(&w.state)).unwrap();
        let p = o.pq2.unwrap();
        // The row stays, the coin is shown as on its way, the view says it may be incomplete; nothing spendable.
        let row = p.addresses.iter().find(|a| a.address == address).expect("the address row");
        assert_eq!((row.spendable, row.incoming), (0, 100_000));
        assert_eq!(row.coins.len(), 1);
        assert_eq!(row.coins[0].status, Pq2Status::Pending);
        assert!(!row.complete && !p.complete);
        assert_eq!(p.spendable, 0);
        // Nothing spends it.
        assert_eq!(block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.0001".into(), None, None)).unwrap_err().code, "no_coins");
        // Both list it: spendable, and complete again.
        *guard(&w.net.utxos_b) = None;
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert_eq!(p.spendable, 100_000);
        assert!(p.complete);
    }

    #[test]
    fn a_rebuild_too_large_for_slh_dsa_pays_what_fits_keeping_its_anchor() {
        // One pq2 address with 13 outputs of 100,000 sat, all sent through ML-DSA-44.
        let w = wallet("too-large", words(0x7f), true, m4_state(H4T + 10, false));
        let address = block(new_pq2_address(&w.state)).unwrap().address;
        guard(&w.net.utxos).insert(address.clone(), (0..13).map(|v| utxo('a', v, 100_000, H4T + 7)).collect());
        let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "all".into(), Some(Path::Mldsa44), None)).unwrap();
        assert_eq!((view.signature, view.inputs), (Path::Mldsa44, 13));
        // Never sent: ML-DSA-44 is disabled while the dialog is open; the rebuild through SLH-DSA, 13 inputs too
        // large, pays what 12 fit, for the user to confirm with its new amount.
        let net = w.net.clone();
        let result = block(send_plan(&w.state, &view.id, Some("en"), move |_| {
            *guard(&net.state) = m4_state(H4T + 11, true);
            std::future::ready(true)
        })).unwrap();
        let rebuilt = result.rebuilt.expect("a rebuild through SLH-DSA");
        assert_eq!((rebuilt.signature, rebuilt.inputs), (Path::Slhdsa128s, 12));
        assert!(rebuilt.send < view.send);
        guard(&w.state.pending).take();
        // Refused: the rebuild keeps the original's anchor among the 12.
        let all: Vec<String> = (0..13).map(|v| format!("{}:{v}", "a".repeat(64))).collect();
        let t = ml_record(&w, &address, &"7f".repeat(32), "rejected", &all);
        let mut records: Vec<Sent> = store::load(&w.state.sent_path());
        records.last_mut().unwrap().send = view.send;
        store::save(&w.state.sent_path(), &records).unwrap();
        let r = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        assert_eq!((r.signature, r.inputs), (Path::Slhdsa128s, 12));
        assert!(r.send < view.send);
        let coins: Vec<String> = guard(&w.state.pending).as_ref().unwrap().plan.coins.iter().map(Coin::outpoint).collect();
        assert!(coins.contains(&all[0]), "the anchor is spent");
    }

    #[test]
    fn an_own_pq2_address_that_appears_during_the_dialog_stops_the_payment() {
        for open in [false, true] {
            let tip = if open { H4T + 10 } else { H4T - 2 };
            let w = wallet("own-pq2-race", words(0x60 + open as u8), false, m4_state(tip, false));
            block(scan_pq2(&w.state, false)).unwrap();
            let mldsa44 = w.state.templates().unwrap().1.address;
            guard(&w.net.utxos).insert(mldsa44, vec![utxo('8', 0, 500_000, 9_000)]);
            // One of the wallet's own pq2 addresses the book does not know yet: the plan and the confirmation's
            // re-check see a payment to a foreign address.
            let later = pq2_address(&w, 0, 30);
            let view = block(plan_payment(&w.state, Kind::Mldsa44, later.clone(), "0.001".into())).unwrap();
            assert_ne!(guard(&w.state.pending).as_ref().unwrap().plan.lock_time, H4T);
            // A scan writes it into the book while the system dialog is open.
            let state = &w.state;
            let result = block(send_plan(state, &view.id, Some("en"), |_| {
                state.edit_book(|b| { b.chains[0].issued = 31; b.chains[0].addresses.insert(30, later.clone()); }).unwrap();
                std::future::ready(true)
            }));
            assert_eq!(result.err().map(|f| f.code), Some("chain_changed".to_string()), "pq2 open: {open}");
            assert!(guard(&w.net.broadcasts).is_empty(), "pq2 open: {open}");
            assert!(store::load::<Vec<Sent>>(&w.state.sent_path()).is_empty(), "pq2 open: {open}");
        }
        // An ordinary payment holds the book from that last check until it is recorded: no scan comes between.
        let (w, address) = funded("own-pq2-held");
        let view = block(plan_pq2_payment(&w.state, address, elsewhere(), "0.001".into(), None, None)).unwrap();
        let held = Arc::new(AtomicBool::new(false));
        let h = held.clone();
        *guard(&w.state.before_commit) = Some(Box::new(move |state: &AppState| h.store(state.book_ops.try_lock().is_err(), Ordering::SeqCst)));
        block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true))).unwrap();
        assert!(held.load(Ordering::SeqCst));
        assert!(w.state.book_ops.try_lock().is_ok());
    }

    #[test]
    fn a_late_scan_result_never_reaches_another_wallets_book() {
        for at_answer in [1usize, 2, 21, 40] {
            let w = wallet("scan-switch", words(0x5e), false, m4_state(H4T + 100, false));
            let a_first = pq2_address(&w, 0, 0);
            // While the scan of wallet A waits for the network, A is removed and B is restored.
            let mut answers = 0;
            *guard(&w.state.after_network_answer) = Some(Box::new(move |state: &AppState| {
                answers += 1;
                if answers == at_answer {
                    state.lock();
                    state.open_session(&words(0x5f), state.generation(), false).unwrap();
                }
            }));
            assert_eq!(block(scan_pq2(&w.state, false)).unwrap_err().code, "locked", "answer {at_answer}");
            *guard(&w.state.after_network_answer) = None;
            let book = w.state.book().unwrap();
            assert_ne!(pq2_address(&w, 0, 0), a_first);
            assert_eq!(book.wallet, pq2_address(&w, 0, 0));
            assert!(book.scan_needed, "answer {at_answer}: B still needs its own scan");
            assert!(book.chains.iter().all(|c| c.addresses.is_empty() && c.issued == 0 && c.scanned == 0), "answer {at_answer}");
        }
    }

    #[test]
    fn a_book_from_before_the_history_check_is_migrated_and_scanned_again() {
        let w = wallet("migrate", words(0x60), true, m4_state(H4T + 100, false));
        // A book as the version without the history check wrote it: version 1, no history tip, addresses
        // only for indices handed out or used, 2 to 21 reserved by its scan.
        let old = json!({
            "version": 1, "wallet": pq2_address(&w, 0, 0), "scan_needed": false,
            "chains": [
                {"issued": 22, "handed_out": [0, 1], "used": [1], "scanned": 22,
                 "addresses": {"0": pq2_address(&w, 0, 0), "1": pq2_address(&w, 0, 1)}},
                {"issued": 0, "handed_out": [], "used": [], "scanned": 0, "addresses": {}}
            ]
        });
        std::fs::write(w.state.pq2_path(), old.to_string()).unwrap();
        w.state.lock();
        w.state.open_session(&words(0x60), w.state.generation(), false).unwrap();
        let book = w.state.book().unwrap();
        // Every issued record kept, a new scan required, reserved addresses filled in.
        assert_eq!(book.version, 2);
        assert!(book.scan_needed);
        assert_eq!(book.chains[0].issued, 22);
        assert_eq!(book.chains[0].handed_out.iter().copied().collect::<Vec<_>>(), vec![0, 1]);
        assert!(book.chains[0].used.contains(&1));
        for i in 0..22 {
            assert_eq!(book.chains[0].addresses.get(&i), Some(&pq2_address(&w, 0, i)), "index {i}");
        }
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_scan_needed");
        // The reserved addresses are now checked by the refresh, and the scan completes the migration.
        block(scan_pq2(&w.state, false)).unwrap();
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, 22);
    }

    #[test]
    fn a_late_refresh_answer_never_reaches_another_wallets_book() {
        for at_answer in [1usize, 3] {
            let w = wallet("refresh-switch", words(0x61), false, m4_state(H4T + 100, false));
            block(scan_pq2(&w.state, false)).unwrap();
            // A's reserved index 2 was paid since the scan, and its address 20 (handed out) holds coins.
            *guard(&w.net.state) = m4_state(H4T + 110, false);
            guard(&w.net.history).insert(pq2_address(&w, 0, 2), H4T + 105);
            let a20 = block(new_pq2_address(&w.state)).unwrap().address;
            guard(&w.net.utxos).insert(a20, vec![utxo('a', 0, 5_000, H4T + 106)]);
            // While A's refresh waits for the network, A is removed and B is restored.
            let mut answers = 0;
            *guard(&w.state.after_network_answer) = Some(Box::new(move |state: &AppState| {
                answers += 1;
                if answers == at_answer {
                    state.lock();
                    state.open_session(&words(0x62), state.generation(), false).unwrap();
                }
            }));
            assert_eq!(block(overview_of(&w.state)).err().map(|f| f.code), Some("locked".to_string()), "answer {at_answer}");
            *guard(&w.state.after_network_answer) = None;
            let book = w.state.book().unwrap();
            assert_eq!(book.wallet, pq2_address(&w, 0, 0));
            assert!(book.scan_needed && watermarks(&book).is_empty(), "answer {at_answer}: no watermark of A");
            assert!(book.chains.iter().all(|c| c.addresses.is_empty() && c.used.is_empty()), "answer {at_answer}: nothing of A");
        }
    }

    #[test]
    fn a_use_found_later_extends_the_reserved_range_and_asks_for_a_scan() {
        let w = wallet("extend", words(0x63), false, m4_state(H4T + 100, false));
        // Restored with nothing found: 0 to 19 reserved, as the original wallet may have handed them out.
        block(scan_pq2(&w.state, false)).unwrap();
        assert_eq!(w.state.book().unwrap().chains[0].issued, 20);
        // Index 0 is paid later: the original wallet may now hand out 20.
        *guard(&w.net.state) = m4_state(H4T + 110, false);
        guard(&w.net.history).insert(pq2_address(&w, 0, 0), H4T + 105);
        block(overview_of(&w.state)).unwrap();
        let book = w.state.book().unwrap();
        assert!(book.chains[0].used.contains(&0));
        assert_eq!(book.chains[0].issued, 21, "a full gap past the highest used index");
        assert!(book.scan_needed);
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_scan_needed");
        block(scan_pq2(&w.state, false)).unwrap();
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, 21);
    }

    #[test]
    fn a_wider_scan_cut_short_leaves_a_scan_needed() {
        let w = wallet("wider-short", words(0x64), true, m4_state(H4T + 100, false));
        assert!(!w.state.book().unwrap().scan_needed);
        // The wider scan finds index 5 used on the receiving chain, then the site stops answering.
        guard(&w.net.history).insert(pq2_address(&w, 0, 5), H4T + 50);
        *guard(&w.net.history_ok) = Some(6);
        assert_eq!(block(scan_pq2(&w.state, true)).unwrap_err().code, "history_unavailable");
        let book = w.state.book().unwrap();
        assert!(book.chains[0].used.contains(&5));
        assert!(book.scan_needed, "no address while the use at 5 has no full gap after it");
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_scan_needed");
        *guard(&w.net.history_ok) = None;
        block(scan_pq2(&w.state, true)).unwrap();
        assert_eq!(block(new_pq2_address(&w.state)).unwrap().index, 26);
    }

    #[test]
    fn a_plain_scan_after_a_cut_wider_one_covers_the_use_it_found() {
        let w = wallet("cut-then-plain", words(0x66), false, m4_state(H4T + 100, false));
        block(scan_pq2(&w.state, false)).unwrap();
        // The wider scan finds index 80 used, saves it, and the site stops answering after 80's batch.
        guard(&w.net.history).insert(pq2_address(&w, 0, 80), H4T + 50);
        // Five batches of 20 (0 to 99), each asked of both APIs.
        *guard(&w.net.history_ok) = Some(10);
        assert_eq!(block(scan_pq2(&w.state, true)).unwrap_err().code, "history_unavailable");
        assert!(w.state.book().unwrap().chains[0].used.contains(&80));
        // A plain scan must cover the reserved range and a full gap past 80, every address saved.
        *guard(&w.net.history_ok) = None;
        block(scan_pq2(&w.state, false)).unwrap();
        let book = w.state.book().unwrap();
        assert!(!book.scan_needed);
        assert!(book.chains[0].issued >= 101);
        for i in 0..book.chains[0].issued {
            assert!(book.chains[0].addresses.contains_key(&i), "the address of index {i} is in the book");
        }
        // So a later payment to index 90 is seen by the refresh.
        *guard(&w.net.state) = m4_state(H4T + 120, false);
        guard(&w.net.history).insert(pq2_address(&w, 0, 90), H4T + 115);
        block(overview_of(&w.state)).unwrap();
        assert!(w.state.book().unwrap().chains[0].used.contains(&90));
    }

    #[test]
    fn a_scan_does_not_clear_a_requirement_raised_while_it_ran() {
        let w = wallet("scan-revision", words(0x67), false, m4_state(H4T + 100, false));
        block(scan_pq2(&w.state, false)).unwrap();
        // While a wider scan runs, something else requires a scan (a use found by a refresh).
        let mut raised = false;
        *guard(&w.state.after_network_answer) = Some(Box::new(move |state: &AppState| {
            if !raised {
                raised = true;
                state.edit_book(|b| b.require_scan()).unwrap();
            }
        }));
        block(scan_pq2(&w.state, true)).unwrap();
        *guard(&w.state.after_network_answer) = None;
        assert!(w.state.book().unwrap().scan_needed, "raised during the scan: it stays until another scan");
        block(scan_pq2(&w.state, false)).unwrap();
        assert!(!w.state.book().unwrap().scan_needed);
    }

    #[test]
    fn a_use_seen_in_a_coin_lookup_extends_the_reserved_range() {
        let w = wallet("coin-use", words(0x68), false, m4_state(H4T + 100, false));
        block(scan_pq2(&w.state, false)).unwrap();
        // Reserved index 19 receives a payment, seen by a coin lookup before any history check.
        let address = pq2_address(&w, 0, 19);
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('a', 0, 300_000, H4T + 101)]);
        let _ = block(plan_pq2_payment(&w.state, address, elsewhere(), "all".into(), None, None));
        let book = w.state.book().unwrap();
        assert!(book.chains[0].used.contains(&19));
        assert_eq!(book.chains[0].issued, 40, "a full gap past 19");
        assert!(book.scan_needed);
        assert_eq!(block(new_pq2_address(&w.state)).unwrap_err().code, "pq2_scan_needed");
    }

    #[test]
    fn a_refresh_of_activity_or_a_new_address_never_mixes_two_wallets() {
        // Activity: A's records are looked up; meanwhile A is removed and B restored.
        let (w, address) = funded("activity-switch");
        ml_record(&w, &address, &"76".repeat(32), "rejected", &[format!("{}:0", "d".repeat(64))]);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        *guard(&w.state.after_network_answer) = Some(Box::new(|state: &AppState| {
            state.lock();
            state.open_session(&words(0x6a), state.generation(), false).unwrap();
        }));
        assert_eq!(block(activity_of(&w.state)).err().map(|f| f.code), Some("locked".to_string()));
        // A new address: A's request waits on the chain state; meanwhile A is replaced by a wallet made here.
        let (w, _) = funded("address-switch");
        let a_book = w.state.book().unwrap();
        *guard(&w.state.after_network_answer) = Some(Box::new(|state: &AppState| {
            state.lock();
            state.open_session(&words(0x6b), state.generation(), true).unwrap();
        }));
        assert_eq!(block(new_pq2_address(&w.state)).err().map(|f| f.code), Some("locked".to_string()));
        *guard(&w.state.after_network_answer) = None;
        let b_book = w.state.book().unwrap();
        assert_ne!(b_book.wallet, a_book.wallet);
        assert!(b_book.chains[0].handed_out.is_empty(), "nothing handed out in B for A's request");
    }

    #[test]
    fn the_wider_scan_looks_at_the_scanned_range_again() {
        let w = wallet("wider-again", words(0x58), false, m4_state(H4T + 100, false));
        block(scan_pq2(&w.state, false)).unwrap();
        // A payment to index 5 that the history check of a refresh missed (the site could not answer then).
        *guard(&w.net.history_fails) = Some((503, r#"{"error":"busy"}"#.to_string()));
        guard(&w.net.history).insert(pq2_address(&w, 0, 5), H4T + 50);
        assert!(!block(overview_of(&w.state)).unwrap().pq2.unwrap().complete);
        assert!(!w.state.book().unwrap().chains[0].used.contains(&5));
        *guard(&w.net.history_fails) = None;
        let r = block(scan_pq2(&w.state, true)).unwrap();
        assert_eq!(r.found, 1);
        assert!(w.state.book().unwrap().chains[0].used.contains(&5));
    }

    /// A wallet with one pq2 receiving address holding two coins, at H4T + 10.
    fn funded(label: &str) -> (Wallet, String) {
        let w = wallet(label, words(0x33), true, m4_state(H4T + 10, false));
        let address = block(new_pq2_address(&w.state)).unwrap().address;
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('d', 0, 150_000, H4T + 7), utxo('e', 2, 60_000, H4T - 3)]);
        (w, address)
    }

    fn elsewhere() -> String {
        Template::schnorr(&[9u8; 32]).address
    }

    #[test]
    fn pq2_coins_show_their_status_and_spends_take_all_of_them_through_slh_by_default() {
        let (w, address) = funded("status");
        guard(&w.net.incoming).insert(address.clone(), vec![json!({"txid": "f0".repeat(32), "vout": 1, "sats": 1_000})]);
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        let statuses: Vec<(u64, Pq2Status)> = p.addresses[0].coins.iter().map(|c| (c.sats, c.status)).collect();
        assert_eq!(statuses, vec![(150_000, Pq2Status::Protected), (60_000, Pq2Status::Unprotected), (1_000, Pq2Status::Pending)]);
        // A reorganization that confirms the first coin lower: recomputed from what the API says now.
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('d', 0, 150_000, H4T - 1), utxo('e', 2, 60_000, H4T - 3)]);
        let p = block(overview_of(&w.state)).unwrap().pq2.unwrap();
        assert_eq!(p.addresses[0].coins[0].status, Pq2Status::Unprotected);
        guard(&w.net.incoming).clear();
        // The default leaf, the larger coin alone (the other stays), change to the change chain, H4T as
        // lock time.
        let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), None, None)).unwrap();
        assert_eq!((view.signature, view.inputs), (Path::Slhdsa128s, 1));
        let p = view.pq2.as_ref().unwrap();
        assert!(!p.several_coins && p.mldsa44_allowed);
        assert_eq!((p.staying_coins, p.staying_sats), (1, 60_000));
        assert_eq!(p.witness_bytes, 7_972);
        assert_eq!(p.change_address.as_deref(), Some(pq2_address(&w, 1, 0).as_str()));
        let pending = guard(&w.state.pending).take().unwrap();
        assert_eq!(pending.plan.lock_time, H4T);
        assert_eq!(pending.plan.outputs[1].1, w.state.pq2_template(1, 0).unwrap().script_pubkey);
        // The ML-DSA-44 leaf when asked and allowed: 3,795 bytes of witness.
        let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
        assert_eq!((view.signature, view.pq2.as_ref().unwrap().witness_bytes), (Path::Mldsa44, 3_795));
        // Not offered once the node reports it off, nor while that is unknown.
        for flag in [json!(true), json!(null)] {
            // Disabled: a tripwire reported missing, and the flag that follows from it.
            let mut s = m4_state(H4T + 10, flag == json!(true));
            s["tripwire"]["lattice"]["mldsa_disabled_next_block"] = flag.clone();
            *guard(&w.net.state) = s;
            let result = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), Some(Path::Mldsa44), None));
            if flag.is_null() {
                // Unknown state: no new pq2 output, so no change; a spend goes through the SLH-DSA leaf,
                // without change, with the lock time of the rules before.
                assert_eq!(result.err().unwrap().code, "pq2_change_limit");
                let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "all".into(), Some(Path::Mldsa44), None)).unwrap();
                assert_eq!((view.signature, view.change), (Path::Slhdsa128s, 0));
                assert_eq!(view.pq2.as_ref().unwrap().mldsa44_reason, Some("unknown"));
                assert_eq!(guard(&w.state.pending).take().unwrap().plan.lock_time, crate::chain::TRIPWIRE_HEIGHT);
            } else {
                let view = result.unwrap();
                assert_eq!(view.signature, Path::Slhdsa128s);
                let p = view.pq2.unwrap();
                assert_eq!((p.mldsa44_allowed, p.mldsa44_reason), (false, Some("disabled")));
            }
        }
    }

    #[test]
    fn at_the_change_chains_limit_only_a_payment_without_change_goes() {
        let (w, address) = funded("change-limit");
        w.state.edit_book(|b| {
            for i in 0..GAP_LIMIT {
                b.chains[1].issue(i, &format!("tb1zchange{i}"));
            }
        }).unwrap();
        let err = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), None, None)).unwrap_err();
        assert_eq!(err.code, "pq2_change_limit");
        let view = block(plan_pq2_payment(&w.state, address, elsewhere(), "all".into(), None, None)).unwrap();
        assert_eq!(view.change, 0);
        let p = view.pq2.unwrap();
        assert!(p.change_blocked && p.change_address.is_none());
    }

    #[test]
    fn other_payments_keep_their_lock_time_unless_they_pay_a_pq2_address_of_the_wallet() {
        let (w, pq2) = funded("lock-time");
        let mldsa44 = w.state.templates().unwrap().1.address;
        guard(&w.net.utxos).insert(mldsa44, vec![utxo('9', 0, 500_000, 9_000)]);
        block(plan_payment(&w.state, Kind::Mldsa44, elsewhere(), "0.001".into())).unwrap();
        assert_eq!(guard(&w.state.pending).take().unwrap().plan.lock_time, crate::chain::TRIPWIRE_HEIGHT);
        block(plan_payment(&w.state, Kind::Mldsa44, pq2, "0.001".into())).unwrap();
        let pending = guard(&w.state.pending).take().unwrap();
        assert!(pending.creates_pq2);
        assert_eq!(pending.plan.lock_time, H4T);
        // Before H4T + 6 the wallet does not pay its own pq2 address at all.
        *guard(&w.net.state) = m4_state(H4T + 5, false);
        let own = pq2_address(&w, 0, 0);
        assert_eq!(block(plan_payment(&w.state, Kind::Mldsa44, own, "0.001".into())).unwrap_err().code, "destination_not_ready");
    }

    #[test]
    fn a_flip_before_broadcasting_drops_the_ml_dsa_spend_and_rebuilds_it_through_slh() {
        let (w, address) = funded("flip");
        let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
        assert_eq!(view.signature, Path::Mldsa44);
        // The tripwire is spent while the system dialog is open: the state flips before broadcasting.
        let net = w.net.clone();
        let result = block(send_plan(&w.state, &view.id, Some("en"), move |_| {
            *guard(&net.state) = m4_state(H4T + 11, true);
            std::future::ready(true)
        })).unwrap();
        // Nothing went out and nothing was recorded; the change address was not handed out.
        assert!(guard(&w.net.broadcasts).is_empty());
        assert!(store::load::<Vec<Sent>>(&w.state.sent_path()).is_empty());
        assert_eq!(w.state.book().unwrap().chains[1].issued, 0);
        assert!(result.txid.is_empty());
        let rebuilt = result.rebuilt.unwrap();
        // Dropped before it was sent, the original binds nothing: the fewest coins that pay, as any payment.
        assert_eq!((rebuilt.signature, rebuilt.inputs), (Path::Slhdsa128s, 1));
        // The rebuild goes through the system dialog like any payment, then out.
        let sent = block(send_plan(&w.state, &rebuilt.id, Some("en"), |_| std::future::ready(true))).unwrap();
        assert!(matches!(sent.result, BroadcastResult::Sent { .. }));
        let broadcasts = guard(&w.net.broadcasts).clone();
        // Sent to both APIs, the same transaction.
        assert_eq!(broadcasts.len(), 2);
        assert_eq!(broadcasts[0], broadcasts[1]);
        let tx = decode(&hex::decode(&broadcasts[0]).unwrap());
        assert_eq!(tx.lock_time, H4T);
        assert!(tx.inputs.iter().all(|i| i.sequence == crate::tx::SEQUENCE));
        // Each input through SLH1: sixteen pieces, the leaf, and the control block e3 <S1's hash>.
        let leaf = w.state.pq2_template(0, 0).unwrap().slhdsa128s_leaf.unwrap();
        for input in &tx.inputs {
            assert_eq!(input.witness.len(), 18);
            assert_eq!((&input.witness[16], &input.witness[17]), (&leaf.script, &leaf.control_block));
        }
        let record = &store::load::<Vec<Sent>>(&w.state.sent_path())[0];
        assert_eq!((record.from.as_str(), record.address.as_str(), record.signature.as_str(), record.status.as_str()), ("pq2", address.as_str(), "slhdsa128s", "mempool"));
        assert_eq!(w.state.book().unwrap().chains[1].handed_out.iter().copied().collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn a_stale_snapshot_before_broadcasting_counts_as_unknown_and_rebuilds_through_slh() {
        let (w, address) = funded("stale");
        let view = block(plan_pq2_payment(&w.state, address, elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
        assert_eq!(view.signature, Path::Mldsa44);
        // The node moves on, the API keeps answering the old "not disabled" snapshot.
        let net = w.net.clone();
        let result = block(send_plan(&w.state, &view.id, Some("en"), move |_| {
            let mut stale = m4_state(H4T + 12, false);
            stale["tripwire"]["tip_height"] = json!(H4T + 10);
            *guard(&net.state) = stale;
            std::future::ready(true)
        })).unwrap();
        assert!(guard(&w.net.broadcasts).is_empty());
        assert_eq!(result.rebuilt.unwrap().signature, Path::Slhdsa128s);
    }

    #[test]
    fn a_plan_begun_before_a_lock_never_replaces_a_later_one() {
        for fallback in [false, true] {
            let (w, address) = funded(if fallback { "kept-fallback" } else { "kept-plan" });
            let ml = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
            // Plan R has passed its last check; before it is kept, the wallet is locked and unlocked and a
            // new plan N is made.
            let newer: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let n_id = newer.clone();
            let to = address.clone();
            *guard(&w.state.before_plan_kept) = Some(Box::new(move |state: &AppState| {
                state.lock();
                state.open_session(&words(0x33), state.generation(), true).unwrap();
                let n = std::thread::scope(|s| s.spawn(|| block(plan_pq2_payment(state, to.clone(), elsewhere(), "0.002".into(), None, None))).join().unwrap()).unwrap();
                *guard(&n_id) = Some(n.id);
            }));
            let result = if fallback {
                // R is the SLH-DSA plan that replaces an ML-DSA-44 payment dropped unsent.
                let net = w.net.clone();
                block(send_plan(&w.state, &ml.id, Some("en"), move |_| {
                    *guard(&net.state) = m4_state(H4T + 11, true);
                    std::future::ready(true)
                })).map(|_| ())
            } else {
                block(plan_pq2_payment(&w.state, address, elsewhere(), "0.001".into(), None, None)).map(|_| ())
            };
            assert_eq!(result.unwrap_err().code, "locked", "fallback: {fallback}");
            // N is the plan kept, and it can be confirmed.
            let n = guard(&newer).clone().unwrap();
            assert_eq!(guard(&w.state.pending).as_ref().map(|p| p.id.clone()), Some(n.clone()), "fallback: {fallback}");
            assert!(guard(&w.net.broadcasts).is_empty());
            block(send_plan(&w.state, &n, Some("en"), |_| std::future::ready(true))).unwrap();
            assert!(!guard(&w.net.broadcasts).is_empty());
        }
    }

    #[test]
    fn an_unsent_fallback_stays_with_the_wallet_it_began_for() {
        let (w, address) = funded("fallback-switch");
        let view = block(plan_pq2_payment(&w.state, address, elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
        // The tripwire is spent while the dialog is open, and while the state is read again the wallet is
        // replaced: the fallback through SLH-DSA must not be planned for the new wallet.
        let net = w.net.clone();
        *guard(&w.state.after_network_answer) = Some(Box::new(|state: &AppState| {
            state.lock();
            state.open_session(&words(0x6e), state.generation(), true).unwrap();
        }));
        let result = block(send_plan(&w.state, &view.id, Some("en"), move |_| {
            *guard(&net.state) = m4_state(H4T + 11, true);
            std::future::ready(true)
        }));
        *guard(&w.state.after_network_answer) = None;
        assert_eq!(result.err().map(|f| f.code), Some("locked".to_string()));
        assert!(guard(&w.state.pending).is_none(), "no plan kept for the new wallet");
        assert!(guard(&w.net.broadcasts).is_empty());
    }

    #[test]
    fn a_rebuild_plan_stays_with_the_session_it_began_in() {
        // The wallet is locked and unlocked again while the plan waits for the node's state: the plan
        // begun before the lock is not saved into the new session.
        let (w, address) = funded("rebuild-relock");
        let t = ml_record(&w, &address, &"81".repeat(32), "rejected", &[format!("{}:0", "d".repeat(64))]);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        let mut fired = false;
        *guard(&w.state.after_network_answer) = Some(Box::new(move |state: &AppState| {
            if !std::mem::replace(&mut fired, true) {
                state.lock();
                state.open_session(&words(0x33), state.generation(), true).unwrap();
            }
        }));
        assert_eq!(block(rebuild_plan(&w.state, &t.txid)).unwrap_err().code, "locked");
        *guard(&w.state.after_network_answer) = None;
        assert!(guard(&w.state.pending).is_none());
        // Unchanged, the same rebuild is planned.
        assert!(block(rebuild_plan(&w.state, &t.txid)).is_ok());
        // The rebuild after a refused broadcast keeps the confirmation's snapshot: relocked meanwhile,
        // no rebuild is offered and nothing is saved.
        let (w, address) = funded("refused-relock");
        let view = block(plan_pq2_payment(&w.state, address, elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
        *guard(&w.net.refuse) = Some("refused".into());
        *guard(&w.net.on_broadcast) = Some(m4_state(H4T + 11, true));
        // Armed once the payment is committed, so that it fires in the rebuild that follows.
        *guard(&w.state.before_commit) = Some(Box::new(|state: &AppState| {
            let mut fired = false;
            *guard(&state.after_network_answer) = Some(Box::new(move |state: &AppState| {
                if !std::mem::replace(&mut fired, true) {
                    state.lock();
                    state.open_session(&words(0x33), state.generation(), true).unwrap();
                }
            }));
        }));
        let result = block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true)));
        *guard(&w.state.after_network_answer) = None;
        // The confirmation, stale after its first answer since the commit, ends locked: its refusal recorded
        // before, no rebuild, nothing saved.
        assert_eq!(result.unwrap_err().code, "locked");
        assert!(guard(&w.state.pending).is_none());
        let records: Vec<Sent> = store::load(&w.state.sent_path());
        assert_eq!(records[0].status, "rejected");
    }

    #[test]
    fn a_refused_ml_dsa_spend_is_rebuilt_when_the_state_says_so_whatever_the_refusal_says() {
        for flips in [false, true] {
            let (w, address) = funded(if flips { "refused-flip" } else { "refused-same" });
            let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
            // The same refusal text either way: the decision goes by the node's state.
            *guard(&w.net.refuse) = Some("mempool-script-verify-flag-failed (ML-DSA-44 signature checks are disabled in this leaf)".into());
            if flips {
                *guard(&w.net.on_broadcast) = Some(m4_state(H4T + 11, true));
            }
            let result = block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true))).unwrap();
            assert!(matches!(result.result, BroadcastResult::Rejected { .. }));
            let records: Vec<Sent> = store::load(&w.state.sent_path());
            assert_eq!((records[0].status.as_str(), records[0].signature.as_str()), ("rejected", "mldsa44"));
            assert_eq!(result.rebuild_error, None);
            if flips {
                let rebuilt = result.rebuilt.unwrap();
                assert_eq!(rebuilt.signature, Path::Slhdsa128s);
                assert_eq!(rebuilt.pq2.as_ref().unwrap().rebuilt_from.as_deref(), Some(result.txid.as_str()));
                // It spends a coin of the refused payment, so the two can never both go through.
                assert_eq!(rebuilt.replaces, 1);
                let pending = guard(&w.state.pending).take().unwrap();
                assert!(records[0].outpoints.iter().any(|o| pending.plan.coins.iter().any(|c| &c.outpoint() == o)));
            } else {
                assert!(result.rebuilt.is_none());
            }
        }
    }

    #[test]
    fn a_rebuild_that_cannot_be_planned_after_a_refusal_says_why() {
        let (w, address) = funded("rebuild-error");
        let view = block(plan_pq2_payment(&w.state, address, elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
        *guard(&w.net.refuse) = Some("mempool-script-verify-flag-failed (ML-DSA-44 signature checks are disabled in this leaf)".into());
        *guard(&w.net.on_broadcast) = Some(m4_state(H4T + 11, true));
        // Once the payment is committed the site takes no more coin lookups: the rebuild's are refused (limit).
        let net = w.net.clone();
        *guard(&w.state.before_commit) = Some(Box::new(move |_: &AppState| {
            let mut limits = SiteLimits::deployed(Duration::from_millis(10));
            limits.utxos = Bucket { tokens: 0.0, burst: 0.0, rate: 0.0, at: Instant::now() };
            *guard(&net.limits) = Some(limits);
        }));
        let result = block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true))).unwrap();
        assert!(matches!(result.result, BroadcastResult::Rejected { .. }));
        assert!(result.rebuilt.is_none());
        assert_eq!(result.rebuild_error.as_deref(), Some("limit"));
        // The activity view offers it once the site answers again.
        *guard(&w.net.limits) = None;
        let activity = block(activity_of(&w.state)).unwrap();
        assert!(activity.iter().any(|a| a.sent.txid == result.txid && a.rebuild));
        assert_eq!(block(rebuild_plan(&w.state, &result.txid)).unwrap().signature, Path::Slhdsa128s);
    }

    #[test]
    fn a_lock_while_the_rebuild_after_a_refusal_waits_ends_the_confirmation_locked() {
        let (w, address) = funded("rebuild-locked");
        let view = block(plan_pq2_payment(&w.state, address, elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
        *guard(&w.net.refuse) = Some("mempool-script-verify-flag-failed (ML-DSA-44 signature checks are disabled in this leaf)".into());
        *guard(&w.net.on_broadcast) = Some(m4_state(H4T + 11, true));
        // After the commit: the state query right after the refusal passes; the wallet is locked during the
        // rebuild's first wait on the network.
        *guard(&w.state.before_commit) = Some(Box::new(|state: &AppState| {
            let mut answers = 0;
            *guard(&state.after_network_answer) = Some(Box::new(move |state: &AppState| {
                answers += 1;
                if answers == 2 {
                    state.lock();
                }
            }));
        }));
        let result = block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true)));
        *guard(&w.state.after_network_answer) = None;
        assert_eq!(result.err().map(|f| f.code), Some("locked".to_string()));
        let records: Vec<Sent> = store::load(&w.state.sent_path());
        assert_eq!(records[0].status, "rejected");
        assert!(guard(&w.state.pending).is_none());
    }

    #[test]
    fn an_ml_dsa_spend_that_left_the_mempool_is_offered_a_rebuild_while_the_state_says_so() {
        let (w, address) = funded("left");
        let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
        let sent = block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true))).unwrap();
        assert!(sent.rebuilt.is_none());
        // The node no longer has it (the API's /api/tx says unknown): "unknown" after the next lookup.
        let items = block(activity_of(&w.state)).unwrap();
        assert_eq!(items[0].sent.status, "unknown");
        assert!(!items[0].rebuild);
        assert_eq!(block(rebuild_plan(&w.state, &sent.txid)).unwrap_err().code, "no_rebuild");
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        let items = block(activity_of(&w.state)).unwrap();
        assert!(items[0].rebuild);
        let rebuilt = block(rebuild_plan(&w.state, &sent.txid)).unwrap();
        assert_eq!((rebuilt.signature, rebuilt.replaces), (Path::Slhdsa128s, 1));
        assert_eq!(rebuilt.send, 100_000);
    }

    /// A pq2 address with one large coin and `dust` small ones.
    fn dusted(label: &str, dust: u32) -> (Wallet, String) {
        let w = wallet(label, words(0x44), true, m4_state(H4T + 10, false));
        let address = block(new_pq2_address(&w.state)).unwrap().address;
        let mut utxos = vec![utxo('9', 0, 500_000, H4T + 7)];
        utxos.extend((0..dust).map(|i| utxo('8', i + 1, 1_000, H4T + 8)));
        guard(&w.net.utxos).insert(address.clone(), utxos);
        (w, address)
    }

    #[test]
    fn small_coins_do_not_lock_an_address_through_the_slh_leaf() {
        for dust in [13u32, 30] {
            let (w, address) = dusted(&format!("dust-{dust}"), dust);
            // A fixed amount: the fewest coins that pay it, largest first.
            let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), None, None)).unwrap();
            assert_eq!((view.signature, view.inputs), (Path::Slhdsa128s, 1), "{dust}");
            let p = view.pq2.as_ref().unwrap();
            assert_eq!((p.staying_coins, p.staying_sats), (dust as usize, u64::from(dust) * 1_000));
            assert!(!p.several_coins);
            // "All": as many as fit, largest first; the rest stays for another payment.
            let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "all".into(), None, None)).unwrap();
            assert!(view.size <= wallet::MAX_TX_BYTES && view.inputs >= 10 && view.inputs < dust as usize + 1, "{dust}: {}", view.inputs);
            assert_eq!(view.left, dust as usize + 1 - view.inputs);
            let pending = guard(&w.state.pending).take().unwrap();
            assert_eq!(pending.plan.coins[0].sats, 500_000);
            let p = view.pq2.unwrap();
            assert_eq!(p.staying_coins, dust as usize + 1 - view.inputs);
            // The ML-DSA-44 leaf takes every coin or none: 14 coins fit, 31 do not.
            let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
            if dust == 13 {
                assert_eq!((view.signature, view.inputs), (Path::Mldsa44, 14));
            } else {
                assert_eq!(view.signature, Path::Slhdsa128s);
                let p = view.pq2.unwrap();
                assert_eq!((p.mldsa44_allowed, p.mldsa44_reason), (false, Some("too_many_coins")));
            }
            let fits = block(overview_of(&w.state)).unwrap().pq2.unwrap().addresses[0].mldsa44_fits;
            assert_eq!(fits, dust == 13);
        }
    }

    /// An ML-DSA-44 payment from the funded address that got no clear answer, spending coin d:0.
    fn unclear_mldsa_payment(w: &Wallet, address: &str) -> Sent {
        let old = Sent {
            txid: "77".repeat(32), created: now(), from: "pq2".into(), address: address.into(), to: elsewhere(),
            send: 100_000, fee: 4_000, change: 0, vsize: 1_000, size: 4_000, signature: "mldsa44".into(), inputs: 1,
            sign_ms: 1.0, status: "unknown".into(), confirmations: 0, proof_verified: false, reason: String::new(),
            outpoints: vec![format!("{}:0", "d".repeat(64))], doubted: true, lookup_mark: 0,
        };
        store::save(&w.state.sent_path(), &vec![old.clone()]).unwrap();
        old
    }

    #[test]
    fn a_rebuild_is_bound_to_the_payment_it_replaces() {
        let (w, address) = funded("bound");
        let old = unclear_mldsa_payment(&w, &address);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        // The original was confirmed in the block that spent a tripwire; new coins reached the address.
        guard(&w.net.txs).insert(old.txid.clone(), json!({"status": "confirmed", "confirmations": 2}));
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('5', 0, 400_000, H4T + 11)]);
        assert_eq!(block(rebuild_plan(&w.state, &old.txid)).unwrap_err().code, "rebuild_original_went_out");
        assert_eq!(store::load::<Vec<Sent>>(&w.state.sent_path())[0].status, "confirmed");
        // Still unclear, but its coin is gone and only a new coin is there: no rebuild from other coins.
        let (w, address) = funded("bound-spent");
        let old = unclear_mldsa_payment(&w, &address);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('5', 0, 400_000, H4T + 11)]);
        assert_eq!(block(rebuild_plan(&w.state, &old.txid)).unwrap_err().code, "rebuild_anchor_unavailable");
    }

    #[test]
    fn a_rebuild_is_not_sent_once_its_original_turns_up() {
        let (w, address) = funded("bound-late");
        let old = unclear_mldsa_payment(&w, &address);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        let plan = block(rebuild_plan(&w.state, &old.txid)).unwrap();
        // The rebuild spends the original's coin d:0.
        assert!(guard(&w.state.pending).as_ref().unwrap().plan.coins.iter().any(|c| c.outpoint() == old.outpoints[0]));
        // While the dialog is open the original turns up in the mempool after all.
        let net = w.net.clone();
        let txid = old.txid.clone();
        let err = block(send_plan(&w.state, &plan.id, Some("en"), move |_| {
            guard(&net.txs).insert(txid, json!({"status": "mempool"}));
            std::future::ready(true)
        })).unwrap_err();
        assert_eq!(err.code, "rebuild_original_went_out");
        assert!(guard(&w.net.broadcasts).is_empty());
        let records: Vec<Sent> = store::load(&w.state.sent_path());
        assert_eq!((records.len(), records[0].status.as_str()), (1, "mempool"));
    }

    #[test]
    fn a_plan_that_fell_back_to_slh_can_be_confirmed() {
        let (w, address) = dusted("fallback-confirm", 30);
        // ML-DSA-44 asked for, but the 31 coins do not fit: the plan goes through SLH-DSA.
        let view = block(plan_pq2_payment(&w.state, address, elsewhere(), "0.001".into(), Some(Path::Mldsa44), None)).unwrap();
        assert_eq!(view.signature, Path::Slhdsa128s);
        let sent = block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true))).unwrap();
        assert!(matches!(sent.result, BroadcastResult::Sent { .. }), "{sent:?}");
    }

    #[test]
    fn no_change_address_while_a_scan_is_needed() {
        let w = wallet("scan-change", words(0x5c), false, m4_state(H4T + 100, false));
        // The scan finds coins at receiving index 2, then the site stops answering about history.
        guard(&w.net.utxos).insert(pq2_address(&w, 0, 2), vec![utxo('a', 0, 300_000, H4T + 50)]);
        *guard(&w.net.history_ok) = Some(1);
        assert_eq!(block(scan_pq2(&w.state, false)).unwrap_err().code, "history_unavailable");
        let book = w.state.book().unwrap();
        assert!(book.scan_needed && book.chains[0].used.contains(&2));
        let address = pq2_address(&w, 0, 2);
        // The coins can be spent, but only without change: no new address while the scan is incomplete.
        assert_eq!(block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), None, None)).unwrap_err().code, "pq2_change_limit");
        let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "all".into(), None, None)).unwrap();
        assert!(view.change == 0 && view.pq2.unwrap().change_blocked);
        // A plan with change made before the scan became needed is refused at the final issue.
        *guard(&w.net.history_ok) = None;
        block(scan_pq2(&w.state, false)).unwrap();
        let view = block(plan_pq2_payment(&w.state, address, elsewhere(), "0.001".into(), None, None)).unwrap();
        assert!(view.change > 0);
        let state = &w.state;
        let result = block(send_plan(state, &view.id, Some("en"), |_| {
            state.edit_book(|b| b.require_scan()).unwrap();
            std::future::ready(true)
        }));
        assert_eq!(result.unwrap_err().code, "pq2_scan_needed");
        assert!(guard(&w.net.broadcasts).is_empty());
        assert!(w.state.book().unwrap().chains[1].handed_out.is_empty());
    }

    #[test]
    fn a_change_address_waits_for_an_operation_on_the_book_in_progress() {
        let (w, address) = funded("change-waits");
        let view = block(plan_pq2_payment(&w.state, address, elsewhere(), "0.001".into(), None, None)).unwrap();
        assert!(view.change > 0);
        let reached = Arc::new(AtomicBool::new(false));
        let r = reached.clone();
        // Another operation on the book (a scan, say) holds it while the payment is confirmed.
        let held = w.state.book_ops.try_lock().unwrap();
        std::thread::scope(|s| {
            let state = &w.state;
            let id = view.id.clone();
            let send = s.spawn(move || block(send_plan(state, &id, Some("en"), move |_| {
                r.store(true, Ordering::SeqCst);
                std::future::ready(true)
            })));
            let started = Instant::now();
            while !reached.load(Ordering::SeqCst) {
                assert!(started.elapsed() < Duration::from_secs(120));
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_millis(200));
            // Confirmed in its dialog, it waits for the book before its last check and signing: nothing handed
            // out or sent.
            assert!(!send.is_finished());
            assert!(guard(&w.net.broadcasts).is_empty());
            assert!(w.state.book().unwrap().chains[1].handed_out.is_empty());
            drop(held);
            send.join().unwrap().unwrap();
        });
        assert!(!guard(&w.net.broadcasts).is_empty());
        assert!(w.state.book().unwrap().chains[1].handed_out.contains(&0));
    }

    /// An ML-DSA-44 payment of the wallet's, recorded with this status and these inputs.
    fn ml_record(w: &Wallet, address: &str, txid: &str, status: &str, inputs: &[String]) -> Sent {
        let record = Sent {
            txid: txid.into(), created: now(), from: "pq2".into(), address: address.into(), to: elsewhere(),
            send: 100_000, fee: 4_000, change: 0, vsize: 1_000, size: 4_000, signature: "mldsa44".into(), inputs: inputs.len(),
            sign_ms: 1.0, status: status.into(), confirmations: 0, proof_verified: false, reason: String::new(),
            outpoints: inputs.to_vec(), doubted: true, lookup_mark: 0,
        };
        let mut all: Vec<Sent> = store::load(&w.state.sent_path());
        all.push(record.clone());
        store::save(&w.state.sent_path(), &all).unwrap();
        record
    }

    fn held_by(txid: char, vout: u32, sats: u64, by: char) -> Value {
        json!({"txid": txid.to_string().repeat(64), "vout": vout, "sats": sats, "height": H4T + 7, "spent_in_mempool": true, "spent_by": by.to_string().repeat(64)})
    }

    #[test]
    fn two_rebuilds_of_one_payment_can_never_both_confirm() {
        let (w, address) = funded("lineage");
        let (a, b) = (format!("{}:0", "d".repeat(64)), format!("{}:2", "e".repeat(64)));
        // T spent {A, B} through ML-DSA-44 and was refused; ML-DSA-44 checks are off now.
        let t = ml_record(&w, &address, &"71".repeat(32), "rejected", &[a.clone(), b.clone()]);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        // B is held by another transaction in the mempool: the first rebuild R1 can only conflict through A.
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('d', 0, 150_000, H4T + 7), held_by('e', 2, 60_000, 'f')]);
        let r1 = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        let r1_coins: Vec<String> = guard(&w.state.pending).as_ref().unwrap().plan.coins.iter().map(Coin::outpoint).collect();
        assert_eq!(r1_coins, vec![a.clone()]);
        let sent = block(send_plan(&w.state, &r1.id, Some("en"), |_| std::future::ready(true))).unwrap();
        let r1_txid = sent.txid.clone();
        // The lineage of T is in the book: T, then R1.
        let lineage = w.state.book().unwrap().lineage_of(&t.txid).unwrap().clone();
        assert_eq!(lineage.versions.iter().map(|v| v.txid.as_str()).collect::<Vec<_>>(), vec![t.txid.as_str(), r1_txid.as_str()]);
        // R1 waits in the mempool, holding A; B is free again. A second rebuild of T would spend only B.
        guard(&w.net.txs).insert(r1_txid.clone(), json!({"status": "mempool"}));
        guard(&w.net.utxos).insert(address.clone(), vec![held_by('d', 0, 150_000, '9'), utxo('e', 2, 60_000, H4T + 7)]);
        assert_eq!(block(rebuild_plan(&w.state, &t.txid)).unwrap_err().code, "rebuild_original_went_out");
        // R1 leaves the mempool and both coins are free: a new version must conflict with T and R1, so it
        // spends A, the one input they share.
        guard(&w.net.txs).insert(r1_txid.clone(), json!({"status": "unknown"}));
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('d', 0, 150_000, H4T + 7), utxo('e', 2, 60_000, H4T + 7)]);
        let r2 = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        assert!(guard(&w.state.pending).as_ref().unwrap().plan.coins.iter().any(|c| c.outpoint() == a));
        // R1 reappears in the mempool before R2 is sent: nothing goes out.
        let net = w.net.clone();
        let r1_again = r1_txid.clone();
        let err = block(send_plan(&w.state, &r2.id, Some("en"), move |_| {
            guard(&net.txs).insert(r1_again, json!({"status": "mempool"}));
            std::future::ready(true)
        })).unwrap_err();
        assert_eq!(err.code, "rebuild_original_went_out");
        assert_eq!(guard(&w.net.broadcasts).len(), 2, "only R1, sent to both APIs");
        // Once a version is confirmed, no more rebuilds of T.
        guard(&w.net.txs).insert(r1_txid, json!({"status": "confirmed", "confirmations": 1}));
        assert_eq!(block(rebuild_plan(&w.state, &t.txid)).unwrap_err().code, "rebuild_original_went_out");
    }

    /// The inputs of every transaction broadcast so far.
    fn broadcast_inputs(w: &Wallet) -> Vec<Vec<String>> {
        guard(&w.net.broadcasts).iter().map(|hex| {
            decode(&hex::decode(hex).unwrap()).inputs.iter().map(|i| format!("{}:{}", crate::tx::display_hex(&i.prevout.txid), i.prevout.vout)).collect()
        }).collect()
    }

    #[test]
    fn a_rebuild_is_planned_only_while_its_anchor_is_free() {
        let (w, address) = funded("anchor-held");
        let (a, b) = (format!("{}:0", "d".repeat(64)), format!("{}:2", "e".repeat(64)));
        // T spent {A, B}: A, its first input, is the anchor.
        let t = ml_record(&w, &address, &"74".repeat(32), "rejected", &[a.clone(), b.clone()]);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        // A held by a transaction in the mempool, B free: no rebuild from B alone.
        guard(&w.net.utxos).insert(address.clone(), vec![held_by('d', 0, 150_000, 'f'), utxo('e', 2, 60_000, H4T + 7)]);
        assert_eq!(block(rebuild_plan(&w.state, &t.txid)).unwrap_err().code, "rebuild_anchor_unavailable");
        // A spent for good (gone from the address): no rebuild either.
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('e', 2, 60_000, H4T + 7)]);
        assert_eq!(block(rebuild_plan(&w.state, &t.txid)).unwrap_err().code, "rebuild_anchor_unavailable");
        // A free again: the rebuild spends it, whatever else it takes.
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('d', 0, 150_000, H4T + 7), utxo('e', 2, 60_000, H4T + 7)]);
        block(rebuild_plan(&w.state, &t.txid)).unwrap();
        assert!(guard(&w.state.pending).as_ref().unwrap().plan.coins.iter().any(|c| c.outpoint() == a));
    }

    #[test]
    fn two_rebuilds_of_one_payment_never_both_go_out_without_the_anchor() {
        // Two interleavings: a second rebuild planned while the first waits in its dialog, then
        // committed after the first went out and came back unclear, with coins moving in between.
        for case in 0..2 {
            let w = wallet(&format!("anchor-pair-{case}"), words(0x70 + case), true, m4_state(H4T + 10, false));
            let address = block(new_pq2_address(&w.state)).unwrap().address;
            let (a, b) = (format!("{}:0", "d".repeat(64)), format!("{}:2", "e".repeat(64)));
            let mut all = vec![ml_record(&w, &address, &"77".repeat(32), "rejected", &[a.clone(), b.clone()])];
            all[0].send = 100_000;
            store::save(&w.state.sent_path(), &all).unwrap();
            let t = all[0].clone();
            *guard(&w.net.state) = m4_state(H4T + 12, true);
            guard(&w.net.utxos).insert(address.clone(), vec![utxo('d', 0, 98_000, H4T + 7), utxo('e', 2, 104_176, H4T + 7), utxo('c', 0, 10_400, H4T + 11)]);
            let r2 = block(rebuild_plan(&w.state, &t.txid)).unwrap();
            let net = w.net.clone();
            let (address_in, t_txid) = (address.clone(), t.txid.clone());
            let state = &w.state;
            let result = block(send_plan(state, &r2.id, Some("en"), move |_| {
                let sent = std::thread::scope(|scope| {
                    scope.spawn(|| {
                        let r1 = block(rebuild_plan(state, &t_txid)).unwrap();
                        block(send_plan(state, &r1.id, Some("en"), |_| std::future::ready(true)))
                    }).join().unwrap()
                }).unwrap();
                if case == 1 {
                    // R1 comes back unclear and leaves the mempool; its coins are free again.
                    edit_sent(state, |all| {
                        if let Some(s) = all.iter_mut().find(|s| s.txid == sent.txid) {
                            s.status = "unknown".into();
                        }
                    }).unwrap();
                } else {
                    guard(&net.utxos).insert(address_in.clone(), vec![held_by('d', 0, 98_000, '6'), utxo('e', 2, 104_176, H4T + 7), utxo('c', 0, 10_400, H4T + 11)]);
                }
                std::future::ready(true)
            }));
            // Whatever happened to R2, everything broadcast spends the anchor A: at most one confirms.
            let inputs = broadcast_inputs(&w);
            assert!(!inputs.is_empty());
            assert!(inputs.iter().all(|i| i.contains(&a)), "case {case}: {inputs:?} ({result:?})");
        }
    }

    #[test]
    fn a_lineage_with_a_version_that_does_not_spend_the_anchor_is_not_rebuilt() {
        // An earlier build left T = {A, B} and an SLH-DSA rebuild R1 spending B alone, sent and unclear.
        let (w, address) = funded("unanchored");
        let (a, b) = (format!("{}:0", "a".repeat(64)), format!("{}:1", "b".repeat(64)));
        let t = ml_record(&w, &address, &"7b".repeat(32), "rejected", &[a.clone(), b.clone()]);
        let r1 = Sent { txid: "7c".repeat(32), signature: "slhdsa128s".into(), status: "unknown".into(), outpoints: vec![b.clone()], inputs: 1, ..t.clone() };
        let mut all: Vec<Sent> = store::load(&w.state.sent_path());
        all.push(r1.clone());
        store::save(&w.state.sent_path(), &all).unwrap();
        let root = Version { txid: t.txid.clone(), inputs: t.outpoints.clone() };
        w.state.edit_book(|bk| bk.add_version(&root, Version { txid: r1.txid.clone(), inputs: r1.outpoints.clone() })).unwrap();
        // A is free, B is held by another transaction Q in the mempool: a version from A would share no
        // input with R1 once Q leaves.
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        guard(&w.net.utxos).insert(address.clone(), vec![utxo('a', 0, 104_176, H4T + 7), held_by('b', 1, 104_176, 'f')]);
        assert_eq!(block(rebuild_plan(&w.state, &t.txid)).unwrap_err().code, "rebuild_not_possible");
        assert!(guard(&w.state.pending).is_none());
        // The commit checks it too: such a version recorded after planning stops the payment.
        let (w, address) = funded("unanchored-commit");
        let t = ml_record(&w, &address, &"7d".repeat(32), "rejected", &[format!("{}:0", "d".repeat(64)), format!("{}:2", "e".repeat(64))]);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        let r = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        let root = Version { txid: t.txid.clone(), inputs: t.outpoints.clone() };
        *guard(&w.state.before_commit) = Some(Box::new(move |state: &AppState| {
            let other = Version { txid: "7e".repeat(32), inputs: vec![format!("{}:2", "e".repeat(64))] };
            state.edit_book(|bk| bk.add_version(&root, other)).unwrap();
        }));
        assert_eq!(block(send_plan(&w.state, &r.id, Some("en"), |_| std::future::ready(true))).err().map(|f| f.code), Some("rebuild_not_possible".to_string()));
        assert!(guard(&w.net.broadcasts).is_empty());
        assert_eq!(store::load::<Vec<Sent>>(&w.state.sent_path()).len(), 1, "no record");
    }

    #[test]
    fn the_other_payments_are_covered_starting_from_the_anchor() {
        // T's anchor A (100,000) and a rebuild of 50,000; twelve other unclear payments of the address, each
        // {A, Yi}, Yi = 200,000 + i, all free: A alone covers every one of them.
        let w = wallet("cover-anchor", words(0x6a), true, m4_state(H4T + 10, false));
        let address = block(new_pq2_address(&w.state)).unwrap().address;
        let a = format!("{}:0", "9".repeat(64));
        let mut utxos = vec![utxo('9', 0, 100_000, H4T + 7)];
        utxos.extend((1..=12u32).map(|i| utxo('8', i, 200_000 + u64::from(i), H4T + 7)));
        guard(&w.net.utxos).insert(address.clone(), utxos);
        let t = ml_record(&w, &address, &"7f".repeat(32), "rejected", std::slice::from_ref(&a));
        let mut all: Vec<Sent> = store::load(&w.state.sent_path());
        all[0].send = 50_000;
        for i in 1..=12u32 {
            let y = format!("{}:{i}", "8".repeat(64));
            all.push(Sent { txid: format!("{:064x}", 0x7000 + i), signature: "slhdsa128s".into(), status: "unknown".into(), outpoints: vec![a.clone(), y], ..all[0].clone() });
        }
        store::save(&w.state.sent_path(), &all).unwrap();
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        let view = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        let coins: Vec<String> = guard(&w.state.pending).as_ref().unwrap().plan.coins.iter().map(Coin::outpoint).collect();
        assert_eq!(coins, vec![a]);
        assert!(view.inputs == 1 && view.change > 0);
    }

    #[test]
    fn a_cover_takes_the_coin_shared_by_the_most_payments_then_the_largest() {
        let coin = |c: char, sats: u64| Coin { txid: c.to_string().repeat(64), vout: 0, sats, height: 1 };
        let e = Earlier {
            usable: Vec::new(), required: Vec::new(), replaces: Vec::new(), spent: false, elsewhere: false, unrecorded: false,
            covers: vec![
                vec![coin('a', 10), coin('b', 50)],
                vec![coin('b', 50), coin('c', 90)],
                vec![coin('b', 50), coin('d', 5)],
                vec![coin('e', 70), coin('f', 80)],
            ],
        };
        // b covers three, then f, the larger of the last one's.
        assert_eq!(e.cover(&[]), vec![coin('b', 50), coin('f', 80)]);
        // Forced inputs cover what they share first.
        assert_eq!(e.cover(&[coin('e', 70)]), vec![coin('b', 50)]);
        assert_eq!(e.cover(&[coin('a', 10), coin('c', 90), coin('d', 5), coin('e', 70)]), Vec::<Coin>::new());
    }

    #[test]
    fn a_commit_writes_in_order_and_a_failed_record_leaves_no_version() {
        // The record cannot be saved: the change index handed out first stays handed out, unused (a gap);
        // nothing is recorded or broadcast.
        let (w, address) = funded("commit-io");
        let view = block(plan_pq2_payment(&w.state, address.clone(), elsewhere(), "0.001".into(), None, None)).unwrap();
        assert!(view.change > 0);
        w.state.fail_sent_writes.store(1, Ordering::SeqCst);
        assert_eq!(block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true))).err().map(|f| f.code), Some("io".to_string()));
        assert_eq!(w.state.book().unwrap().chains[1].handed_out.iter().copied().collect::<Vec<_>>(), vec![0]);
        assert!(guard(&w.net.broadcasts).is_empty() && store::load::<Vec<Sent>>(&w.state.sent_path()).is_empty());
        // A rebuild whose record fails does not join the lineage, and an earlier version with the same txid
        // (the same plan signed before) stays where it was.
        let (w, address) = funded("commit-rebuild-io");
        let t = ml_record(&w, &address, &"78".repeat(32), "rejected", &[format!("{}:0", "d".repeat(64))]);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        let r = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        let plan = guard(&w.state.pending).as_ref().unwrap().plan.clone();
        let txid = crate::tx::display_hex(&wallet::unsigned_transaction(&plan.coins, &plan.outputs, plan.lock_time).txid());
        let root = Version { txid: t.txid.clone(), inputs: t.outpoints.clone() };
        let earlier = Version { txid: txid.clone(), inputs: plan.coins.iter().map(Coin::outpoint).collect() };
        w.state.edit_book(|b| b.add_version(&root, earlier.clone())).unwrap();
        // The next save of the record fails: armed right before the commit (the lookups save it before).
        *guard(&w.state.before_commit) = Some(Box::new(|state: &AppState| state.fail_sent_writes.store(1, Ordering::SeqCst)));
        assert_eq!(block(send_plan(&w.state, &r.id, Some("en"), |_| std::future::ready(true))).err().map(|f| f.code), Some("io".to_string()));
        let lineage = w.state.book().unwrap().lineage_of(&t.txid).unwrap().clone();
        assert_eq!(lineage.versions, vec![root, earlier], "the earlier version with the same txid is still there");
        // A change index another payment took meanwhile stops the commit before anything is written.
        let (w, address) = funded("commit-index");
        let t = ml_record(&w, &address, &"79".repeat(32), "rejected", &[format!("{}:0", "d".repeat(64))]);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        let r = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        assert!(r.change > 0);
        *guard(&w.state.before_commit) = Some(Box::new(|state: &AppState| {
            let address = state.pq2_template(1, 0).unwrap().address;
            assert!(state.edit_book(|b| b.chains[1].issue(0, &address)).unwrap());
        }));
        assert_eq!(block(send_plan(&w.state, &r.id, Some("en"), |_| std::future::ready(true))).err().map(|f| f.code), Some("coins_changed".to_string()));
        assert!(w.state.book().unwrap().lineage_of(&t.txid).is_none());
        assert_eq!(store::load::<Vec<Sent>>(&w.state.sent_path()).len(), 1, "no record");
        // The wallet is replaced while the versions are looked up: the commit writes nothing anywhere.
        let (w, address) = funded("commit-session");
        let t = ml_record(&w, &address, &"7a".repeat(32), "rejected", &[format!("{}:0", "d".repeat(64))]);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        let r = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        *guard(&w.state.before_commit) = Some(Box::new(|state: &AppState| {
            state.lock();
            state.open_session(&words(0x6d), state.generation(), true).unwrap();
        }));
        assert_eq!(block(send_plan(&w.state, &r.id, Some("en"), |_| std::future::ready(true))).err().map(|f| f.code), Some("locked".to_string()));
        let book = w.state.book().unwrap();
        assert!(book.lineages.is_empty() && book.chains[1].handed_out.is_empty());
    }

    #[test]
    fn the_anchor_is_spent_with_whatever_other_payments_force() {
        // T spent {X, C1} with X (3,000,000) first: X is the anchor. Twelve other unclear payments each
        // force their Ci. The rebuild must spend X and all twelve: 13 inputs through SLH-DSA do not fit,
        // and the rebuild is refused rather than made without its anchor.
        let w = wallet("anchor-forced", words(0x69), true, m4_state(H4T + 10, false));
        let address = block(new_pq2_address(&w.state)).unwrap().address;
        let x = format!("{}:0", "9".repeat(64));
        let cs: Vec<String> = (1..=12).map(|i| format!("{}:{i}", "8".repeat(64))).collect();
        let mut utxos = vec![utxo('9', 0, 3_000_000, H4T + 7)];
        utxos.extend((1..=12u32).map(|i| utxo('8', i, 200_000 + u64::from(i), H4T + 7)));
        guard(&w.net.utxos).insert(address.clone(), utxos);
        let t = ml_record(&w, &address, &"75".repeat(32), "rejected", &[x.clone(), cs[0].clone()]);
        let mut all: Vec<Sent> = store::load(&w.state.sent_path());
        all[0].send = 250_000;
        for (i, c) in cs.iter().enumerate() {
            all.push(Sent { txid: format!("{:064x}", 0x6000 + i), signature: "slhdsa128s".into(), status: "unknown".into(), outpoints: vec![c.clone()], ..all[0].clone() });
        }
        store::save(&w.state.sent_path(), &all).unwrap();
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        assert_eq!(block(rebuild_plan(&w.state, &t.txid)).unwrap_err().code, "too_large");
        // With fewer payments waiting, the anchor and their coins pay.
        all.truncate(6);
        store::save(&w.state.sent_path(), &all).unwrap();
        let view = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        let coins: Vec<String> = guard(&w.state.pending).as_ref().unwrap().plan.coins.iter().map(Coin::outpoint).collect();
        assert!(coins.contains(&x) && cs[..5].iter().all(|c| coins.contains(c)) && view.inputs == 6);
    }

    #[test]
    fn a_large_ml_dsa_payment_falls_back_to_a_partial_slh_spend() {
        let (w, address) = dusted("large-rebuild", 12);
        // T spent all 13 coins through ML-DSA-44 (they fit there) and was refused. Through SLH-DSA all 13
        // would be about 104 KB; the large coin alone pays.
        let mut inputs = vec![format!("{}:0", "9".repeat(64))];
        inputs.extend((1..=12).map(|i| format!("{}:{i}", "8".repeat(64))));
        let t = ml_record(&w, &address, &"72".repeat(32), "rejected", &inputs);
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        let view = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        assert_eq!((view.signature, view.inputs), (Path::Slhdsa128s, 1));
        assert!(view.size <= wallet::MAX_TX_BYTES);
        let p = view.pq2.unwrap();
        assert_eq!(p.staying_coins, 12);
    }

    #[test]
    fn a_rebuild_forces_one_small_conflict_set_not_a_coin_per_version() {
        let w = wallet("cover", words(0x65), true, m4_state(H4T + 10, false));
        let address = block(new_pq2_address(&w.state)).unwrap().address;
        // X of 100,000 and Y1..Y13 of 200,000 + i, all usable.
        let x = format!("{}:0", "9".repeat(64));
        let ys: Vec<String> = (1..=13).map(|i| format!("{}:{i}", "8".repeat(64))).collect();
        let mut utxos = vec![utxo('9', 0, 100_000, H4T + 7)];
        utxos.extend((1..=13u32).map(|i| utxo('8', i, 200_000 + u64::from(i), H4T + 7)));
        guard(&w.net.utxos).insert(address.clone(), utxos);
        // T spent X and every Yi through ML-DSA-44 and was refused; 13 versions {X, Yi} are unclear.
        let mut inputs = vec![x.clone()];
        inputs.extend(ys.iter().cloned());
        let mut t = ml_record(&w, &address, &"73".repeat(32), "rejected", &inputs);
        t.send = 250_000;
        let mut all: Vec<Sent> = store::load(&w.state.sent_path());
        all[0].send = 250_000;
        let root = Version { txid: t.txid.clone(), inputs: t.outpoints.clone() };
        for (i, y) in ys.iter().enumerate() {
            let txid = format!("{:064x}", 0x5000 + i);
            all.push(Sent { txid: txid.clone(), signature: "slhdsa128s".into(), status: "unknown".into(), outpoints: vec![x.clone(), y.clone()], ..all[0].clone() });
            w.state.edit_book(|b| b.add_version(&root, Version { txid, inputs: vec![x.clone(), y.clone()] })).unwrap();
        }
        store::save(&w.state.sent_path(), &all).unwrap();
        *guard(&w.net.state) = m4_state(H4T + 12, true);
        // {X, Y13} conflicts with every version and pays 250,000 with change.
        let view = block(rebuild_plan(&w.state, &t.txid)).unwrap();
        assert_eq!((view.signature, view.inputs, view.size), (Path::Slhdsa128s, 2, 16_124));
        assert!(view.change > 0);
        let coins: Vec<String> = guard(&w.state.pending).as_ref().unwrap().plan.coins.iter().map(Coin::outpoint).collect();
        assert!(coins.contains(&x) && coins.contains(&ys[12]), "{coins:?}");
        // It passes the record's retry rules (it shares an input with every one of them) and goes out.
        let sent = block(send_plan(&w.state, &view.id, Some("en"), |_| std::future::ready(true))).unwrap();
        assert!(matches!(sent.result, BroadcastResult::Sent { .. }), "{sent:?}");
    }

    #[test]
    fn the_book_goes_with_the_wallet() {
        let (w, _) = funded("removal");
        assert!(w.state.pq2_path().exists());
        let state = &w.state;
        state.lock();
        // A vault that is gone leaves an orphaned record and book behind; creating removes both.
        remove_orphaned_record(state).unwrap();
        assert!(!state.pq2_path().exists());
    }
}
