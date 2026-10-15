//! The commands the interface calls, and the state behind them.
//!
//! The interface never holds a key, a seed or a signature message. It asks for a send by address and
//! amount; the core plans it from coins it fetched itself, shows the plan, and signs exactly that plan
//! when the user confirms it in a dialog of the system (confirm.rs), after checking the coins are still
//! there. Secrets live in `Session` while the wallet is unlocked and are wiped when it locks (by hand, or
//! after the idle time).
use crate::api::{ApiError, BroadcastResult, CheckResult, Coin, Coins, TxStatus};
use crate::chain::{Chain, ChainProblem};
use crate::keys::{looks_like_backup_code, word_list, KeyError, Keys, Secret};
use crate::p2mr::{parse_destination, Destination, DestinationError, Kind, Path, Template, MLDSA44_SIGNATURE_CHUNKS};
use crate::proof::REQUIRED_BLOCKS;
use crate::sources::{Flags, Sources, StateError};
use crate::store::{self, Sent, Settings};
use crate::vault::{self, VaultError};
use crate::wallet::{self, Account, Amount, Plan, PlanError, SignError, FEE_RATE};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::future::{poll_fn, Future};
use std::path::PathBuf;
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

/// The unlocked wallet.
struct Session {
    legacy: bool,
    keys: Keys,
    schnorr: Template,
    mldsa44: Template,
    mixed: Template,
}

impl Session {
    fn new(secret: &Secret) -> Result<Session, KeyError> {
        let keys = Keys::from_secret(secret)?;
        Ok(Session {
            legacy: secret.is_legacy(),
            schnorr: keys.template(Kind::Schnorr),
            mldsa44: keys.template(Kind::Mldsa44),
            mixed: keys.template(Kind::Mixed),
            keys,
        })
    }

    fn template(&self, kind: Kind) -> &Template {
        match kind {
            Kind::Schnorr => &self.schnorr,
            Kind::Mldsa44 => &self.mldsa44,
            Kind::Mixed => &self.mixed,
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
    /// Where the next batch of due payment lookups starts.
    sent_lookup_offset: AtomicU64,
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
        let settings: Settings = store::load(&dir.join("settings.json"));
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
            sent_lookup_offset: AtomicU64::new(0),
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

    fn touch(&self) {
        *guard(&self.last_use) = (Instant::now(), SystemTime::now());
    }

    /// Time since the last use, by whichever clock has gone further.
    fn idle(&self) -> Duration {
        let (at, wall) = *guard(&self.last_use);
        at.elapsed().max(wall.elapsed().unwrap_or_default())
    }

    fn lock(&self) {
        // Serialize locking with the final session check and mutation of a confirmed wallet change.
        self.lock_session(guard(&self.session));
    }

    fn lock_session(&self, mut session: MutexGuard<'_, Option<Session>>) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.locked.send_replace(());
        *session = None;
        drop(session);
        *guard(&self.pending) = None;
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

    /// Opens the wallet, unless it was locked since `generation` was read.
    fn open_session(&self, secret: &Secret, generation: u64) -> Res<()> {
        let session = Session::new(secret)?;
        let mut current = guard(&self.session);
        if self.generation() != generation {
            return Err(Failure::new("locked"));
        }
        *current = Some(session);
        drop(current);
        self.touch();
        Ok(())
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
    let new = {
        let _one_at_a_time = guard(&state.vault_ops);
        let mut pending = guard(&state.new_wallet);
        let new = pending.as_ref().ok_or_else(|| Failure::new("no_phrase"))?;
        if !new.confirmed {
            return Err(Failure::new("phrase_not_confirmed"));
        }
        // Keep the words for another try on failure, under the same lock as cancellation and locking.
        remove_orphaned_record(state)?;
        vault::create(&state.vault_path(), &password, &new.secret)?;
        pending.take().expect("the pending wallet was checked above")
    };
    state.open_session(&new.secret, generation)
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
    {
        let _one_at_a_time = guard(&state.vault_ops);
        remove_orphaned_record(state)?;
        vault::create(&state.vault_path(), &password, &secret)?;
    }
    state.open_session(&secret, generation)
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
    state.open_session(&secret, generation)
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
    if let Err(error) = std::fs::remove_file(state.sent_path()) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(Failure::new("io"));
        }
    }
    Ok(())
}

/// Called under vault_ops after locking; a vault that cannot be removed must leave the record intact.
fn remove_wallet_files(state: &AppState) -> Res<()> {
    let _sent = guard(&state.sent_ops);
    for path in [state.vault_path(), state.sent_path()] {
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

#[derive(Serialize)]
pub struct Overview {
    chain: Option<Chain>,
    problem: Option<String>,
    accounts: Vec<AccountView>,
    fetched: u64,
}

fn path_now(kind: Kind, chain: &Chain) -> Option<Path> {
    match kind {
        Kind::Schnorr => Some(Path::Schnorr),
        Kind::Mldsa44 => Some(Path::Mldsa44),
        Kind::Mixed => chain.mixed_path(),
    }
}

fn shown(kind: Kind, chain: &Chain) -> bool {
    match kind {
        Kind::Schnorr => true,
        Kind::Mldsa44 => chain.mldsa44_allowed,
        Kind::Mixed => chain.mixed_allowed && chain.mixed_path().is_some(),
    }
}

async fn current_chain(sources: &Sources, flags: &mut Flags) -> Res<Chain> {
    Ok(flags.take(sources.state().await)?)
}

#[tauri::command]
pub async fn overview(state: State<'_, AppState>) -> Res<Overview> {
    let (schnorr, mldsa44, mixed) = state.templates()?;
    let sources = state.sources.clone();
    let mut flags = Flags::default();
    let chain = match current_chain(&sources, &mut flags).await {
        Ok(c) => c,
        Err(f) => return Ok(Overview { chain: None, problem: Some(f.code), accounts: vec![], fetched: now() }),
    };
    let mut accounts = Vec::new();
    for t in [schnorr, mldsa44, mixed] {
        // Coins are looked up for every address, shown or not: the seed alone makes it, and coins may be there.
        let found = flags.take(sources.coins(&t.address).await);
        let sum = |c: &[Coin]| c.iter().map(|c| c.sats).sum::<u64>();
        let (spendable, pending, incoming, n, complete) = match &found {
            Ok(c) => (sum(&c.spendable), sum(&c.pending), c.incoming.iter().map(|i| i.sats).sum(), c.spendable.len(), c.incoming_complete && !c.truncated),
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
    Ok(Overview { chain: Some(chain), problem: None, accounts, fetched: now() })
}

#[derive(Serialize)]
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
}

fn account_for(template: Template, chain: &Chain, path: Option<Path>) -> Res<Account> {
    if !shown(template.kind, chain) {
        return Err(Failure::new("address_not_ready"));
    }
    let path = path.or_else(|| path_now(template.kind, chain)).ok_or_else(|| Failure::new("address_not_ready"))?;
    Account::new(template, path).ok_or_else(|| Failure::new("address_not_ready"))
}

/// Plans a send; nothing is signed until `confirm_send` with the plan's id.
#[tauri::command]
pub async fn plan_send(state: State<'_, AppState>, from: Kind, to: String, amount: String) -> Res<SendPlan> {
    plan_payment(&state, from, to, amount).await
}

async fn plan_payment(state: &AppState, from: Kind, to: String, amount: String) -> Res<SendPlan> {
    state.touch();
    let template = guard(&state.session).as_ref().ok_or_else(|| Failure::new("locked"))?.template(from).clone();
    let own: Vec<Template> = { let (a, b, c) = state.templates()?; vec![a, b, c] };
    let destination = parse_destination(&to)?;
    let amount = if amount.trim() == "all" { Amount::All } else { Amount::Sats(parse_coins(&amount).ok_or_else(|| Failure::new("invalid_amount"))?) };
    let sources = state.sources.clone();
    let mut flags = Flags::default();
    let chain = current_chain(&sources, &mut flags).await?;
    // The wallet does not pay its own address before it hands that out either.
    if own.iter().any(|t| t.address == destination.address && !shown(t.kind, &chain)) {
        return Err(Failure::new("destination_not_ready"));
    }
    let account = account_for(template, &chain, None)?;
    let coins = flags.take(sources.coins(&account.template.address).await)?;
    // The wallet's own payments that are, or may be, on their way, looked up again first.
    let at = now();
    let sent = refresh_sent(state, |s| {
        matches!(s.status.as_str(), "mempool" | "unknown") || (s.status == "confirmed" && !s.proven()) || (refused(s) && recent(s, at))
    }, &mut flags).await;
    // One payment at a time: while one is being handed to the API, its outcome is not known yet.
    if sent.iter().any(|s| s.status == "submitting") {
        return Err(Failure::new("sending"));
    }
    let pending = pending_everywhere(&sources, &coins, &own, &account.template.address, &mut flags).await?;
    let earlier = earlier_payments(&sent, &kind_name(from), &coins.spendable, &pending);
    let went_out = earlier.spent || surfaced(&sent);
    let plan = wallet::plan_spend(&account, &earlier.usable, &earlier.required, &destination, amount, chain.lock_time())?;
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
    };
    let caution = went_out || earlier.elsewhere || earlier.unrecorded;
    *guard(&state.pending) =
        Some(PendingSend { id: view.id.clone(), created: Instant::now(), kind: from, path: account.path, destination, plan, caution, sources: flags });
    Ok(view)
}

#[derive(Serialize)]
pub struct SendResult {
    result: BroadcastResult,
    txid: String,
    sign_ms: f64,
}

/// Signs and broadcasts the plan the interface showed, if its coins are still unspent, the chain's rules
/// for it have not changed since, and the user confirms its figures in a system dialog. The transaction is
/// recorded before the API sees it, so that no answer of the API can make the wallet forget it.
#[tauri::command]
pub async fn confirm_send(app: AppHandle, state: State<'_, AppState>, id: String, locale: Option<String>) -> Res<SendResult> {
    state.touch();
    let generation = state.generation();
    let mut pending = guard(&state.pending).take().ok_or_else(|| Failure::new("no_plan"))?;
    if pending.id != id || pending.created.elapsed() > PLAN_LIFETIME {
        return Err(Failure::new("no_plan"));
    }
    let (account, coins, spending) = recheck_payment(&state, &mut pending).await?;
    let dialog = crate::confirm::payment(
        state.dialog_locale(locale.as_deref()),
        pending.plan.send,
        &pending.destination.address,
        pending.plan.fee,
        pending.plan.change,
        pending.caution,
        pending.sources,
    );
    if !crate::confirm::ask(&app, dialog).await {
        return Err(Failure::new("cancelled"));
    }
    if state.generation() != generation {
        return Err(Failure::new("locked"));
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
    let record = signed_record(&pending, &signed, sign_ms);
    // Recorded before the API sees it. Not sent at all when that fails, when the wallet was locked or
    // removed meanwhile, or when another of its payments on the way spends one of the same coins.
    record_payment(&state, &pending, &coins, &spending, generation, record)?;
    let result = state.sources.broadcast(&signed.hex, &signed.txid).await.value;
    // What the API answered; a refusal is kept too, and looked up again later (activity), because only
    // the network can say whether the transaction went out.
    let (status, reason) = match &result {
        BroadcastResult::Sent { .. } => ("mempool", String::new()),
        BroadcastResult::Unknown => ("unknown", String::new()),
        BroadcastResult::Rejected { reason } => ("rejected", reason.clone()),
        BroadcastResult::Failed { error } => ("failed", error.clone()),
    };
    let _ = edit_sent(&state, |sent| {
        if let Some(s) = sent.iter_mut().find(|s| s.txid == signed.txid) {
            s.status = status.into();
            s.reason = reason;
            s.doubted |= status != "mempool";
        }
        mark_replaced(sent);
    });
    Ok(SendResult { result, txid: signed.txid, sign_ms })
}

fn signed_record(pending: &PendingSend, signed: &wallet::Signed, sign_ms: f64) -> Sent {
    Sent {
        txid: signed.txid.clone(),
        created: now(),
        from: kind_name(pending.kind),
        to: pending.destination.address.clone(),
        send: pending.plan.send,
        fee: pending.plan.fee,
        change: pending.plan.change,
        vsize: signed.sizes.vsize,
        size: signed.sizes.size,
        signature: if pending.path == Path::Schnorr { "schnorr".into() } else { "mldsa44".into() },
        inputs: pending.plan.coins.len(),
        sign_ms,
        status: "submitting".into(),
        confirmations: 0,
        proof_verified: false,
        reason: String::new(),
        outpoints: pending.plan.coins.iter().map(Coin::outpoint).collect(),
        doubted: false,
    }
}

async fn recheck_payment(state: &AppState, pending: &mut PendingSend) -> Res<(Account, Coins, PendingCoins)> {
    let mut flags = pending.sources;
    let chain = current_chain(&state.sources, &mut flags).await?;
    let template = guard(&state.session).as_ref().ok_or_else(|| Failure::new("locked"))?.template(pending.kind).clone();
    let account = account_for(template, &chain, None)?;
    if account.path != pending.path || chain.lock_time() != pending.plan.lock_time {
        return Err(Failure::new("chain_changed"));
    }
    let coins = flags.take(state.sources.coins(&account.template.address).await)?;
    let unspent: HashMap<String, u64> = coins.spendable.iter().map(|c| (c.outpoint(), c.sats)).collect();
    if !pending.plan.coins.iter().all(|c| unspent.get(&c.outpoint()) == Some(&c.sats)) {
        return Err(Failure::new("coins_changed"));
    }
    let at = now();
    let sent = refresh_sent(state, |s| {
        matches!(s.status.as_str(), "mempool" | "unknown") || (s.status == "confirmed" && !s.proven()) || (refused(s) && recent(s, at))
    }, &mut flags).await;
    let own: Vec<Template> = { let (a, b, c) = state.templates()?; vec![a, b, c] };
    let spending = pending_everywhere(&state.sources, &coins, &own, &account.template.address, &mut flags).await?;
    let earlier = earlier_payments(&sent, &kind_name(pending.kind), &coins.spendable, &spending);
    pending.sources = flags;
    pending.caution = earlier.spent || earlier.elsewhere || earlier.unrecorded || surfaced(&sent);
    Ok((account, coins, spending))
}

fn record_payment(state: &AppState, pending: &PendingSend, coins: &Coins, spending: &PendingCoins, generation: u64, record: Sent) -> Res<()> {
    let account_name = kind_name(pending.kind);
    edit_sent(state, |sent| {
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
        let earlier = earlier_payments(sent, &account_name, &coins.spendable, spending);
        let covered = earlier.replaces.iter().all(|txid| sent.iter().any(|s| &s.txid == txid && shared(s)));
        if !covered || (!pending.caution && (earlier.spent || earlier.elsewhere || earlier.unrecorded || surfaced(sent))) {
            return Err(Failure::new("coins_changed"));
        }
        // The same transaction again (an identical retry): it stays doubted if it was.
        let doubted = record.doubted || sent.iter().any(|s| same(s) && s.doubted);
        sent.retain(|s| !same(s));
        sent.insert(0, Sent { doubted, ..record });
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
        // Never a file the wallet could not read back: the change is refused instead.
        if bytes.len() as u64 > store::MAX_FILE_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "the record of payments is full"));
        }
        store::write_atomic(&state.sent_path(), &bytes)?;
    }
    Ok(result)
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
async fn pending_everywhere(sources: &Sources, coins: &Coins, own: &[Template], paying: &str, flags: &mut Flags) -> Res<PendingCoins> {
    let mut pending = PendingCoins {
        coins: coins.pending.clone(), spent_by: coins.spent_by.clone(), unnamed_spenders: coins.unnamed_spenders.clone(),
    };
    for t in own.iter().filter(|t| t.address != paying) {
        let coins = flags.take(sources.coins(&t.address).await)?;
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
    let mut e = Earlier { usable: Vec::new(), required: Vec::new(), replaces: Vec::new(), spent: false, elsewhere: false, unrecorded };
    for s in sent.iter().filter(|s| unclear(s) || refused(s)) {
        if s.outpoints.iter().any(|o| taken.contains(o)) {
            // A proven payment spends one of its coins: it cannot go through.
            continue;
        }
        if s.from != account || s.outpoints.is_empty() {
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
            }
            None => e.spent = true,
        }
    }
    e.usable = usable;
    e
}

/// Looks up again the recorded transactions `due` picks, and uncovered refusals, in rotating batches
/// of at most 20. Applies what changed to the record as it is by then, by txid: the lookups take a while,
/// and a payment may be recorded meanwhile. One being handed to the API is left to the command doing that.
async fn refresh_sent(state: &AppState, due: impl Fn(&Sent) -> bool, flags: &mut Flags) -> Vec<Sent> {
    refresh_sent_with_clock(state, due, flags, Instant::now).await
}

async fn refresh_sent_with_clock(state: &AppState, due: impl Fn(&Sent) -> bool, flags: &mut Flags, mut clock: impl FnMut() -> Instant) -> Vec<Sent> {
    let picked = edit_sent(state, |sent| {
        // Still being handed to the API long after any answer would have come: the send was cut short.
        let at = now();
        for s in sent.iter_mut().filter(|s| s.status == "submitting" && at.saturating_sub(s.created) > SUBMIT_TIMEOUT_SECS) {
            s.status = "unknown".into();
            s.doubted = true;
        }
        mark_replaced(sent);
        let taken: HashSet<&str> = sent.iter().filter(|s| s.proven()).flat_map(|s| s.outpoints.iter().map(String::as_str)).collect();
        let mut picked: Vec<_> = sent.iter().filter(|s| {
            s.status != "submitting" && (due(s) || (refused(s) && !s.outpoints.iter().any(|o| taken.contains(o.as_str()))))
        }).map(|s| (s.txid.clone(), (s.status.clone(), s.confirmations, s.proof_verified))).collect();
        if !picked.is_empty() {
            let offset = (state.sent_lookup_offset.load(Ordering::Relaxed) % picked.len() as u64) as usize;
            picked.rotate_left(offset);
            picked.truncate(20);
        }
        picked
    })
    .unwrap_or_default();
    let mut found = Vec::new();
    let deadline = clock() + LOOKUP_BUDGET;
    for (txid, was) in picked {
        if clock() > deadline {
            break;
        }
        state.sent_lookup_offset.fetch_add(1, Ordering::Relaxed);
        if let Ok(status) = lookup_sent(&state.sources, &txid, flags).await {
            found.push((txid, was, status));
        }
    }
    let refreshed = edit_sent(state, |sent| {
        for (txid, was, (status, proven)) in &found {
            // Only to a record that did not change while it was looked up.
            let Some(s) = sent.iter_mut().find(|s| &s.txid == txid && s.status == was.0 && s.confirmations == was.1 && s.proof_verified == was.2) else { continue };
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

/// The transactions this wallet sent, their states looked up again where they may have changed.
#[tauri::command]
pub async fn activity(state: State<'_, AppState>) -> Res<Vec<Sent>> {
    if !state.unlocked() {
        return Err(Failure::new("locked"));
    }
    let at = now();
    Ok(refresh_sent(&state, |s| !s.proven() && (!settled(s) || recent(s, at)), &mut Flags::default()).await)
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
    let chain = current_chain(&sources, &mut flags).await?;
    let account = account_for(mixed, &chain, Some(path))?;
    let coins = flags.take(sources.coins(&account.template.address).await)?;
    let largest = coins.spendable.iter().max_by_key(|c| c.sats).cloned().ok_or_else(|| Failure::new("no_coins"))?;
    let destination = parse_destination(&account.template.address)?;
    let plan = wallet::plan_spend(&account, std::slice::from_ref(&largest), &[], &destination, Amount::All, chain.lock_time())?;
    let own = { let (a, b, c) = state.templates()?; vec![a, b, c] };
    let spending = pending_everywhere(&sources, &coins, &own, &account.template.address, &mut flags).await?;
    let pending = PendingSend {
        id: String::new(), created: Instant::now(), kind: Kind::Mixed, path, destination, plan,
        // The drill dialog does not authorize paying in addition to an earlier uncertain payment.
        caution: false, sources: flags,
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
    let _ = edit_sent(state, |sent| {
        if let Some(s) = sent.iter_mut().find(|s| s.txid == signed.txid && s.status == "submitting") {
            s.status = "unknown".into();
        }
        mark_replaced(sent);
    });
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
    ]
    .into_iter()
    .map(|(t, path)| {
        let kind = t.kind;
        let a = Account::new(t, path).expect("each has the leaf");
        let s = wallet::measure(&a, std::slice::from_ref(&coin), &out, 0);
        let signature_bytes = if path == Path::Schnorr { 64 } else { MLDSA44_SIGNATURE_CHUNKS.iter().sum() };
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
    store::save(&state.dir.join("settings.json"), &settings).map_err(|_| Failure::new("io"))?;
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

/// Opens one of the network's pages in the system browser: the faucet, or the explorer at a transaction
/// this wallet recorded or at one of its own addresses. Nothing else can be opened from the interface, and
/// no value it makes up reaches the browser.
#[tauri::command]
pub fn open_page(app: AppHandle, state: State<'_, AppState>, page: String, value: Option<String>) -> Res<()> {
    use tauri_plugin_opener::OpenerExt;
    let value = value.unwrap_or_default();
    let recorded = || store::load::<Vec<Sent>>(&state.sent_path()).iter().any(|s| s.txid == value);
    let own = || state.templates().is_ok_and(|(a, b, c)| [a, b, c].iter().any(|t| t.address == value));
    let url = match page.as_str() {
        "faucet" => FAUCET.to_string(),
        "explorer" => format!("{EXPLORER}/"),
        "tx" if crate::api::is_txid(&value) && recorded() => format!("{EXPLORER}/tx/{value}"),
        "address" if own() => format!("{EXPLORER}/address/{value}"),
        _ => return Err(Failure::new("invalid_page")),
    };
    app.opener().open_url(url, None::<&str>).map_err(|_| Failure::new("io"))
}

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
            state.open_session(&secret, state.generation()).unwrap();
            let wrong = tauri::async_runtime::block_on(reveal_secret(&state, "wrong password".into(), Some("en"), |_| async {
                panic!("a wrong password must not open a dialog")
            }));
            assert_eq!(wrong.unwrap_err().code, "wrong_password");
            assert_eq!(reveal("correct horse", false).unwrap_err().code, "cancelled");
            assert_eq!(reveal("correct horse", true).unwrap(), secret.recovery_text().as_str());
            let locked = tauri::async_runtime::block_on(reveal_secret(&state, "correct horse".into(), Some("en"), |_| {
                // Even unlocking again while the dialog is open cannot revive its earlier permission.
                state.lock();
                state.open_session(&secret, state.generation()).unwrap();
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
        state.open_session(&secret, state.generation()).unwrap();
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
            state.open_session(&secret, state.generation()).unwrap();
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
        state.open_session(&secret, state.generation()).unwrap();
        let wrong = tauri::async_runtime::block_on(change_wallet_password(&state, "wrong password".into(), "battery staple".into(), Some("en"), |_| async {
            panic!("a wrong password must not open a dialog")
        }));
        assert_eq!(wrong.unwrap_err().code, "wrong_password");
        assert_eq!(change("correct horse", false).unwrap_err().code, "cancelled");
        assert_eq!(std::fs::read(state.vault_path()).unwrap(), original);
        let relocked = tauri::async_runtime::block_on(change_wallet_password(&state, "correct horse".into(), "battery staple".into(), Some("en"), |_| {
            state.lock();
            state.open_session(&secret, state.generation()).unwrap();
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
            state.open_session(&secret, state.generation()).unwrap();
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
            state.open_session(&secret, state.generation()).unwrap();
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
            state.open_session(&secret, state.generation()).unwrap();
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
                state.open_session(&secret, state.generation()).unwrap();
            }
            if scenario == "answer" {
                answers.remove(0).send(true).unwrap();
            }
            state.lock();
            state.open_session(&secret, state.generation()).unwrap();
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
                    state.open_session(&secret, state.generation()).unwrap();
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
                    state.open_session(&secret, state.generation()).unwrap();
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
                state.open_session(&secret, state.generation()).unwrap();
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
        state.open_session(&secret, state.generation()).unwrap();
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
                    state.open_session(&secret, state.generation()).unwrap();
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
                state.open_session(&secret, state.generation()).unwrap();
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
        let confirmed = |i: usize| Sent {
            txid: format!("{i:064x}"),
            created: 1_000 + i as u64,
            confirmations: 6,
            proof_verified: true,
            outpoints: vec![format!("{i:064x}:1")],
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
                let checked = recheck_payment(&state, &mut pending).await.unwrap();
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
            state.open_session(&Secret::new_bip39().unwrap(), state.generation()).unwrap();
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
                let checked = recheck_payment(&state, &mut pending).await.unwrap();
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
                state.open_session(&Secret::new_bip39().unwrap(), state.generation()).unwrap();
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
                    let checked = recheck_payment(&state, &mut pending).await.unwrap();
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
        state.open_session(&Secret::new_bip39().unwrap(), state.generation()).unwrap();
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
        let mut pending = tauri::async_runtime::block_on(pending_everywhere(&sources, &coins, &own, &own[0].address, &mut Flags::default())).unwrap();
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
            let pending = tauri::async_runtime::block_on(pending_everywhere(&sources, &coins, &own, &own[0].address, &mut Flags::default())).unwrap();
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
            state.open_session(&Secret::new_bip39().unwrap(), state.generation()).unwrap();
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
        state.open_session(&Secret::new_bip39().unwrap(), state.generation()).unwrap();
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
    fn lookup_batches_rotate_and_uncovered_refusals_stay_due() {
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
            for _ in 0..2 { refresh_sent(&state, |_| false, &mut Flags::default()).await; }
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
    fn two_due_records_rotate_after_one_lookup_uses_the_budget() {
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
            refresh_sent(&state, |_| false, &mut Flags::default()).await;
            assert_eq!(state.sent_lookup_offset.load(Ordering::Relaxed), 0);
            for started in 1..=2 {
                let at = Instant::now();
                // The first lookup consumes the whole budget without a wall-clock delay in the test.
                let mut ticks = [at, at, at + LOOKUP_BUDGET + Duration::from_secs(1)].into_iter();
                refresh_sent_with_clock(&state, |_| true, &mut Flags::default(), || ticks.next().unwrap()).await;
                assert_eq!(state.sent_lookup_offset.load(Ordering::Relaxed), started);
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
    fn one_source_adds_its_dialog_note_without_a_payment_warning() {
        use crate::api::tests::{response, serve, utxo};
        use crate::chain::tests::state as chain_state;
        use crate::sources::tests::coins;

        let mut state = test_state("one-source-note");
        state.open_session(&Secret::new_bip39().unwrap(), state.generation()).unwrap();
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
            let checked = recheck_payment(&state, &mut pending).await.unwrap();
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
        state.open_session(&Secret::new_bip39().unwrap(), state.generation()).unwrap();
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
            let (_, coins, spending) = recheck_payment(&state, &mut pending).await.unwrap();
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
            state.open_session(&Secret::new_bip39().unwrap(), state.generation()).unwrap();
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
                let (_, coins, spending) = recheck_payment(&state, &mut pending).await.unwrap();
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
                    let checked = recheck_payment(&state, &mut pending).await.unwrap();
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
        let sent = tauri::async_runtime::block_on(refresh_sent(&state, |_| true, &mut Flags::default()));
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
            let sent = tauri::async_runtime::block_on(refresh_sent(&state, |_| true, &mut flags));
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
            for _ in 0..6 { results.push(refresh_sent(&state, |_| true, &mut Flags::default()).await); }
            results
        });
        let requests = server.join().unwrap();
        assert_eq!(other.join().unwrap().len(), 10);
        assert_eq!(requests.len(), 10);
        assert_eq!(results[0][0].status, "confirmed");
        assert_eq!(results[0][0].confirmations, 5);
        assert!(!results[0][0].proof_verified);
        assert!(surfaced(&results[0]));
        for result in &results[1..4] { assert_eq!(result, &results[0]); }
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
        let one = serde_json::to_vec_pretty(&vec![old.clone()]).unwrap().len();
        let count = (store::MAX_FILE_BYTES as usize - 2) / (one - 2);
        let original = serde_json::to_vec_pretty(&vec![old; count]).unwrap();
        assert!(original.len() as u64 <= store::MAX_FILE_BYTES);
        let mut migrated: Vec<Sent> = serde_json::from_slice(&original).unwrap();
        for s in &mut migrated { prepare_record(s); }
        assert!(serde_json::to_vec_pretty(&migrated).unwrap().len() as u64 > store::MAX_FILE_BYTES);
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-full-migration-{}", hex::encode(nonce)));
        store::write_atomic(&dir.join("sent.json"), &original).unwrap();
        let state = AppState::new(dir.clone()).unwrap();
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), original);
        assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap().len(), count);
        assert_eq!(edit_sent(&state, |_| ()).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        // When the record cannot be written, the fallback read must still restore the protection in memory.
        let view = tauri::async_runtime::block_on(refresh_sent(&state, |_| false, &mut Flags::default()));
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
                        let mut pending = guard(&state.pending).take().unwrap();
                        let checked = recheck_payment(&state, &mut pending).await.unwrap();
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
            let first = refresh_sent(&state, |_| true, &mut flags).await;
            let second = refresh_sent(&state, |_| true, &mut Flags::default()).await;
            (first, second)
        });
        first.join().unwrap();
        second.join().unwrap();
        assert_eq!(results.0, vec![old]);
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
}
