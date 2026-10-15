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
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
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
    /// Held while the vault is made, replaced or removed, so that two of those never interleave.
    vault_ops: Mutex<()>,
    /// Held while the record of sent transactions is read, changed and saved (`edit_sent`).
    sent_ops: Mutex<()>,
    /// Counts locks. Work that began before a lock (an unlock's key derivation, a send waiting on the
    /// network or the user) neither opens a session nor signs after it.
    generation: AtomicU64,
}

impl AppState {
    pub fn new(dir: PathBuf) -> Self {
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
            generation: AtomicU64::new(0),
        };
        // The startup migration goes through the size check too; when the record does not fit, the readable file stays as it was.
        let _ = edit_sent(&state, |sent| {
            for s in sent.iter_mut().filter(|s| s.status == "submitting") {
                s.status = "unknown".into();
                s.doubted = true;
            }
        });
        state
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
        self.generation.fetch_add(1, Ordering::SeqCst);
        *guard(&self.session) = None;
        *guard(&self.pending) = None;
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
pub fn new_phrase(state: State<'_, AppState>) -> Vec<String> {
    let secret = Secret::new_bip39();
    let words = secret.recovery_text().split(' ').map(String::from).collect();
    *guard(&state.new_wallet) = Some(NewWallet { secret, confirmed: false });
    words
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
    let password = Zeroizing::new(password);
    let generation = state.generation();
    let new = guard(&state.new_wallet).take().ok_or_else(|| Failure::new("no_phrase"))?;
    if !new.confirmed {
        *guard(&state.new_wallet) = Some(new);
        return Err(Failure::new("phrase_not_confirmed"));
    }
    {
        let _one_at_a_time = guard(&state.vault_ops);
        if let Err(e) = vault::create(&state.vault_path(), &password, &new.secret) {
            // The words were just written down: they stay, for another try.
            *guard(&state.new_wallet) = Some(new);
            return Err(e.into());
        }
    }
    state.open_session(&new.secret, generation)?;
    Ok(wallet_status(state))
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
    let (text, password) = (Zeroizing::new(text), Zeroizing::new(password));
    let generation = state.generation();
    let secret = parse_recovery(&text)?;
    {
        let _one_at_a_time = guard(&state.vault_ops);
        vault::create(&state.vault_path(), &password, &secret)?;
    }
    state.open_session(&secret, generation)?;
    Ok(wallet_status(state))
}

#[tauri::command]
pub fn bip39_words() -> Vec<&'static str> {
    word_list().to_vec()
}

#[tauri::command(async)]
pub fn unlock(state: State<'_, AppState>, password: String) -> Res<Status> {
    let password = Zeroizing::new(password);
    let generation = state.generation();
    let secret = vault::open(&state.vault_path(), &password)?;
    state.open_session(&secret, generation)?;
    Ok(wallet_status(state))
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

/// The words or backup code, after the password again.
#[tauri::command(async)]
pub fn reveal_recovery(state: State<'_, AppState>, password: String) -> Res<String> {
    let password = Zeroizing::new(password);
    let secret = vault::open(&state.vault_path(), &password)?;
    Ok(secret.recovery_text().to_string())
}

#[tauri::command(async)]
pub fn change_password(state: State<'_, AppState>, old: String, new: String) -> Res<()> {
    let (old, new) = (Zeroizing::new(old), Zeroizing::new(new));
    let _one_at_a_time = guard(&state.vault_ops);
    Ok(vault::change_password(&state.vault_path(), &old, &new)?)
}

/// Removes the wallet from this device: the vault and the record of sent transactions.
#[tauri::command(async)]
pub fn delete_wallet(state: State<'_, AppState>, password: String) -> Res<Status> {
    let password = Zeroizing::new(password);
    {
        let _one_at_a_time = guard(&state.vault_ops);
        vault::delete(&state.vault_path(), &password)?;
        // Locked before the record goes, so that no send begun earlier records into a fresh one.
        state.lock();
        let _sent = guard(&state.sent_ops);
        let _ = std::fs::remove_file(state.sent_path());
    }
    Ok(wallet_status(state))
}

/// For a forgotten password: removes the wallet without it, only while it is locked, and only after the
/// user confirms in a system dialog (the interface's own confirmation is not enough: it is the web view's).
/// The recovery words or backup code bring the wallet back.
#[tauri::command]
pub async fn forget_wallet(app: AppHandle, state: State<'_, AppState>, locale: Option<String>) -> Res<Status> {
    if state.unlocked() {
        return Err(Failure::new("unlocked"));
    }
    if !crate::confirm::ask(&app, crate::confirm::removal(state.dialog_locale(locale.as_deref()))).await {
        return Err(Failure::new("cancelled"));
    }
    {
        let _one_at_a_time = guard(&state.vault_ops);
        if state.unlocked() {
            return Err(Failure::new("unlocked"));
        }
        // An unlock still deriving its key does not open the wallet after it is gone.
        state.lock();
        if vault::exists(&state.vault_path()) {
            std::fs::remove_file(state.vault_path()).map_err(|_| Failure::new("io"))?;
        }
        let _sent = guard(&state.sent_ops);
        let _ = std::fs::remove_file(state.sent_path());
    }
    Ok(wallet_status(state))
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
    /// An earlier payment the wallet doubted has gone out, or most likely has (its coins are spent).
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
    let caution = went_out || earlier.elsewhere || earlier.unrecorded || flags.caution();
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
        wallet::sign_plan(&pending.plan, &account, &session.keys)?
    };
    let sign_ms = started.elapsed().as_secs_f64() * 1000.0;
    let record = Sent {
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
    };
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

async fn recheck_payment(state: &AppState, pending: &mut PendingSend) -> Res<(Account, Coins, Vec<Coin>)> {
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
    refresh_sent(state, |s| {
        matches!(s.status.as_str(), "mempool" | "unknown") || (s.status == "confirmed" && !s.proven()) || (refused(s) && recent(s, at))
    }, &mut flags).await;
    let own: Vec<Template> = { let (a, b, c) = state.templates()?; vec![a, b, c] };
    let spending = pending_everywhere(&state.sources, &coins, &own, &account.template.address, &mut flags).await?;
    pending.sources = flags;
    pending.caution |= flags.caution();
    Ok((account, coins, spending))
}

fn record_payment(state: &AppState, pending: &PendingSend, coins: &Coins, spending: &[Coin], generation: u64, record: Sent) -> Res<()> {
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
        if !covered || (!pending.caution && (earlier.spent || earlier.elsewhere || earlier.unrecorded || surfaced(sent) || pending.sources.caution())) {
            return Err(Failure::new("coins_changed"));
        }
        // The same transaction again (an identical retry): it stays doubted if it was.
        let doubted = sent.iter().any(|s| same(s) && s.doubted);
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
    if s.status == "confirmed" && !s.proven() && !s.doubted {
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
/// pass it on, or a later payment spent one of its coins.
fn settled(s: &Sent) -> bool {
    matches!(s.status.as_str(), "rejected" | "failed" | "replaced")
}

/// A payment without a clear answer that another of the wallet's payments, with the network, spends a
/// coin of cannot go through while that one stands ("replaced"); once that one is no longer with the
/// network, it is without a clear answer again.
fn mark_replaced(sent: &mut [Sent]) {
    let taken: HashSet<String> =
        sent.iter().filter(|s| s.status == "mempool" || s.proven()).flat_map(|s| s.outpoints.iter().cloned()).collect();
    for s in sent.iter_mut().filter(|s| matches!(s.status.as_str(), "unknown" | "replaced")) {
        s.status = if s.outpoints.iter().any(|o| taken.contains(o)) { "replaced" } else { "unknown" }.into();
    }
}

/// The coins being spent by mempool transactions from any of the wallet's addresses (`coins` are those
/// of `paying`, already fetched): a payment made before the wallet was restored here, or on another
/// device, may have gone from any of them. No answer means no plan.
async fn pending_everywhere(sources: &Sources, coins: &Coins, own: &[Template], paying: &str, flags: &mut Flags) -> Res<Vec<Coin>> {
    let mut pending = coins.pending.clone();
    for t in own.iter().filter(|t| t.address != paying) {
        pending.extend(flags.take(sources.coins(&t.address).await)?.pending);
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
    /// that the two can never both go through. Once one of the wallet's payments spends one of its coins,
    /// it is covered.
    required: Vec<Coin>,
    /// The txids of those payments.
    replaces: Vec<String>,
    /// Such a payment whose coins are all spent, by none of the wallet's own payments: it has most likely
    /// gone out, and a new payment is one more rather than a retry.
    spent: bool,
    /// Such a payment from another address, or recorded without its coins: the new payment cannot replace
    /// it. It stays one until a payment from its own address covers it.
    elsewhere: bool,
    /// A coin of the wallet's is being spent by a transaction in the mempool that no record names: a
    /// payment made before the wallet was restored here, or on another device.
    unrecorded: bool,
}

fn earlier_payments(sent: &[Sent], account: &str, spendable: &[Coin], pending: &[Coin]) -> Earlier {
    let coins_of = |statuses: &[&str]| -> HashSet<String> {
        sent.iter().filter(|s| !unclear(s) && statuses.contains(&s.status.as_str())).flat_map(|s| s.outpoints.iter().cloned()).collect()
    };
    // Coins of the wallet's payments on their way, and of those on their way or done.
    let in_flight = coins_of(&["submitting", "mempool"]);
    let taken = coins_of(&["submitting", "mempool", "confirmed"]);
    let usable: Vec<Coin> = spendable.iter().filter(|c| !in_flight.contains(&c.outpoint())).cloned().collect();
    let recorded: HashSet<&str> = sent.iter().flat_map(|s| s.outpoints.iter().map(String::as_str)).collect();
    let unrecorded = pending.iter().any(|c| !recorded.contains(c.outpoint().as_str()));
    let mut e = Earlier { usable: Vec::new(), required: Vec::new(), replaces: Vec::new(), spent: false, elsewhere: false, unrecorded };
    for s in sent.iter().filter(|s| unclear(s) || refused(s)) {
        if s.outpoints.iter().any(|o| taken.contains(o)) {
            // Another of the wallet's payments spends one of its coins: it cannot go through.
            continue;
        }
        if s.from != account || s.outpoints.is_empty() {
            e.elsewhere = true;
            continue;
        }
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

/// Looks up again the recorded transactions `due` picks (at most 20), and applies what changed to the
/// record as it is by then, by txid: the lookups take a while, and a payment may be recorded meanwhile.
/// One being handed to the API is left to the command doing that.
async fn refresh_sent(state: &AppState, due: impl Fn(&Sent) -> bool, flags: &mut Flags) -> Vec<Sent> {
    let picked = edit_sent(state, |sent| {
        // Still being handed to the API long after any answer would have come: the send was cut short.
        let at = now();
        for s in sent.iter_mut().filter(|s| s.status == "submitting" && at.saturating_sub(s.created) > SUBMIT_TIMEOUT_SECS) {
            s.status = "unknown".into();
            s.doubted = true;
        }
        mark_replaced(sent);
        sent.iter().filter(|s| s.status != "submitting" && due(s)).take(20)
            .map(|s| (s.txid.clone(), (s.status.clone(), s.confirmations, s.proof_verified))).collect::<Vec<_>>()
    })
    .unwrap_or_default();
    let mut found = Vec::new();
    let deadline = Instant::now() + LOOKUP_BUDGET;
    for (txid, was) in picked {
        if Instant::now() > deadline {
            break;
        }
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
        sent
    })
}

/// How long a settled outcome is still looked up: a refused transaction may have gone out after all, a
/// replaced one may have been mined first.
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
/// `path`, signed and only checked by the node (testmempoolaccept); it is never broadcast. After the
/// tripwire, the node refuses the Schnorr leaf and gives its reason, which is shown as it is.
#[tauri::command]
pub async fn drill_check(state: State<'_, AppState>, path: Path) -> Res<DrillResult> {
    state.touch();
    let (_, _, mixed) = state.templates()?;
    let sources = state.sources.clone();
    let mut flags = Flags::default();
    let chain = current_chain(&sources, &mut flags).await?;
    let account = account_for(mixed, &chain, Some(path))?;
    let coins = flags.take(sources.coins(&account.template.address).await)?;
    let largest = coins.spendable.iter().max_by_key(|c| c.sats).cloned().ok_or_else(|| Failure::new("no_coins"))?;
    let destination = parse_destination(&account.template.address)?;
    let plan = wallet::plan_spend(&account, &[largest], &[], &destination, Amount::All, chain.lock_time())?;
    let started = Instant::now();
    let signed = {
        let session = guard(&state.session);
        let session = session.as_ref().ok_or_else(|| Failure::new("locked"))?;
        wallet::sign_plan(&plan, &account, &session.keys)?
    };
    let sign_ms = started.elapsed().as_secs_f64() * 1000.0;
    let verdict = sources.check(&signed.hex).await.value;
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
            // Its only coin is spent by the payment on its way: it cannot go through.
            paid('4', "unknown", "mldsa44", &['c']),
            // Refused: the API may have passed it on all the same, so it is covered too, however old.
            Sent { created: NOW - 60, ..paid('5', "rejected", "mldsa44", &['b']) },
            paid('7', "failed", "mldsa44", &['a']),
            // Refused, and one of its coins spent by a later payment of the wallet: covered.
            paid('9', "rejected", "mldsa44", &['a', 'z']),
            Sent { confirmations: 6, proof_verified: true, ..paid('0', "confirmed", "mldsa44", &['z']) },
        ];
        let e = earlier_payments(&sent, "mldsa44", &spendable, &[]);
        assert_eq!(e.usable, vec![coin('a', 5_000), coin('b', 9_000)]);
        assert_eq!(e.required, vec![coin('b', 9_000), coin('a', 5_000)]);
        assert_eq!(e.replaces, vec!["1".repeat(64), "5".repeat(64), "7".repeat(64)]);
        assert!(!e.spent && !e.elsewhere);
        // One whose coins are all spent, by none of the wallet's payments, has most likely gone out.
        let mut more = sent.to_vec();
        more.push(paid('6', "unknown", "mldsa44", &['e']));
        assert!(earlier_payments(&more, "mldsa44", &spendable, &[]).spent);
        // A coin being spent by a transaction no record names: a payment made before a restore, or elsewhere.
        assert!(!earlier_payments(&sent, "mldsa44", &spendable, &[coin('c', 7_000)]).unrecorded);
        assert!(earlier_payments(&sent, "mldsa44", &spendable, &[coin('x', 7_000)]).unrecorded);
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
            let e = earlier_payments(&more, "mldsa44", &spendable, &[]);
            assert_eq!((e.elsewhere, e.spent), (warned, false));
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
            let e = earlier_payments(&sent, "mldsa44", &spendable, &[]);
            assert_eq!(e.usable, spendable.to_vec());
            assert_eq!(e.required, vec![coin('a', 5_000)]);
            assert_eq!(e.replaces, vec![old.txid.clone(), sent[1].txid.clone()]);
            assert!(!e.spent && !e.elsewhere);
            assert!(earlier_payments(&[old.clone()], "mldsa44", &spendable[1..], &[]).spent);
            assert!(earlier_payments(&[old.clone()], "schnorr", &spendable, &[]).elsewhere);
            let mut without_coins = old.clone();
            without_coins.outpoints.clear();
            assert!(earlier_payments(&[without_coins], "mldsa44", &spendable, &[]).elsewhere);

            // Only a verified settlement covers other unclear payments and ends those protections.
            let (status, verified) = confirmed_status(100, REQUIRED_BLOCKS);
            let TxStatus::Confirmed { confirmations } = status else { panic!("confirmed") };
            sent[0] = Sent { confirmations, proof_verified: verified, ..old };
            mark_replaced(&mut sent);
            assert_eq!(sent[1].status, "replaced");
            assert!(!surfaced(&sent));
            let e = earlier_payments(&sent, "mldsa44", &spendable, &[]);
            assert!(e.required.is_empty() && e.replaces.is_empty());
            assert!(!e.spent && !e.elsewhere);
        }
    }

    #[test]
    fn recording_a_retry_rechecks_coverage_and_the_unproven_warning() {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-unproven-retry-{}", hex::encode(nonce)));
        let state = AppState::new(dir.clone());
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
        let rejected = record_payment(&state, &pending, &coins, &[], state.generation(), record_for(&pending)).unwrap_err();
        assert_eq!(rejected.code, "coins_changed");
        let earlier = earlier_payments(&[old], "schnorr", &coins.spendable, &[]);
        pending.plan = wallet::plan_spend(&account, &earlier.usable, &earlier.required, &pending.destination, Amount::Sats(10_000), 0).unwrap();
        assert_eq!(pending.plan.coins, vec![coin('a', 50_000)]);
        pending.caution = false;
        let rejected = record_payment(&state, &pending, &coins, &[], state.generation(), record_for(&pending)).unwrap_err();
        assert_eq!(rejected.code, "coins_changed");
        let saved: Vec<Sent> = store::load_existing(&state.sent_path()).unwrap();
        assert_eq!(saved.len(), 1);
        assert!(saved[0].doubted && !saved[0].proven());
        pending.caution = true;
        let new = record_for(&pending);
        record_payment(&state, &pending, &coins, &[], state.generation(), new.clone()).unwrap();
        assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap()[0], new);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_payment_whose_coin_another_spends_is_replaced_while_that_one_stands() {
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
        assert_eq!(statuses, ["replaced", "mempool", "unknown", "rejected", "confirmed", "replaced", "unknown"]);
        // The payment that replaced it is gone from the network: it may go through again.
        sent[1].status = "unknown".into();
        mark_replaced(&mut sent);
        assert_eq!(sent[0].status, "unknown");
    }

    /// A payment the app stopped in the middle of sending is unknown once it starts again.
    #[test]
    fn a_send_cut_short_is_unknown_after_a_restart() {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-app-test-{}", hex::encode(nonce)));
        store::save(&dir.join("sent.json"), &vec![record('a', "submitting"), record('b', "mempool")]).unwrap();
        let state = AppState::new(dir.clone());
        let sent: Vec<Sent> = store::load(&state.sent_path());
        assert_eq!(sent.iter().map(|s| s.status.as_str()).collect::<Vec<_>>(), ["unknown", "mempool"]);
        assert_eq!(sent[0].outpoints, record('a', "unknown").outpoints);
        let _ = std::fs::remove_dir_all(dir);
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
        let mut state = AppState::new(dir.clone());
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
        let e = earlier_payments(&sent, "mldsa44", &[coin('a', 5_000), coin('b', 90_000)], &[]);
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
            let mut state = AppState::new(dir.clone());
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
            let e = earlier_payments(&sent, "mldsa44", &[coin('a', 5_000), coin('b', 90_000)], &[]);
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
        let mut state = AppState::new(dir.clone());
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
        let state = AppState::new(dir.clone());
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
        let state = AppState::new(dir.clone());
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
        let state = AppState::new(dir.clone());
        assert_eq!(std::fs::read(state.sent_path()).unwrap(), original);
        assert_eq!(store::load_existing::<Vec<Sent>>(&state.sent_path()).unwrap().len(), count);
        assert_eq!(edit_sent(&state, |_| ()).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        // When the record cannot be written, the fallback read must still restore the protection in memory.
        let view = tauri::async_runtime::block_on(refresh_sent(&state, |_| false, &mut Flags::default()));
        assert_eq!(view, migrated);
        assert!(surfaced(&view));
        assert_eq!(earlier_payments(&view, "mldsa44", &[coin('a', 5_000)], &[]).required, vec![coin('a', 5_000)]);
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
                    let mut state = AppState::new(dir.clone());
                    *guard(&state.session) = Some(Session::new(&Secret::new_bip39()).unwrap());
                    // The old payment is in the mempool of another address and not in doubt: on its own it sets no caution.
                    let old = paid('1', "mempool", "mldsa44", &['c']);
                    store::save(&state.sent_path(), &vec![old.clone()]).unwrap();
                    let to = state.templates().unwrap().0.address;
                    let (a, first) = serve(left);
                    let (b, second) = serve(right);
                    state.sources = Arc::new(Sources::new(a, b));
                    let (view, mut pending, checked) = tauri::async_runtime::block_on(async {
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
                    assert!(pending.caution);
                    let (_, coins, spending) = checked;
                    let new = Sent {
                        from: "schnorr".into(),
                        outpoints: pending.plan.coins.iter().map(Coin::outpoint).collect(),
                        ..record('2', "submitting")
                    };
                    // A plan that showed no warning cannot use a source flag to get past the protection when it is recorded.
                    pending.caution = false;
                    let rejected = record_payment(&state, &pending, &coins, &spending, state.generation(), new.clone()).unwrap_err();
                    assert_eq!(rejected.code, "coins_changed");
                    assert_eq!(store::load::<Vec<Sent>>(&state.sent_path()), vec![old]);
                    pending.caution = true;
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
        let mut state = AppState::new(dir.clone());
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
