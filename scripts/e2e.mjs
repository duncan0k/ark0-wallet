// End-to-end run of the real app: makes a wallet the way a person would (reads the words off the screen,
// types three of them back, sets a password), then visits every screen, locks, unlocks, and runs the
// signing core's self-test. A screenshot of each step goes to the output directory. The app must start
// with an empty data directory.
//
//   node scripts/e2e.mjs <app binary | CDP endpoint> <output dir> [language: zh-Hans | zh-Hant | en]
//
// Given the app binary, the script starts it through tauri-driver (WebDriver on 127.0.0.1:4444; Linux).
// Given a CDP endpoint such as http://127.0.0.1:9222, it attaches to a running app whose WebView2 was
// started with --remote-debugging-port (Windows, where the app runs in the signed-in user's session).
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [target, outDir, language = 'zh-Hans'] = process.argv.slice(2);
const PASSWORD = 'correct horse battery staple';
mkdirSync(outDir, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let shot = 0;

/** WebDriver through tauri-driver, which starts the app. Scripts run as WebDriver's execute/sync. */
async function webdriver(app) {
  const DRIVER = 'http://127.0.0.1:4444';
  const call = async (method, path, body) => {
    const res = await fetch(DRIVER + path, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    const json = await res.json();
    if (!res.ok) throw new Error(`${method} ${path}: ${JSON.stringify(json.value ?? json).slice(0, 400)}`);
    return json.value;
  };
  const session = (await call('POST', '/session', { capabilities: { alwaysMatch: { 'tauri:options': { application: app } } } })).sessionId;
  return {
    js: (script, args) => call('POST', `/session/${session}/execute/sync`, { script, args }),
    png: () => call('GET', `/session/${session}/screenshot`),
    stop: () => call('DELETE', `/session/${session}`).catch(() => {}),
  };
}

/** The Chrome DevTools Protocol of a running WebView2; scripts run as a function with the same arguments. */
async function cdp(endpoint) {
  const page = (await (await fetch(`${endpoint}/json`)).json()).find((t) => t.type === 'page');
  if (!page) throw new Error(`no page at ${endpoint}`);
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(new Error(`cannot connect to ${endpoint}`)); });
  const pending = new Map();
  let id = 0;
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    if (m.error) p.reject(new Error(m.error.message));
    else p.resolve(m.result);
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    pending.set(++id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
  return {
    async js(script, args) {
      const r = await send('Runtime.evaluate', { expression: `(async function () { ${script} }).apply(null, ${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
      return r.result.value;
    },
    png: async () => (await send('Page.captureScreenshot', { format: 'png' })).data,
    stop: async () => ws.close(),
  };
}

let driver;

async function js(script, ...args) {
  return driver.js(script, args);
}

async function waitFor(script, what, timeout = 30000, ...args) {
  const end = Date.now() + timeout;
  let last = '';
  for (;;) {
    const v = await js(script, ...args).catch((err) => { last = String(err?.message ?? err); return null; });
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}${last ? ` (last driver error: ${last})` : ''}`);
    await sleep(250);
  }
}

async function screenshot(name) {
  await sleep(450); // let transitions settle
  const png = await driver.png();
  const file = join(outDir, `${String(++shot).padStart(2, '0')}-${name}.png`);
  writeFileSync(file, Buffer.from(png, 'base64'));
  console.log(`screenshot ${file}`);
}

/** Clicks the first visible button whose text contains `text`. */
async function click(text) {
  const ok = await waitFor(
    `const t = arguments[0];
     const b = [...document.querySelectorAll('button')].find((x) => x.offsetParent !== null && !x.disabled && x.textContent.includes(t));
     if (b) { b.click(); return true; } return false;`,
    `a button "${text}"`, 30000, text);
  return ok;
}

/** Sets an input's value the way typing does (Preact listens to input events). */
async function type(selector, value) {
  await waitFor(`return !!document.querySelector(arguments[0])`, selector, 15000, selector);
  await js(
    `const el = document.querySelector(arguments[0]);
     const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
     Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, arguments[1]);
     el.dispatchEvent(new Event('input', { bubbles: true }));`,
    selector, value);
}

const text = (path) => js(`return ${path}`);
const result = { language, steps: [] };
const step = (name, detail = '') => { result.steps.push({ name, detail }); console.log(`step ${name} ${detail}`); };

try {
  driver = /^https?:\/\//.test(target) ? await cdp(target) : await webdriver(target);
  await waitFor(`return document.querySelector('.choice') !== null`, 'the welcome screen');

  // The language, through the settings the core keeps (the first run follows the system).
  await js(`return window.__TAURI_INTERNALS__.invoke('settings_set', { settings: { language: arguments[0], auto_lock_minutes: 15 } })`, language);
  await js(`location.reload(); return true`);
  await waitFor(`return document.querySelector('.choice') !== null`, 'the welcome screen again');
  await screenshot('welcome');

  // Make a wallet.
  await js(`document.querySelectorAll('.choice')[0].click(); return true`);
  await waitFor(`return document.querySelector('.rules') !== null`, 'the rules');
  await screenshot('create-intro');
  await js(`document.querySelector('.check input').click(); return true`);
  await js(`[...document.querySelectorAll('.btn-primary')].pop().click(); return true`);
  await waitFor(`return document.querySelectorAll('.word').length === 24`, 'the 24 words');
  await screenshot('create-words-hidden');
  await js(`document.querySelector('.words-cover button').click(); return true`);
  await screenshot('create-words');
  const words = await text(`[...document.querySelectorAll('.word-w')].map((w) => w.textContent)`);
  step('words', `${words.length} words`);
  await js(`[...document.querySelectorAll('.btn-primary')].pop().click(); return true`);
  await waitFor(`return document.querySelectorAll('.confirm-grid input').length === 3`, 'the check');
  const asked = await text(`[...document.querySelectorAll('.confirm-grid .field-label')].map((l) => parseInt(l.textContent.match(/\\d+/)[0], 10))`);
  for (let i = 0; i < 3; i++) await type(`#w${i}`, words[asked[i] - 1]);
  await screenshot('create-check');
  await js(`[...document.querySelectorAll('.btn-primary')].pop().click(); return true`);
  await waitFor(`return document.querySelector('#pw1') !== null`, 'the password form');
  await type('#pw1', PASSWORD);
  await type('#pw2', PASSWORD);
  await screenshot('create-password');
  await js(`[...document.querySelectorAll('.btn-primary')].pop().click(); return true`);
  await waitFor(`return document.querySelector('.shell') !== null`, 'the wallet', 60000);
  step('created');

  // The overview, with the network's answer.
  await waitFor(`return document.querySelector('.balance') !== null || document.querySelector('.notice-bad') !== null`, 'the overview', 60000);
  const addresses = await text(`[...document.querySelectorAll('.addr-text')].map((a) => a.getAttribute('title'))`);
  step('overview', `addresses shown: ${addresses.length}`);
  await screenshot('overview');

  for (const [i, name] of ['send', 'receive', 'activity', 'drill', 'settings'].entries()) {
    await js(`document.querySelectorAll('.nav-item')[arguments[0]].click(); return true`, i + 1);
    await sleep(900);
    if (name === 'receive') await waitFor(`return document.querySelector('.qr-svg svg') !== null || document.querySelector('.notice') !== null`, 'the QR code', 20000);
    await screenshot(name);
  }

  // The self-test from the settings.
  await js(`document.querySelector('.card-actions button').click(); return true`);
  await waitFor(`return document.querySelector('.selftest .notice') !== null`, 'the self-test report', 60000);
  const selftestOk = await text(`document.querySelector('.selftest .notice').classList.contains('notice-good')`);
  step('selftest', selftestOk ? 'pass' : 'fail');
  await screenshot('settings-selftest');

  // A send form with a bad address and a review that cannot be planned without coins.
  await js(`document.querySelectorAll('.nav-item')[1].click(); return true`);
  await sleep(600);
  const canSend = await text(`document.querySelector('#to') !== null`);
  if (canSend) {
    await type('#to', 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsy');
    await type('#amount', '0.001');
    await js(`[...document.querySelectorAll('.btn-primary')].pop().click(); return true`);
    await waitFor(`return document.querySelector('.form-card .notice-bad') !== null`, 'the address error');
    step('send-validation', await text(`document.querySelector('.form-card .notice-bad').textContent`));
    await screenshot('send-error');
  }

  // Lock, then unlock with the password.
  await js(`document.querySelector('.lock-btn').click(); return true`);
  await waitFor(`return document.querySelector('#unlock') !== null`, 'the unlock screen');
  await screenshot('unlock');
  await type('#unlock', PASSWORD);
  await js(`document.querySelector('.btn-primary').click(); return true`);
  await waitFor(`return document.querySelector('.shell') !== null`, 'the wallet again', 60000);
  step('unlocked');

  result.state = selftestOk ? 'pass' : 'fail';
} catch (err) {
  result.state = 'error';
  result.error = String(err?.message ?? err);
  // What the window showed, as text: the app's own error screen says what failed.
  result.page = await js(`return document.body ? document.body.innerText.slice(0, 2000) : null`).catch((e) => `unavailable: ${e.message}`);
  try { await screenshot('error'); } catch {}
} finally {
  await driver?.stop();
}
writeFileSync(join(outDir, `result-${language}.json`), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));
process.exit(result.state === 'pass' ? 0 : 1);
