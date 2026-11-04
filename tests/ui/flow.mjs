// Flow tests of the interface: the built pages (dist/, from `npm run build:ui`) in headless Chromium, with
// the core replaced by a script that answers its commands. They check what a person can do on the screens,
// not the core.
//
//   npm run build:ui && node tests/ui/flow.mjs
//
// Needs Playwright with Chromium (`npm i -g playwright`, or set NODE_PATH to where it is installed).
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, '../../dist');
const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  const { execSync } = await import('node:child_process');
  ({ chromium } = require(join(execSync('npm root -g').toString().trim(), 'playwright')));
}

const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
const server = createServer(async (req, res) => {
  try {
    const path = join(dist, new URL(req.url, 'http://x').pathname.replace(/^\/$/, '/index.html'));
    res.writeHead(200, { 'Content-Type': types[extname(path)] ?? 'application/octet-stream' });
    res.end(await readFile(path));
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

const H4T = 55000;
const addr = (c) => 'tb1z' + c.repeat(58);
const chain = {
  tip: H4T + 20, tip_time: 1760000000, mldsa44_height: 8600, mldsa44_allowed: true, tripwire_height: 30000, tripwire_tip: H4T + 20,
  ec_disabled: false, tripwires: [], mixed_allowed: true, lattice_height: H4T, lattice_tip: H4T + 20, mldsa_disabled: false,
  lattice_tripwires: [], pq2_allowed: true, pq2_spendable: true,
};
const account = (kind) => ({ kind, address: addr(kind[0]), shown: true, path: kind === 'schnorr' ? 'schnorr' : 'mldsa44', spendable: 0, pending: 0, incoming: 0, coins: 0, complete: true });
const pq2Address = addr('q');
const overview = {
  chain, problem: null, accounts: [account('mldsa44'), account('schnorr'), account('mixed')], fetched: 1760000000,
  pq2: {
    blocked: null, allowed: true, spend_allowed: true, opens_at: H4T + 6, mldsa44_allowed: true, mldsa_disabled: false,
    spendable: 210000, pending: 0, incoming: 0, complete: true, change_blocked: false, scanned: [0, 0], issued: [1, 0],
    addresses: [{ chain: 0, index: 0, address: pq2Address, mldsa44_fits: true, spendable: 210000, pending: 0, incoming: 0, complete: true,
      coins: [{ txid: 'd'.repeat(64), vout: 0, sats: 210000, height: H4T + 7, status: 'protected', spending: false }] }],
  },
};
const info = { version: '0', api: '', explorer: '', faucet: '', target: '', fee_rate: 2, costs: [] };
const plan = (id, signature, extra = {}) => ({
  id, from: 'pq2', signature, to: addr('t'), send: 100000, fee: signature === 'mldsa44' ? 4000 : 8400, change: 0, inputs: 1, vsize: 2000, size: 8000,
  fee_rate: 2, left: 0, truncated: false, to_self: false, replaces: 0, went_out: false, unclear_elsewhere: false, unrecorded: false,
  one_source: false, sources_disagree: false,
  pq2: { address: pq2Address, mldsa44_allowed: true, mldsa44_reason: null, witness_bytes: 3795, several_coins: false, staying_coins: 0,
    staying_sats: 0, change_address: null, change_blocked: false, rebuilt_from: null, ...extra },
});

/** Opens the app with these answers; returns the page and the log of commands it sent. */
async function open(browser, answers) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 1600 } });
  await page.exposeFunction('__answer', (cmd, args) => answers(cmd, args));
  await page.addInitScript(() => {
    let n = 0;
    window.__calls = [];
    window.__TAURI_INTERNALS__ = {
      invoke: async (cmd, args) => {
        if (cmd.startsWith('plugin:')) return 0;
        window.__calls.push([cmd, args]);
        const a = await window.__answer(cmd, args ?? {});
        if (a && a.__reject) throw a.__reject;
        return a;
      },
      transformCallback: () => ++n, unregisterCallback: () => {},
      metadata: { currentWindow: { label: 'main' }, currentWebview: { windowLabel: 'main', label: 'main' } },
    };
    window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
  });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(`${base}/index.html`);
  await page.waitForSelector('text=Overview');
  return { page, errors, calls: () => page.evaluate(() => window.__calls.map((c) => c[0])) };
}

const common = (cmd) => ({
  app_info: info, wallet_status: { exists: true, unlocked: true, legacy: false }, overview,
  settings_get: { language: 'en', auto_lock_minutes: 15 }, activity: [], qr_svg: '<svg/>',
})[cmd];

let failed = 0;
async function test(name, body) {
  const browser = await chromium.launch();
  try {
    await body(browser);
    console.log(`ok: ${name}`);
  } catch (e) {
    failed = 1;
    console.log(`FAILED: ${name}\n  ${e.message}`);
  } finally {
    await browser.close();
  }
}
function assert(ok, what) {
  if (!ok) throw new Error(what);
}

async function reviewFromPq2(page) {
  await page.locator('nav button, .nav button, [role=tab]').filter({ hasText: /^Send$/ }).first().click();
  await page.locator('.source', { hasText: 'pq2' }).first().click();
  await page.locator('.source', { hasText: 'ML-DSA-44' }).last().click();
  await page.fill('#to', addr('t'));
  await page.fill('#amount', '0.001');
  await page.locator('button[type=submit]').click();
  await page.waitForSelector('.modal');
}

await test('after a rebuild the review can be confirmed again', async (browser) => {
  let confirms = 0;
  const { page, errors, calls } = await open(browser, (cmd) => {
    if (cmd === 'plan_send') return plan('first', 'mldsa44');
    if (cmd === 'confirm_send') {
      confirms += 1;
      if (confirms === 1) return { result: { kind: 'unknown' }, txid: '', sign_ms: 0, rebuilt: plan('second', 'slhdsa128s', { rebuilt_from: '', witness_bytes: 7972 }) };
      return { result: { kind: 'sent', txid: 'a'.repeat(64) }, txid: 'a'.repeat(64), sign_ms: 900, rebuilt: null };
    }
    return common(cmd);
  });
  await reviewFromPq2(page);
  await page.locator('.modal button', { hasText: 'Confirm' }).click();
  await page.waitForSelector('text=Here it is again through SLH-DSA');
  const confirm = page.locator('.modal button', { hasText: 'Confirm' });
  assert(await confirm.isEnabled(), 'the Confirm button of the rebuilt plan is enabled');
  await confirm.click();
  await page.waitForSelector('text=Sent', { timeout: 3000 });
  const sent = (await calls()).filter((c) => c === 'confirm_send').length;
  assert(sent === 2, `confirm_send called twice, got ${sent}`);
  assert(errors.length === 0, errors.join('; '));
});

await test('after a rebuild the review can be cancelled', async (browser) => {
  const { page } = await open(browser, (cmd) => {
    if (cmd === 'plan_send') return plan('first', 'mldsa44');
    if (cmd === 'confirm_send') return { result: { kind: 'unknown' }, txid: '', sign_ms: 0, rebuilt: plan('second', 'slhdsa128s', { rebuilt_from: '' }) };
    return common(cmd);
  });
  await reviewFromPq2(page);
  await page.locator('.modal button', { hasText: 'Confirm' }).click();
  await page.waitForSelector('text=Here it is again through SLH-DSA');
  await page.locator('.modal button', { hasText: 'Cancel' }).click();
  await page.waitForSelector('.modal', { state: 'detached', timeout: 2000 });
});

await test('a refusal whose rebuild could not be planned says so', async (browser) => {
  const reason = 'mempool-script-verify-flag-failed (ML-DSA-44 signature checks are disabled in this leaf)';
  const { page, errors } = await open(browser, (cmd) => {
    if (cmd === 'plan_send') return plan('first', 'mldsa44');
    if (cmd === 'confirm_send') return { result: { kind: 'rejected', reason }, txid: 'b'.repeat(64), sign_ms: 900, rebuilt: null, rebuild_error: 'limit' };
    return common(cmd);
  });
  await reviewFromPq2(page);
  await page.locator('.modal button', { hasText: 'Confirm' }).click();
  await page.waitForSelector('text=could not be prepared again with SLH-DSA just now', { timeout: 3000 });
  await page.waitForSelector(`text=${reason}`);
  assert(errors.length === 0, errors.join('; '));
});

await test('a failed confirmation leaves the review usable', async (browser) => {
  const { page } = await open(browser, (cmd) => {
    if (cmd === 'plan_send') return plan('first', 'slhdsa128s');
    if (cmd === 'confirm_send') return { __reject: { code: 'coins_changed' } };
    return common(cmd);
  });
  await reviewFromPq2(page);
  await page.locator('.modal button', { hasText: 'Confirm' }).click();
  await page.waitForSelector('text=The coins changed');
  assert(await page.locator('.modal button', { hasText: 'Confirm' }).isEnabled(), 'Confirm enabled after an error');
});

await test('the ML-DSA-44 leaf is shown disabled for an address whose coins do not fit', async (browser) => {
  const many = structuredClone(overview);
  many.pq2.addresses[0].mldsa44_fits = false;
  const { page } = await open(browser, (cmd) => (cmd === 'overview' ? many : common(cmd)));
  await page.locator('nav button, .nav button, [role=tab]').filter({ hasText: /^Send$/ }).first().click();
  await page.locator('.source', { hasText: 'pq2' }).first().click();
  const mldsa = page.locator('.source', { hasText: 'ML-DSA-44' }).last();
  assert(await mldsa.isDisabled(), 'the ML-DSA-44 choice is disabled');
  await page.waitForSelector('text=all of its coins must go together');
});

server.close();
process.exit(failed);
