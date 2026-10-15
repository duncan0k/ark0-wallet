// Makes src-tauri/tests/vectors/p2mr.json from a checkout of the Ark-0 web wallet (its wallet/ directory,
// with node_modules installed):
//
//   node tools/vectors/run.mjs <path to ark0-web/wallet>
//
// gen.ts imports the web wallet's own modules and the p2mr-ts sources it vendors; esbuild from that
// checkout bundles it, and node runs the bundle.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const walletDir = resolve(process.argv[2] ?? '');
const require = createRequire(join(walletDir, 'package.json'));
const esbuild = require('esbuild');

const source = readFileSync(join(walletDir, 'vendor/p2mr-ts/SOURCE.md'), 'utf8');
const commit = /commit `([0-9a-f]{40})`/.exec(source)?.[1];
if (!commit) throw new Error('no p2mr-ts commit in vendor/p2mr-ts/SOURCE.md');

const work = mkdtempSync(join(tmpdir(), 'pqw-vectors-'));
try {
  const bundle = join(work, 'gen.mjs');
  await esbuild.build({
    entryPoints: [join(here, 'gen.ts')],
    bundle: true,
    platform: 'node',
    format: 'esm',
    outfile: bundle,
    nodePaths: [join(walletDir, 'node_modules')],
    alias: {
      'p2mr-ts': join(walletDir, 'vendor/p2mr-ts/src/index.ts'),
      'wallet/keys': join(walletDir, 'src/keys.ts'),
      'wallet/dest': join(walletDir, 'src/dest.ts'),
      'wallet/spend': join(walletDir, 'src/spend.ts'),
    },
    logLevel: 'warning',
  });
  const json = JSON.parse(execFileSync(process.execPath, [bundle], { encoding: 'utf8', maxBuffer: 64 << 20 }));
  const walletCommit = execFileSync('git', ['-C', walletDir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const vectors = { ...json, reference: { web_wallet_commit: walletCommit, p2mr_ts_commit: commit } };
  const out = join(here, '../../src-tauri/tests/vectors/p2mr.json');
  const text = JSON.stringify(vectors, null, 2) + '\n';
  writeFileSync(out, text);
  console.log(`${out}: ${vectors.spends.length} spends, sha256 ${createHash('sha256').update(text).digest('hex')}`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
