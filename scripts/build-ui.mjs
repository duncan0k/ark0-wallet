// Builds the user interface into dist/: one ES module bundle plus the static files. No dev server, no
// inline scripts (the window's CSP allows 'self' only).
import { build } from 'esbuild';
import { copyFile, mkdir, rm } from 'node:fs/promises';

await rm('dist', { recursive: true, force: true });
await mkdir('dist', { recursive: true });
await build({
  entryPoints: ['ui/main.tsx'],
  bundle: true,
  jsx: 'automatic',
  jsxImportSource: 'preact',
  minify: true,
  format: 'esm',
  target: 'es2020',
  outfile: 'dist/main.js',
  legalComments: 'none',
  logLevel: 'warning',
});
for (const f of ['index.html', 'style.css']) await copyFile(`ui/${f}`, `dist/${f}`);
console.log('ui built into dist/');
