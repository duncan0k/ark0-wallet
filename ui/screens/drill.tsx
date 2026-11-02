// The drill: the network's tripwire, and both leaves of the mixed address tried against the node.
import { useState } from 'preact/hooks';
import { codeOf, core, type Chain, type DrillResult, type Overview, type Path } from '../api';
import { Button, Card, Chip, Icon, Notice, useToast } from '../components';
import { errorText, fill, locale, m } from '../i18n';
import { group, ms } from '../format';
import { LegacyNotice, openFaucet } from './overview';

export function Drill({ data, legacy }: { data: Overview | null; legacy: boolean }) {
  const d = m().drill;
  const chain = data?.chain ?? null;
  const mixed = data?.accounts.find((a) => a.kind === 'mixed');
  const toast = useToast();
  const [results, setResults] = useState<Partial<Record<Path, DrillResult | string>>>({});
  const tries: Path[] = ['schnorr', 'mldsa44'];
  const [busy, setBusy] = useState<Path | null>(null);

  const run = async (path: Path) => {
    setBusy(path);
    try {
      const r = await core.drillCheck(path, locale());
      setResults((x) => ({ ...x, [path]: r }));
    } catch (err) {
      setResults((x) => ({ ...x, [path]: errorText(codeOf(err)) }));
    } finally {
      setBusy(null);
    }
  };

  const state = chain?.ec_disabled == null ? d.unknown : chain.ec_disabled ? d.on : d.off;
  return (
    <div class="page">
      <header class="drill-banner">
        <Icon name="alert" size={18} />
        <div>
          <span class="drill-tag">{d.header}</span>
          <p>{d.disclaimer}</p>
        </div>
      </header>

      {legacy && <LegacyNotice />}

      <div class="grid2">
        <Card title={d.state}>
          <div class="tripwire">
            <span class={`tripwire-light ${chain?.ec_disabled ? 'on' : chain?.ec_disabled === false ? 'off' : 'unknown'}`} />
            <p>{state}</p>
          </div>
          {chain && (
            <dl class="facts compact">
              <div><dt>{d.h3}</dt><dd class="num">{chain.tripwire_height === null ? '—' : group(chain.tripwire_height)}</dd></div>
              <div><dt>{m().overview.tip}</dt><dd class="num">{group(chain.tip)}</dd></div>
              {chain.tripwires.map((t) => (
                <div><dt class="mono small">{t.outpoint.slice(0, 10)}…:{t.outpoint.split(':')[1]}</dt><dd><Chip tone={t.unspent ? 'neutral' : 'warn'} dot>{t.unspent ? d.unspent : d.spent}</Chip></dd></div>
              ))}
            </dl>
          )}
        </Card>
        <Card title={m().kinds.mixed.title}>
          <p class="muted">{d.what}</p>
          <div class="leaves">
            <div class={`leaf ${chain?.ec_disabled ? 'leaf-off' : ''}`}><Icon name="lock" size={16} /><span>Schnorr · 0xe0</span></div>
            <div class="leaf leaf-pq"><Icon name="drill" size={16} /><span>ML-DSA-44 · 0xe0</span></div>
          </div>
        </Card>
      </div>

      {chain && chain.lattice_height !== null && <LatticeCard chain={chain} />}

      <Card title={d.tryTitle}>
        <p class="muted">{d.tryHint}</p>
        {!mixed?.shown ? (
          <Notice tone="info">{d.notReady}</Notice>
        ) : mixed.spendable === 0 ? (
          <div class="drill-faucet">
            <Notice tone="info">{d.noCoins}</Notice>
            <Button kind="secondary" icon="drop" onClick={() => openFaucet(mixed.address, toast)}>{d.faucet}</Button>
          </div>
        ) : (
          <div class="drill-tries">
            {tries.map((p) => (
              <div class="drill-try">
                <Button kind={p === 'mldsa44' ? 'primary' : 'secondary'} busy={busy === p} disabled={busy !== null} onClick={() => run(p)}>
                  {p === 'schnorr' ? d.trySchnorr : d.tryMldsa44}
                </Button>
                <Verdict r={results[p]} />
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

/**
 * The lattice tripwires of pq2 as the node reports them: their outputs, the node's name and key hash for
 * each, the node's word for its state, and whether ML-DSA-44 checks in pq2 addresses work in the next
 * block. It draws no conclusion about which of them was spent, or why.
 */
function LatticeCard({ chain }: { chain: Chain }) {
  const p = m().pq2;
  const state = chain.mldsa_disabled == null ? p.latticeUnknown : chain.mldsa_disabled ? p.latticeOn : p.latticeOff;
  return (
    <Card title={p.latticeTitle}>
      <div class="tripwire">
        <span class={`tripwire-light ${chain.mldsa_disabled ? 'on' : chain.mldsa_disabled === false ? 'off' : 'unknown'}`} />
        <p>{state}</p>
      </div>
      <dl class="facts compact">
        <div><dt>{p.h4t}</dt><dd class="num">{chain.lattice_height === null ? '—' : group(chain.lattice_height)}</dd></div>
        {chain.lattice_tripwires.map((t) => (
          <div>
            <dt class="mono small">{t.outpoint.slice(0, 10)}…:{t.outpoint.split(':')[1]}{t.label ? ` · ${t.label}` : ''}</dt>
            <dd><Chip tone="neutral" dot>{t.unspent ? p.reported_unspent : p.reported_missing}</Chip>{t.key_sha256 && <span class="mono small faint"> {t.key_sha256.slice(0, 12)}…</span>}</dd>
          </div>
        ))}
      </dl>
      <p class="faint small">{p.latticeNote}</p>
    </Card>
  );
}

function Verdict({ r }: { r: DrillResult | string | undefined }) {
  const d = m().drill;
  if (r === undefined) return null;
  if (typeof r === 'string') return <Notice tone="bad">{r}</Notice>;
  const v = r.verdict;
  return (
    <div class={`verdict verdict-${v.kind}`}>
      <div class="verdict-head">
        <Icon name={v.kind === 'allowed' ? 'check' : 'alert'} size={18} />
        <strong>{v.kind === 'allowed' ? d.allowed : v.kind === 'rejected' ? d.rejected : errorText(v.error)}</strong>
        <span class="muted small num">{group(r.vsize)} vB · {fill(m().send.signedIn, { ms: ms(r.sign_ms) })}</span>
      </div>
      {v.kind === 'rejected' && (
        <>
          <span class="eyebrow">{d.nodeSays}</span>
          <pre class="node-says">{v.reason}</pre>
        </>
      )}
    </div>
  );
}
