import { useEffect, useState } from 'preact/hooks';
import { signForQuote, type CheckoutResult, type Delegation, type Quote, type SignedVerifyRequest, type VerificationResponse } from '@kya/sdk';
import { kya, merchant, useSession } from '../session';
import { Card, Copy, DecisionBadge, Spinner, Tag, TelegraphEvidence, Timeline, money } from '../ui';

type Product = Awaited<ReturnType<typeof merchant.catalog>>[number];

export function Checkout({ inspect }: { inspect: (id: string) => void }) {
  const s = useSession();
  const [products, setProducts] = useState<Product[]>([]);
  const [sku, setSku] = useState('sku_headphones_nc');
  const [delegations, setDelegations] = useState<Delegation[]>([]);
  const [dlg, setDlg] = useState('');
  const [quote, setQuote] = useState<Quote | null>(null);
  const [signed, setSigned] = useState<SignedVerifyRequest | null>(null);
  const [result, setResult] = useState<CheckoutResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [simulate, setSimulate] = useState('');

  useEffect(() => { merchant.catalog().then(setProducts).catch((e) => setErr(String(e))); }, []);
  useEffect(() => {
    if (!s.token) return;
    kya.listDelegations(s.token).then((r) => {
      const active = r.delegations.filter((d) => !d.revoked_at && Date.parse(d.claims.expires_at) > Date.now() && d.claims.subject_agent_id === s.agent?.agentId);
      setDelegations(active);
      if (!active.some((d) => d.delegation_id === dlg)) setDlg(active[0]?.delegation_id ?? '');
    }).catch(() => {});
  }, [s.token, s.version, s.agent]);
  useEffect(() => { merchant.quote(sku).then(setQuote).catch(() => setQuote(null)); setSigned(null); setResult(null); }, [sku]);

  const sign = async () => {
    setErr(null);
    if (!quote || !dlg) return;
    setSigned(await signForQuote({ kya, merchant, merchantId: s.merchantId, consumerToken: s.token!, agent: await s.ensureAgent() }, dlg, quote));
    setResult(null);
  };

  const buy = async () => {
    if (!signed) return;
    setBusy(true);
    setErr(null);
    try {
      setResult(await merchant.checkout(sku, 1, signed, simulate || undefined));
      s.bump();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  const v = result?.verification as VerificationResponse | undefined;
  return (
    <div class="grid two">
      <div class="stack">
        <Card title="Merchant checkout" actions={<Tag tone="warn">payment SIMULATED</Tag>}>
          <div class="products">
            {products.map((p) => (
              <label class={`product ${sku === p.sku ? 'selected' : ''}`} key={p.sku}>
                <input type="radio" name="sku" checked={sku === p.sku} onChange={() => setSku(p.sku)} />
                <span>{p.name}</span>
                <strong>{money(p.unit_price_minor, p.currency)}</strong>
              </label>
            ))}
          </div>
          <dl class="kv">
            <dt>Shopping agent</dt>
            <dd>{s.agent ? <><Copy value={s.agent.agentId} label={s.agent.agentId} /> <span class="muted small">key {s.agent.publicKeyB64.slice(0, 10)}…</span></> : <button class="btn btn-small" onClick={() => s.newAgent()}>Register demo agent</button>}</dd>
            <dt>Consent scope</dt>
            <dd>
              {delegations.length === 0 ? <span class="muted">No active delegation for this agent; create one in Consumer.</span> : (
                <select value={dlg} onChange={(e) => setDlg(e.currentTarget.value)}>
                  {delegations.map((d) => (
                    <option value={d.delegation_id} key={d.delegation_id}>
                      {d.delegation_id.slice(0, 14)}… ≤ {money(d.claims.max_amount_minor, d.claims.currency)} @ {d.claims.merchant_id}
                    </option>
                  ))}
                </select>
              )}
            </dd>
            <dt>Cart digest</dt><dd><Copy value={quote?.cart_digest} /></dd>
            {s.status?.telegraph.simulated && (
              <>
                <dt>Simulate risk</dt>
                <dd>
                  <select value={simulate} onChange={(e) => setSimulate(e.currentTarget.value)}>
                    <option value="">normal (low risk)</option>
                    <option value="high_risk">high risk</option>
                    <option value="critical_risk">critical risk</option>
                    <option value="unavailable">provider unavailable</option>
                    <option value="prompt_injection">prompt-injected result</option>
                  </select>
                </dd>
              </>
            )}
          </dl>
          <div class="row gap">
            <button class="btn" onClick={sign} disabled={!quote || !dlg || !s.agent}>1. Agent signs intent</button>
            <button class="btn btn-primary" onClick={buy} disabled={!signed || busy}>{busy ? <Spinner /> : '2. Submit to merchant'}</button>
          </div>
          {err && <p class="error">{err}</p>}
        </Card>
        {signed && (
          <Card title="Signed purchase intent">
            <p class="muted small">Ed25519 over <code>KYA-PURCHASE-INTENT-V1\n</code> + canonical JSON. Signature excluded below.</p>
            <pre class="code">{JSON.stringify({ ...signed, signature: signed.signature.slice(0, 16) + '…' }, null, 2)}</pre>
          </Card>
        )}
      </div>
      <div class="stack">
        {v?.decision ? (
          <>
            <Card title={<>Decision <DecisionBadge d={v.decision} large /></>} actions={<button class="btn btn-ghost" onClick={() => inspect(v.verification_id)}>Open evidence →</button>}>
              <p><strong>Order:</strong> {result?.order?.status} <span class="muted small">· {result?.order?.payment_note}</span></p>
              <div class="codes">{v.reason_codes.map((c) => <code key={c}>{c}</code>)}</div>
              <ul class="explain">{v.explanation.map((e, i) => <li key={i}>{e}</li>)}</ul>
            </Card>
            <Card title="Verification timeline"><Timeline steps={v.trace ?? []} /></Card>
            <Card title="Purchased intelligence"><TelegraphEvidence v={v} /></Card>
          </>
        ) : result ? (
          <Card title="Rejected by merchant"><pre class="code">{JSON.stringify(result.verification, null, 2)}</pre></Card>
        ) : (
          <Card title="Decision"><p class="muted">Sign and submit an intent to see the merchant agent's automatic KYA verification.</p></Card>
        )}
      </div>
    </div>
  );
}
