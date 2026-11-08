import { useEffect, useState } from 'preact/hooks';
import type { Delegation } from '@kya/sdk';
import { DEMO_PASS, DEMO_USER, kya, useSession } from '../session';
import { Card, Copy, Tag, money } from '../ui';

export function Consumer() {
  const s = useSession();
  const [user, setUser] = useState(DEMO_USER);
  const [pass, setPass] = useState(DEMO_PASS);
  const [list, setList] = useState<Delegation[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({ merchant: '', max: '500', cumulative: '', minutes: '30', categories: '' });

  const load = async () => {
    if (!s.token) return;
    try {
      setList((await kya.listDelegations(s.token)).delegations);
    } catch (e) {
      setErr(String(e));
    }
  };
  useEffect(() => { load(); }, [s.token, s.version]);

  const create = async (e: Event) => {
    e.preventDefault();
    setErr(null);
    try {
      const agent = await s.ensureAgent();
      const token = await s.ensureToken();
      await kya.createDelegation(token, {
        agent_id: agent.agentId,
        merchant_id: form.merchant || s.merchantId,
        actions: ['purchase'],
        max_amount_minor: Math.round(Number(form.max) * 100),
        cumulative_limit_minor: form.cumulative ? Math.round(Number(form.cumulative) * 100) : undefined,
        categories: form.categories ? form.categories.split(',').map((c) => c.trim()).filter(Boolean) : undefined,
        currency: 'USD',
        expires_in_seconds: Math.round(Number(form.minutes) * 60),
      });
      s.bump();
    } catch (e) {
      setErr(String(e));
    }
  };

  const revoke = async (id: string) => {
    if (!s.token) return;
    await kya.revokeDelegation(s.token, id).catch((e) => setErr(String(e)));
    s.bump();
  };

  if (!s.token) {
    return (
      <Card title="Consumer sign-in">
        <p class="muted">Synthetic demo account. This is <strong>not</strong> identity proofing; it stands in for the consumer's real authentication.</p>
        <form class="form" onSubmit={async (e) => { e.preventDefault(); await s.login(user, pass).catch((x) => setErr(String(x))); }}>
          <label>Username<input value={user} onInput={(e) => setUser(e.currentTarget.value)} /></label>
          <label>Password<input type="password" value={pass} onInput={(e) => setPass(e.currentTarget.value)} /></label>
          <button class="btn btn-primary">Sign in</button>
          {err && <p class="error">{err}</p>}
        </form>
      </Card>
    );
  }

  const now = Date.now();
  return (
    <div class="stack">
      <Card title="Delegate purchasing authority" actions={<button class="btn btn-ghost" onClick={s.logout}>Sign out</button>}>
        <p class="muted small">
          Consumer <Copy value={s.consumerRef} /> delegates to agent {s.agent ? <Copy value={s.agent.agentId} label={s.agent.agentId} /> : <em>(created on submit)</em>}.
          KYA signs the delegation claims with its issuer key; merchants verify it on every purchase.
        </p>
        <form class="form grid-form" onSubmit={create}>
          <label>Merchant<input placeholder={s.merchantId} value={form.merchant} onInput={(e) => setForm({ ...form, merchant: e.currentTarget.value })} /></label>
          <label>Per-purchase limit (USD)<input type="number" min="1" step="0.01" value={form.max} onInput={(e) => setForm({ ...form, max: e.currentTarget.value })} /></label>
          <label>Cumulative limit (optional)<input type="number" min="1" step="0.01" value={form.cumulative} onInput={(e) => setForm({ ...form, cumulative: e.currentTarget.value })} /></label>
          <label>Expires in (minutes)<input type="number" min="1" max="1440" value={form.minutes} onInput={(e) => setForm({ ...form, minutes: e.currentTarget.value })} /></label>
          <label>Categories (optional, comma-separated)<input placeholder="electronics" value={form.categories} onInput={(e) => setForm({ ...form, categories: e.currentTarget.value })} /></label>
          <div class="form-end"><button class="btn btn-primary">Create delegation</button></div>
        </form>
        {err && <p class="error">{err}</p>}
      </Card>
      <Card title={`Delegations (${list.length})`}>
        {list.length === 0 ? <p class="muted">None yet.</p> : (
          <div class="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Agent</th><th>Merchant</th><th>Limit</th><th>Spent</th><th>Expires</th><th>Status</th><th /></tr></thead>
              <tbody>
                {list.map((d) => {
                  const expired = Date.parse(d.claims.expires_at) <= now;
                  const state = d.revoked_at ? 'revoked' : expired ? 'expired' : 'active';
                  return (
                    <tr key={d.delegation_id}>
                      <td><Copy value={d.delegation_id} /></td>
                      <td class="mono small">{d.claims.subject_agent_id}</td>
                      <td>{d.claims.merchant_id}</td>
                      <td>{money(d.claims.max_amount_minor, d.claims.currency)}{d.claims.cumulative_limit_minor ? <span class="muted"> / {money(d.claims.cumulative_limit_minor)} total</span> : null}</td>
                      <td>{money(d.spent_minor, d.claims.currency)}</td>
                      <td class="small">{new Date(d.claims.expires_at).toLocaleTimeString()}</td>
                      <td><Tag tone={state === 'active' ? 'live' : 'warn'}>{state}</Tag></td>
                      <td>{state === 'active' && <button class="btn btn-small btn-danger" onClick={() => revoke(d.delegation_id)}>Revoke</button>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
