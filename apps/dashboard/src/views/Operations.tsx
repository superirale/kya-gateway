import { useEffect, useState } from 'preact/hooks';
import { merchant, useSession } from '../session';
import { Card, DecisionBadge, Tag, money, usdc } from '../ui';

interface Stats {
  total: number;
  by_decision: Record<string, number>;
  by_reason: Record<string, number>;
  telegraph_calls: number;
  telegraph_errors: number;
  telegraph_settled: number;
  telegraph_spend_minor: number;
  rejected_before_spend: number;
  avg_telegraph_latency_ms: number;
}

interface Order { order_id: string; status: string; decision: string; agent_id: string; cart: { total_minor: number; currency: string }; created_at: string }

export function Operations() {
  const s = useSession();
  const [st, setSt] = useState<Stats | null>(null);
  const [audit, setAudit] = useState<{ events: number; intact: boolean; head_hash?: string; first_broken_seq?: number } | null>(null);
  const [orders, setOrders] = useState<Order[]>([]);

  useEffect(() => {
    merchant.kya<Stats>('/stats').then(setSt).catch(() => {});
    merchant.kya<typeof audit>('/audit/verify').then(setAudit).catch(() => {});
    fetch((import.meta.env.VITE_MERCHANT_URL ?? '/merchant') + '/api/orders').then((r) => r.json()).then((r) => setOrders(r.orders ?? [])).catch(() => {});
  }, [s.version]);

  const spend = s.status?.spend;
  const reasons = Object.entries(st?.by_reason ?? {})
    .filter(([r]) => !['AGENT_SIGNATURE_VALID', 'DELEGATION_VALID', 'NONCE_UNIQUE'].includes(r))
    .sort((a, b) => b[1] - a[1]);
  const maxReason = Math.max(1, ...reasons.map(([, n]) => n));
  const pctBefore = st && st.total ? Math.round((st.rejected_before_spend / st.total) * 100) : 0;

  return (
    <div class="stack">
      <div class="tiles">
        <div class="tile"><span class="tile-label">Verifications</span><span class="tile-value">{st?.total ?? '—'}</span></div>
        {(['ALLOW', 'REVIEW', 'DENY'] as const).map((d) => (
          <div class="tile" key={d}><span class="tile-label"><DecisionBadge d={d} /></span><span class="tile-value">{st?.by_decision[d] ?? 0}</span></div>
        ))}
        <div class="tile"><span class="tile-label">Denied before spend</span><span class="tile-value">{st?.rejected_before_spend ?? 0}<small> · {pctBefore}%</small></span></div>
        <div class="tile"><span class="tile-label">Telegraph calls</span><span class="tile-value">{st?.telegraph_calls ?? 0}<small> · {st?.telegraph_errors ?? 0} err</small></span></div>
        <div class="tile"><span class="tile-label">Settled + verified</span><span class="tile-value">{st?.telegraph_settled ?? 0}</span></div>
        <div class="tile"><span class="tile-label">Avg intel latency</span><span class="tile-value">{st ? Math.round(st.avg_telegraph_latency_ms) : '—'}<small> ms</small></span></div>
      </div>
      <div class="grid two">
        <Card title="Telegraph spend">
          {s.status?.telegraph.simulated ? (
            <p class="muted">Simulated adapter: no network spend. <Tag tone="warn">SIMULATED</Tag></p>
          ) : (
            <>
              <p class="tile-value">{usdc(st?.telegraph_spend_minor ?? 0)}</p>
              {spend && (
                <>
                  <div class="meter" role="meter" aria-valuenow={spend.spent_today_minor} aria-valuemax={spend.daily_cap_minor}>
                    <span style={{ width: `${Math.min(100, (spend.spent_today_minor / spend.daily_cap_minor) * 100)}%` }} />
                  </div>
                  <p class="muted small">Today {usdc(spend.spent_today_minor)} of {usdc(spend.daily_cap_minor)} daily cap · per-call cap {usdc(s.status!.telegraph.max_price_minor)}</p>
                </>
              )}
            </>
          )}
        </Card>
        <Card title="Audit hash chain">
          {audit ? (
            <>
              <p>{audit.intact ? <Tag tone="live">intact</Tag> : <Tag tone="warn">broken at seq {audit.first_broken_seq}</Tag>} <span class="muted">{audit.events} events</span></p>
              {audit.head_hash && <p class="mono small break">{audit.head_hash}</p>}
              <p class="muted small">Tamper-evident (append-only + hash chain), not a guarantee of immutability.</p>
            </>
          ) : <p class="muted">—</p>}
        </Card>
      </div>
      <div class="grid two">
        <Card title="Decision reasons">
          {reasons.length === 0 ? <p class="muted">No data yet.</p> : (
            <ul class="bars">
              {reasons.map(([r, n]) => (
                <li key={r}><code>{r}</code><span class="bar"><span style={{ width: `${(n / maxReason) * 100}%` }} /></span><span class="bar-n">{n}</span></li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Recent merchant orders" actions={<Tag tone="warn">SIMULATED</Tag>}>
          {orders.length === 0 ? <p class="muted">No orders yet.</p> : (
            <div class="table-wrap">
              <table>
                <thead><tr><th>Order</th><th>Amount</th><th>Decision</th><th>Status</th></tr></thead>
                <tbody>
                  {orders.slice(0, 12).map((o) => (
                    <tr key={o.order_id}><td class="mono small">{o.order_id.slice(0, 12)}…</td><td>{money(o.cart.total_minor, o.cart.currency)}</td><td><DecisionBadge d={o.decision} /></td><td class="small">{o.status}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
