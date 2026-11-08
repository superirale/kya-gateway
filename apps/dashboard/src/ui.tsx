import type { ComponentChildren } from 'preact';
import type { Decision, TraceStep, VerificationResponse } from '@kya/sdk';

export const money = (minor: number, currency = 'USD') =>
  new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(minor / 100);

export const usdc = (micro: number) => `${(micro / 1e6).toFixed(micro % 1000 === 0 ? 3 : 6)} USDC`;

export const short = (s: string | null | undefined, n = 10) => (!s ? '—' : s.length > n * 2 + 1 ? `${s.slice(0, n)}…${s.slice(-6)}` : s);

export function DecisionBadge({ d, large }: { d: Decision | string; large?: boolean }) {
  return <span class={`badge decision-${String(d).toLowerCase()}${large ? ' badge-lg' : ''}`}>{d}</span>;
}

export function Tag({ children, tone = 'neutral', title }: { children: ComponentChildren; tone?: 'neutral' | 'warn' | 'live' | 'info'; title?: string }) {
  return <span class={`tag tag-${tone}`} title={title}>{children}</span>;
}

export function Card({ title, children, actions, class: cls }: { title?: ComponentChildren; children: ComponentChildren; actions?: ComponentChildren; class?: string }) {
  return (
    <section class={`card ${cls ?? ''}`}>
      {(title || actions) && (
        <header class="card-head">
          {title && <h2>{title}</h2>}
          {actions && <div class="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Copy({ value, label }: { value: string | null | undefined; label?: string }) {
  if (!value) return <span class="muted">—</span>;
  return (
    <code class="mono copy" title={`${value}\n(click to copy)`} onClick={() => navigator.clipboard?.writeText(value).catch(() => {})}>
      {label ?? short(value, 12)}
    </code>
  );
}

const STEP_LABEL: Record<string, string> = {
  agent_signature: 'Agent signature',
  nonce: 'Nonce uniqueness',
  intent_timestamp: 'Timestamp window',
  delegation: 'Delegation',
  spend_reservation: 'Spend reservation',
  telegraph_purchase: 'Telegraph purchase',
  receipt_verification: 'Receipt verification',
  policy_decision: 'Policy decision',
};

const STEP_ICON: Record<TraceStep['status'], string> = { pass: '✓', fail: '✕', warn: '!', skipped: '–' };

export function Timeline({ steps }: { steps: TraceStep[] }) {
  return (
    <ol class="timeline">
      {steps.map((s) => (
        <li class={`step step-${s.status}`} key={s.step}>
          <span class="step-dot" aria-label={s.status}>{STEP_ICON[s.status]}</span>
          <div class="step-body">
            <div class="step-title">
              {STEP_LABEL[s.step] ?? s.step}
              {s.reason && <code class="reason">{s.reason}</code>}
              {s.status !== 'skipped' && <span class="muted step-ms">{s.duration_ms} ms</span>}
            </div>
            {s.detail && <div class="step-detail">{s.detail}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}

export function TelegraphEvidence({ v }: { v: VerificationResponse }) {
  const t = v.telegraph;
  if (!t) {
    return <p class="muted">No intelligence purchased: the request was denied by local checks before any paid call.</p>;
  }
  return (
    <div>
      <div class="row gap wrap">
        {t.simulated ? <Tag tone="warn">SIMULATED · no network purchase</Tag> : <Tag tone="live">REAL · {t.network}</Tag>}
        <Tag tone={t.settlement_status === 'SETTLED' ? 'live' : t.settlement_status === 'FAILED' ? 'warn' : 'info'}>{t.settlement_status}</Tag>
        {t.error_code && <Tag tone="warn">{t.error_code}</Tag>}
      </div>
      <dl class="kv">
        <dt>Intent</dt><dd><code>{t.intent}</code></dd>
        <dt>Request (signal hash)</dt><dd><Copy value={t.request_id} /></dd>
        <dt>Receipt</dt><dd><Copy value={t.receipt_id} /></dd>
        <dt>Transaction</dt>
        <dd>
          {t.tx_hash ? (
            <>
              <Copy value={t.tx_hash} /> {t.explorer_url && <a href={t.explorer_url} target="_blank" rel="noreferrer noopener">explorer ↗</a>}
            </>
          ) : <span class="muted">— not provided</span>}
        </dd>
        <dt>Provider</dt><dd>{t.provider_id ?? <span class="muted">—</span>}</dd>
        <dt>Observed cost</dt><dd>{t.observed_cost ? usdc(t.observed_cost.amount_minor) : <span class="muted">n/a</span>}</dd>
        <dt>Risk output</dt>
        <dd>{t.risk_level ?? '—'}{t.risk_score != null && <span class="muted"> · score {t.risk_score.toFixed(3)}</span>}</dd>
        <dt>Latency</dt><dd>{t.latency_ms != null ? `${t.latency_ms} ms` : '—'}</dd>
        {t.verification_note && (<><dt>Verification</dt><dd class="small">{t.verification_note}</dd></>)}
      </dl>
    </div>
  );
}

export function Spinner() {
  return <span class="spinner" aria-label="loading" />;
}
