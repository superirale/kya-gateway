import { useEffect, useState } from 'preact/hooks';
import type { VerificationResponse } from '@kya/sdk';
import { merchant, useSession } from '../session';
import { Card, Copy, DecisionBadge, Tag, TelegraphEvidence, Timeline, money } from '../ui';

interface EvidenceBundle {
  evidence_id: string;
  evidence_hash: string;
  hash_matches: boolean;
  document: Record<string, unknown>;
  telegraph_record?: { result?: unknown; receipt?: unknown; result_hash?: string };
  labels: Record<string, string>;
}

export function Inspector({ selected, select }: { selected: string | null; select: (id: string) => void }) {
  const s = useSession();
  const [list, setList] = useState<VerificationResponse[]>([]);
  const [v, setV] = useState<VerificationResponse | null>(null);
  const [ev, setEv] = useState<EvidenceBundle | null>(null);

  useEffect(() => {
    merchant.kya<{ verifications: VerificationResponse[] }>('/verifications?limit=100').then((r) => {
      setList(r.verifications ?? []);
      if (!selected && r.verifications?.[0]) select(r.verifications[0].verification_id);
    }).catch(() => {});
  }, [s.version]);

  useEffect(() => {
    if (!selected) return;
    setV(null);
    setEv(null);
    merchant.kya<VerificationResponse>(`/verifications/${selected}`).then(setV).catch(() => {});
    merchant.kya<EvidenceBundle>(`/verifications/${selected}/evidence`).then(setEv).catch(() => {});
  }, [selected]);

  return (
    <div class="grid inspector">
      <Card title="Recent verifications" class="list-card">
        {list.length === 0 && <p class="muted">No verifications yet. Run a scenario.</p>}
        <ul class="ver-list">
          {list.map((x) => (
            <li key={x.verification_id}>
              <button class={`ver-item ${selected === x.verification_id ? 'active' : ''}`} onClick={() => select(x.verification_id)}>
                <DecisionBadge d={x.decision} />
                <span class="ver-main">
                  <span>{x.amount_minor != null ? money(x.amount_minor, x.currency) : ''} <span class="muted small">{x.agent_id}</span></span>
                  <span class="muted small">{x.reason_codes.filter((r) => !['AGENT_SIGNATURE_VALID', 'DELEGATION_VALID', 'NONCE_UNIQUE'].includes(r)).join(', ')}</span>
                </span>
                <span class="muted small">{new Date(x.created_at).toLocaleTimeString()}</span>
              </button>
            </li>
          ))}
        </ul>
      </Card>
      <div class="stack">
        {!v ? <Card><p class="muted">Select a verification.</p></Card> : (
          <>
            <Card title={<>Verification <DecisionBadge d={v.decision} large /></>} actions={<Tag>{v.policy_version}</Tag>}>
              <div class="codes">{v.reason_codes.map((c) => <code key={c}>{c}</code>)}</div>
              <ul class="explain">{v.explanation.map((e, i) => <li key={i}>{e}</li>)}</ul>
              <dl class="kv">
                <dt>Verification</dt><dd><Copy value={v.verification_id} label={v.verification_id} /></dd>
                <dt>Intent hash</dt><dd><Copy value={v.intent_hash} /></dd>
                <dt>Evidence hash</dt>
                <dd><Copy value={v.evidence_hash} /> {ev && (ev.hash_matches ? <Tag tone="live">recomputed ✓</Tag> : <Tag tone="warn">MISMATCH</Tag>)}</dd>
                <dt>Mode</dt><dd>{v.mode}</dd>
              </dl>
            </Card>
            <Card title="Timeline"><Timeline steps={v.trace ?? []} /></Card>
            <Card title="Telegraph evidence"><TelegraphEvidence v={v} /></Card>
            {ev?.telegraph_record?.result != null && (
              <Card title="Provider result (untrusted data)" actions={<Tag tone="warn">display only</Tag>}>
                <p class="muted small">Only the enum level and bounded numeric score feed the policy. Free text is never interpreted.</p>
                <pre class="code">{JSON.stringify(ev.telegraph_record.result, null, 2)}</pre>
              </Card>
            )}
            {ev && (
              <Card title="Hashed evidence document">
                <pre class="code">{JSON.stringify(ev.document, null, 2)}</pre>
              </Card>
            )}
          </>
        )}
      </div>
    </div>
  );
}
