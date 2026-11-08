import { useState } from 'preact/hooks';
import { SCENARIOS, runScenario, type ScenarioDef, type ScenarioId, type VerificationResponse } from '@kya/sdk';
import { kya, merchant, useSession } from '../session';
import { Card, DecisionBadge, Spinner, Tag } from '../ui';

interface RunState {
  running: boolean;
  log: string[];
  results: VerificationResponse[];
  error?: string;
}

export function Launcher({ inspect }: { inspect: (id: string) => void }) {
  const s = useSession();
  const [runs, setRuns] = useState<Record<string, RunState>>({});
  const simulated = s.status?.telegraph.simulated ?? true;

  const run = async (def: ScenarioDef) => {
    const update = (p: Partial<RunState>) => setRuns((r) => ({ ...r, [def.id]: { ...r[def.id], ...p } as RunState }));
    update({ running: true, log: [], results: [], error: undefined });
    const log: string[] = [];
    try {
      const [token, agent] = [await s.ensureToken(), await s.ensureAgent()];
      const out = await runScenario(
        { kya, merchant, merchantId: s.merchantId, consumerToken: token, agent, log: (m) => { log.push(m); update({ log: [...log] }); } },
        def.id as ScenarioId,
      );
      update({ results: out.checkouts.map((c) => c.verification as VerificationResponse).filter((v) => v.decision) });
    } catch (e) {
      update({ error: String(e) });
    } finally {
      update({ running: false });
      s.bump();
      s.refreshStatus();
    }
  };

  const runAll = async () => {
    for (const d of SCENARIOS) await run(d);
  };

  return (
    <div class="stack">
      <Card
        title="Demo scenarios"
        actions={<button class="btn" onClick={runAll} disabled={Object.values(runs).some((r) => r.running)}>Run all</button>}
      >
        <p class="muted">
          Each scenario uses the demo shopping agent registered in this browser, a delegation issued by the synthetic consumer, and the demo merchant agent.
          The merchant agent calls KYA automatically before a <strong>simulated</strong> checkout.
          {simulated
            ? ' Intelligence is SIMULATED in this deployment, so no Telegraph purchase occurs.'
            : ' Eligible requests buy real Telegraph testnet intelligence.'}
        </p>
      </Card>
      <div class="grid scenarios">
        {SCENARIOS.map((def) => {
          const r = runs[def.id];
          const last = r?.results.at(-1);
          const matched = last && last.decision === def.decision && last.reason_codes.includes(def.reason);
          return (
            <article class="card scenario" key={def.id}>
              <header class="row between">
                <h3>{def.title}</h3>
                <Tag tone={def.telegraph === 'no' ? 'neutral' : 'info'} title="Does this scenario reach the paid intelligence call?">
                  {def.telegraph === 'no' ? 'no spend' : def.telegraph === 'first-only' ? '1 paid call' : def.telegraph === 'attempt' ? 'attempted' : 'paid call'}
                </Tag>
              </header>
              <p class="muted small">{def.description}</p>
              <p class="small">Expect <code>{def.expect}</code></p>
              {def.simulatedOnly && !simulated && <p class="small warn-text">Live mode: outcome depends on the real provider response.</p>}
              <div class="row gap">
                <button class="btn btn-primary" onClick={() => run(def)} disabled={r?.running}>{r?.running ? <Spinner /> : 'Run'}</button>
                {r?.results.map((v) => (
                  <button class="btn btn-ghost" key={v.verification_id} onClick={() => inspect(v.verification_id)} title="Open in inspector">
                    <DecisionBadge d={v.decision} /> inspect
                  </button>
                ))}
                {last && <span class={matched ? 'ok-text small' : 'warn-text small'}>{matched ? 'as expected' : 'unexpected'}</span>}
              </div>
              {r?.log.length ? <ul class="log">{r.log.map((l, i) => <li key={i}>{l}</li>)}</ul> : null}
              {r?.error && <p class="error small">{r.error}</p>}
            </article>
          );
        })}
      </div>
    </div>
  );
}
