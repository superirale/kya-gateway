/**
 * KYA demo shopping agent (CLI).
 *
 *   npm run agent -- allow over_limit replay     # run selected scenarios
 *   npm run agent -- all                         # run every scenario
 *
 * Env: KYA_URL (default http://localhost:8080), MERCHANT_URL (default
 * http://localhost:8081), CONSUMER_USER / CONSUMER_PASS (demo account).
 * Merchandise payment is SIMULATED. In x402 mode the Telegraph purchase is real.
 */
import { DemoMerchantClient, KyaClient, SCENARIOS, createDemoAgent, runScenario, type ScenarioId, type VerificationResponse } from '@kya/sdk';

const KYA_URL = process.env.KYA_URL ?? 'http://localhost:8080';
const MERCHANT_URL = process.env.MERCHANT_URL ?? 'http://localhost:8081';

const color = (c: number) => (s: string) => (process.stdout.isTTY ? `\x1b[${c}m${s}\x1b[0m` : s);
const green = color(32), red = color(31), yellow = color(33), dim = color(2), bold = color(1);
const paint = (d: string) => (d === 'ALLOW' ? green(d) : d === 'DENY' ? red(d) : yellow(d));

async function main() {
  const args = process.argv.slice(2);
  const ids = (args.length === 0 || args.includes('all') ? SCENARIOS.map((s) => s.id) : args) as ScenarioId[];
  for (const id of ids) {
    if (!SCENARIOS.some((s) => s.id === id)) throw new Error(`unknown scenario ${id}; choose from ${SCENARIOS.map((s) => s.id).join(', ')}`);
  }

  const kya = new KyaClient(KYA_URL);
  const merchant = new DemoMerchantClient(MERCHANT_URL);
  const status = await kya.status();
  const tg = status.telegraph;
  console.log(bold('KYA Gateway demo shopping agent'));
  console.log(dim(`mode=${status.mode} policy=${status.policy_version} intelligence=${tg.adapter} intent=${tg.intent} network=${tg.network}${tg.simulated ? ' (SIMULATED, no network purchase)' : ''}`));
  console.log(dim('Merchandise checkout is SIMULATED. Consumers and agents are synthetic.\n'));

  const { merchant_id } = await merchant.merchant();
  const login = await kya.login(process.env.CONSUMER_USER ?? 'alice', process.env.CONSUMER_PASS ?? 'alice-demo-pass');
  const agent = await createDemoAgent(kya, 'cli shopping agent');
  console.log(`Registered agent ${bold(agent.agentId)} (public key ${agent.publicKeyB64.slice(0, 12)}…) via signed challenge\n`);

  let failures = 0;
  for (const id of ids) {
    const def = SCENARIOS.find((s) => s.id === id)!;
    console.log(bold(`▶ ${def.title}`) + dim(` — expect ${def.expect}`));
    if (def.simulatedOnly && !tg.simulated) console.log(dim('  (live intelligence: outcome depends on the real provider result)'));
    const run = await runScenario(
      { kya, merchant, merchantId: merchant_id, consumerToken: login.token, agent, log: (m) => console.log(dim('  · ' + m)) },
      id,
    );
    for (const c of run.checkouts) {
      const v = c.verification as VerificationResponse;
      if (!v.decision) {
        console.log(red(`  ✗ request rejected (${c.httpStatus})`));
        failures++;
        continue;
      }
      console.log(`  ${paint(v.decision)} ${v.reason_codes.join(', ')}  ${dim(v.verification_id)}`);
      const t = v.telegraph;
      if (t) {
        const cost = t.observed_cost ? `${t.observed_cost.amount_minor / 10 ** t.observed_cost.decimals} ${t.observed_cost.currency}` : 'n/a';
        console.log(dim(`    telegraph: ${t.intent} on ${t.network} · ${t.settlement_status}${t.simulated ? ' · SIMULATED' : ''} · request ${t.request_id ?? '—'} · cost ${cost}`));
        if (t.explorer_url) console.log(dim(`    tx: ${t.explorer_url}`));
      } else {
        console.log(dim('    telegraph: not called (denied before any intelligence spend)'));
      }
    }
    const last = run.checkouts.at(-1)?.verification as VerificationResponse | undefined;
    const matched = last?.decision === def.decision && last.reason_codes.includes(def.reason);
    if (!matched && !(def.simulatedOnly && !tg.simulated)) {
      console.log(red(`  ✗ expected ${def.decision} ${def.reason}`));
      failures++;
    }
    console.log();
  }
  if (failures) {
    console.log(red(`${failures} scenario(s) did not match expectations`));
    process.exit(1);
  }
  console.log(green('All scenarios matched expectations.'));
}

main().catch((e) => {
  console.error(red(String(e?.stack ?? e)));
  process.exit(1);
});
