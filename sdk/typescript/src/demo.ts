/**
 * Demo helpers shared by the CLI shopping agent and the dashboard. They talk
 * to apps/merchant-demo (the merchant agent) and KYA public endpoints. Every
 * checkout here is SIMULATED; only the Telegraph purchase (in x402 mode) is real.
 */
import { KyaClient, KyaError } from './client.js';
import { AgentSigner, canonicalTimestamp, newId, newNonce } from './crypto.js';
import type { Decision, Delegation, SignedVerifyRequest, VerificationResponse } from './types.js';

export interface Quote {
  cart: unknown;
  cart_digest: string;
  amount_minor: number;
  currency: string;
  category: string;
  merchant_id: string;
}

export interface Order {
  order_id: string;
  status: 'SIMULATED_PAID' | 'HELD_FOR_REVIEW' | 'REJECTED';
  decision: string;
  verification_id: string;
  payment_note: string;
}

export interface CheckoutResult {
  httpStatus: number;
  verification: VerificationResponse | { error: { code: string; message: string } };
  order: Order | null;
}

export class DemoMerchantClient {
  constructor(readonly baseUrl: string, private readonly f: typeof fetch = globalThis.fetch.bind(globalThis)) {}

  private async json<T>(path: string, init?: RequestInit): Promise<{ status: number; body: T }> {
    const res = await this.f(this.baseUrl.replace(/\/$/, '') + path, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    });
    return { status: res.status, body: (await res.json()) as T };
  }

  async merchant() {
    return (await this.json<{ merchant_id: string; payment_mode: string }>('/api/merchant')).body;
  }

  async catalog() {
    return (await this.json<{ products: Array<{ sku: string; name: string; category: string; unit_price_minor: number; currency: string }> }>('/api/catalog')).body.products;
  }

  async quote(sku: string, quantity = 1): Promise<Quote> {
    const r = await this.json<Quote & { error?: { message: string } }>('/api/quote', { method: 'POST', body: JSON.stringify({ sku, quantity }) });
    if (r.status !== 200) throw new Error(r.body.error?.message ?? 'quote failed');
    return r.body;
  }

  async checkout(sku: string, quantity: number, signed: SignedVerifyRequest, simulate?: string): Promise<CheckoutResult> {
    const r = await this.json<any>('/api/checkout', {
      method: 'POST',
      body: JSON.stringify({ sku, quantity, signed_request: signed, simulate }),
    });
    if (r.body?.error) return { httpStatus: r.status, verification: r.body, order: null };
    return { httpStatus: r.status, verification: r.body.verification, order: r.body.order };
  }

  /** Read-only KYA evidence proxied by the merchant (merchant key stays server-side). */
  async kya<T = any>(path: string): Promise<T> {
    return (await this.json<T>('/api/kya' + path)).body;
  }
}

export type ScenarioId =
  | 'allow'
  | 'over_limit'
  | 'high_risk'
  | 'revoked'
  | 'replay'
  | 'tampered'
  | 'unavailable'
  | 'expired'
  | 'wrong_merchant';

export interface ScenarioDef {
  id: ScenarioId;
  title: string;
  description: string;
  expect: string;
  /** Expected decision/reason of the final checkout (local simulated mode). */
  decision: Decision;
  reason: string;
  telegraph: 'yes' | 'no' | 'first-only' | 'attempt';
  simulatedOnly?: boolean;
}

export const SCENARIOS: ScenarioDef[] = [
  { id: 'allow', title: 'Approved purchase', description: '$350 headphones under a $500 delegation.', expect: 'ALLOW', decision: 'ALLOW', reason: 'RISK_ACCEPTABLE', telegraph: 'yes' },
  { id: 'over_limit', title: 'Over budget', description: '$650 smartwatch under a $500 delegation.', expect: 'DENY · AMOUNT_EXCEEDS_DELEGATION', decision: 'DENY', reason: 'AMOUNT_EXCEEDS_DELEGATION', telegraph: 'no' },
  { id: 'high_risk', title: 'High-risk intelligence', description: 'Valid $350 request; risk intelligence returns HIGH.', expect: 'REVIEW · RISK_ELEVATED_REVIEW', decision: 'REVIEW', reason: 'RISK_ELEVATED_REVIEW', telegraph: 'yes', simulatedOnly: true },
  { id: 'revoked', title: 'Revoked delegation', description: 'Consumer revokes consent, then the agent buys.', expect: 'DENY · DELEGATION_REVOKED', decision: 'DENY', reason: 'DELEGATION_REVOKED', telegraph: 'no' },
  { id: 'replay', title: 'Nonce replay', description: 'The same signed intent is submitted twice.', expect: 'ALLOW, then DENY · NONCE_REPLAY', decision: 'DENY', reason: 'NONCE_REPLAY', telegraph: 'first-only' },
  { id: 'tampered', title: 'Tampered signature', description: 'Signature altered in transit.', expect: 'DENY · INVALID_AGENT_SIGNATURE', decision: 'DENY', reason: 'INVALID_AGENT_SIGNATURE', telegraph: 'no' },
  { id: 'unavailable', title: 'Provider unavailable', description: 'Telegraph request fails; KYA fails closed.', expect: 'REVIEW · RISK_INTELLIGENCE_UNAVAILABLE', decision: 'REVIEW', reason: 'RISK_INTELLIGENCE_UNAVAILABLE', telegraph: 'attempt', simulatedOnly: true },
  { id: 'expired', title: 'Expired delegation', description: 'Delegation with a 2-second lifetime is used after expiry.', expect: 'DENY · DELEGATION_EXPIRED', decision: 'DENY', reason: 'DELEGATION_EXPIRED', telegraph: 'no' },
  { id: 'wrong_merchant', title: 'Wrong merchant', description: 'Delegation scoped to another merchant.', expect: 'DENY · MERCHANT_NOT_ALLOWED', decision: 'DENY', reason: 'MERCHANT_NOT_ALLOWED', telegraph: 'no' },
];

export interface DemoContext {
  kya: KyaClient;
  merchant: DemoMerchantClient;
  merchantId: string;
  consumerToken: string;
  agent: AgentSigner;
  log?: (msg: string) => void;
}

export interface ScenarioRun {
  scenario: ScenarioId;
  delegation?: Delegation;
  signed?: SignedVerifyRequest;
  checkouts: CheckoutResult[];
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Register a fresh demo agent (synthetic identity) with proof of possession. */
export async function createDemoAgent(kya: KyaClient, label = 'demo shopping agent'): Promise<AgentSigner> {
  const signer = await AgentSigner.generate('agent_' + newNonce().toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10));
  await kya.registerAgent(signer, label);
  return signer;
}

export async function signForQuote(ctx: DemoContext, delegationId: string, q: Quote): Promise<SignedVerifyRequest> {
  return ctx.agent.signIntent({
    merchantId: q.merchant_id,
    delegationId,
    intent: {
      intent_id: newId('pi_'),
      action: 'purchase',
      amount_minor: q.amount_minor,
      currency: q.currency,
      cart_digest: q.cart_digest,
      category: q.category,
      timestamp: canonicalTimestamp(),
      nonce: newNonce(),
    },
  });
}

export async function runScenario(ctx: DemoContext, id: ScenarioId): Promise<ScenarioRun> {
  const log = ctx.log ?? (() => {});
  const run: ScenarioRun = { scenario: id, checkouts: [] };
  const delegate = async (opts: { merchantId?: string; ttl?: number } = {}) => {
    const d = await ctx.kya.createDelegation(ctx.consumerToken, {
      agent_id: ctx.agent.agentId,
      merchant_id: opts.merchantId ?? ctx.merchantId,
      actions: ['purchase'],
      max_amount_minor: 50000,
      currency: 'USD',
      expires_in_seconds: opts.ttl ?? 1800,
    });
    log(`Consumer delegated purchase ≤ $500.00 to ${ctx.agent.agentId} at ${d.claims.merchant_id} until ${d.claims.expires_at} (${d.delegation_id})`);
    run.delegation = d;
    return d;
  };
  const buy = async (sku: string, simulate?: string, mutate?: (s: SignedVerifyRequest) => SignedVerifyRequest) => {
    const q = await ctx.merchant.quote(sku);
    let signed = await signForQuote(ctx, run.delegation!.delegation_id, q);
    log(`Agent signed ${q.currency} ${(q.amount_minor / 100).toFixed(2)} intent ${signed.intent.intent_id} (nonce ${signed.intent.nonce.slice(0, 8)}…)`);
    if (mutate) signed = mutate(signed);
    run.signed = signed;
    return submit(sku, signed, simulate);
  };
  const submit = async (sku: string, signed: SignedVerifyRequest, simulate?: string) => {
    const res = await ctx.merchant.checkout(sku, 1, signed, simulate);
    run.checkouts.push(res);
    const v = res.verification as VerificationResponse;
    log(v.decision ? `Merchant → KYA: ${v.decision} [${v.reason_codes.join(', ')}] · order ${res.order?.status ?? '—'}` : `Rejected: ${JSON.stringify(res.verification)}`);
    return res;
  };

  try {
    switch (id) {
      case 'allow':
        await delegate();
        await buy('sku_headphones_nc');
        break;
      case 'over_limit':
        await delegate();
        await buy('sku_smartwatch_pro');
        break;
      case 'high_risk':
        await delegate();
        await buy('sku_headphones_nc', 'high_risk');
        break;
      case 'unavailable':
        await delegate();
        await buy('sku_headphones_nc', 'unavailable');
        break;
      case 'revoked': {
        const d = await delegate();
        await ctx.kya.revokeDelegation(ctx.consumerToken, d.delegation_id);
        log('Consumer revoked the delegation');
        await buy('sku_headphones_nc');
        break;
      }
      case 'replay': {
        await delegate();
        await buy('sku_headphones_nc');
        log('Attacker replays the identical signed request');
        await submit('sku_headphones_nc', run.signed!);
        break;
      }
      case 'tampered':
        await delegate();
        await buy('sku_headphones_nc', undefined, (s) => {
          const c = s.signature[10] === 'A' ? 'B' : 'A';
          return { ...s, signature: s.signature.slice(0, 10) + c + s.signature.slice(11) };
        });
        break;
      case 'expired':
        await delegate({ ttl: 2 });
        log('Waiting 3s for the delegation to expire…');
        await sleep(3000);
        await buy('sku_headphones_nc');
        break;
      case 'wrong_merchant':
        await delegate({ merchantId: 'merchant_other_store' });
        await buy('sku_headphones_nc');
        break;
    }
  } catch (e) {
    log(`Error: ${e instanceof KyaError ? e.message : String(e)}`);
    throw e;
  }
  return run;
}
