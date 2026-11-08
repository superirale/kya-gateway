import { AgentSigner } from './crypto.js';
import type {
  Agent,
  Challenge,
  Delegation,
  DelegationRequest,
  SignedVerifyRequest,
  VerificationResponse,
} from './types.js';

export class KyaError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly body?: unknown,
  ) {
    super(`${code}: ${message}`);
  }
}

type Fetch = typeof fetch;

async function request<T>(f: Fetch, url: string, init: RequestInit & { token?: string; okStatuses?: number[] } = {}): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...(init.headers as Record<string, string>) };
  if (init.token) headers.Authorization = `Bearer ${init.token}`;
  const res = await f(url, { ...init, headers });
  const text = await res.text();
  const body = text ? JSON.parse(text) : undefined;
  if (!res.ok && !(init.okStatuses ?? []).includes(res.status)) {
    const e = body?.error ?? {};
    throw new KyaError(res.status, e.code ?? 'HTTP_ERROR', e.message ?? res.statusText, body);
  }
  return body as T;
}

/** Public + consumer endpoints (safe for browsers and agents). */
export class KyaClient {
  constructor(
    readonly baseUrl: string,
    private readonly f: Fetch = globalThis.fetch.bind(globalThis),
  ) {}

  private url(p: string) {
    return this.baseUrl.replace(/\/$/, '') + p;
  }

  status() {
    return request<Record<string, any>>(this.f, this.url('/v1/public/status'));
  }

  challenge(agentId: string, purpose: 'register' | 'rotate' = 'register') {
    return request<Challenge>(this.f, this.url('/v1/agents/challenge'), {
      method: 'POST',
      body: JSON.stringify({ agent_id: agentId, purpose }),
    });
  }

  getAgent(agentId: string) {
    return request<Agent>(this.f, this.url(`/v1/agents/${encodeURIComponent(agentId)}`));
  }

  /** Proof-of-possession registration: fetch challenge, sign it, register. */
  async registerAgent(signer: AgentSigner, developerLabel: string): Promise<Agent> {
    const ch = await this.challenge(signer.agentId, 'register');
    return request<Agent>(this.f, this.url('/v1/agents/register'), {
      method: 'POST',
      body: JSON.stringify({
        agent_id: signer.agentId,
        developer_label: developerLabel,
        public_key: signer.publicKeyB64,
        challenge_id: ch.challenge_id,
        signed_challenge: await signer.signChallenge(ch),
      }),
    });
  }

  /** Rotate to `next`; both the current and new keys sign the rotation. */
  async rotateKey(current: AgentSigner, next: AgentSigner): Promise<Agent> {
    const agent = await this.getAgent(current.agentId);
    const ch = await this.challenge(current.agentId, 'rotate');
    const msg = AgentSigner.rotationMessage(current.agentId, ch, agent.key_version, next.publicKeyB64);
    return request<Agent>(this.f, this.url(`/v1/agents/${encodeURIComponent(current.agentId)}/rotate-key`), {
      method: 'POST',
      body: JSON.stringify({
        new_public_key: next.publicKeyB64,
        challenge_id: ch.challenge_id,
        old_key_signature: await current.sign(msg),
        new_key_signature: await next.sign(msg),
      }),
    });
  }

  /** Demo consumer login (synthetic account, not identity proofing). */
  login(username: string, password: string) {
    return request<{ token: string; expires_at: string; consumer_ref: string }>(this.f, this.url('/v1/consumers/login'), {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  }

  createDelegation(consumerToken: string, req: DelegationRequest) {
    return request<Delegation>(this.f, this.url('/v1/delegations'), {
      method: 'POST',
      token: consumerToken,
      body: JSON.stringify(req),
    });
  }

  listDelegations(consumerToken: string) {
    return request<{ delegations: Delegation[] }>(this.f, this.url('/v1/delegations'), { token: consumerToken });
  }

  revokeDelegation(consumerToken: string, delegationId: string) {
    return request<Delegation>(this.f, this.url(`/v1/delegations/${encodeURIComponent(delegationId)}/revoke`), {
      method: 'POST',
      token: consumerToken,
    });
  }
}

/**
 * Merchant-side client. Holds the merchant API key: use it on a server,
 * never in a browser.
 */
export class KyaMerchantClient {
  constructor(
    readonly baseUrl: string,
    private readonly apiKey: string,
    private readonly f: Fetch = globalThis.fetch.bind(globalThis),
  ) {}

  private url(p: string) {
    return this.baseUrl.replace(/\/$/, '') + p;
  }

  /**
   * Verify a signed purchase intent. Authorization denials (including a
   * replayed nonce, HTTP 409) resolve with decision DENY rather than throwing.
   */
  verify(req: SignedVerifyRequest, opts: { simulate?: string } = {}) {
    return request<VerificationResponse>(this.f, this.url('/v1/verify-transactions'), {
      method: 'POST',
      token: this.apiKey,
      body: JSON.stringify(req),
      headers: opts.simulate ? { 'X-KYA-Simulate': opts.simulate } : {},
      okStatuses: [409],
    });
  }

  getVerification(id: string) {
    return request<VerificationResponse>(this.f, this.url(`/v1/verifications/${encodeURIComponent(id)}`), { token: this.apiKey });
  }

  getEvidence(id: string) {
    return request<Record<string, unknown>>(this.f, this.url(`/v1/verifications/${encodeURIComponent(id)}/evidence`), { token: this.apiKey });
  }

  listVerifications(limit = 50) {
    return request<{ verifications: VerificationResponse[] }>(this.f, this.url(`/v1/verifications?limit=${limit}`), { token: this.apiKey });
  }
}
