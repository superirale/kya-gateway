import * as ed from '@noble/ed25519';
import { Domains, canonicalize, signingMessage } from './canonical.js';
import type { Challenge, PurchaseIntent, SignedIntentPayload, SignedVerifyRequest } from './types.js';

export function b64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64url(s: string): Uint8Array {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** 128-bit random base64url nonce (22 chars). */
export const newNonce = (): string => b64url(randomBytes(16));
export const newId = (prefix: string): string => prefix + b64url(randomBytes(12));

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** sha256:<hex> of canonical JSON, the format KYA expects for cart_digest. */
export async function cartDigest(cart: unknown): Promise<string> {
  return 'sha256:' + (await sha256Hex(canonicalize(cart)));
}

/** RFC 3339 UTC timestamp without fractional seconds (KYA's canonical form). */
export function canonicalTimestamp(d = new Date()): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Holds an agent's Ed25519 secret key. The key never leaves this object;
 * KYA only ever receives the public key and signatures.
 */
export class AgentSigner {
  private constructor(
    readonly agentId: string,
    private readonly secretKey: Uint8Array,
    readonly publicKey: Uint8Array,
  ) {}

  static async generate(agentId: string): Promise<AgentSigner> {
    return AgentSigner.fromSecretKey(agentId, ed.utils.randomSecretKey());
  }

  static async fromSecretKey(agentId: string, secretKey: Uint8Array): Promise<AgentSigner> {
    return new AgentSigner(agentId, secretKey, await ed.getPublicKeyAsync(secretKey));
  }

  get publicKeyB64(): string {
    return b64url(this.publicKey);
  }

  /** Export for persistence by the agent operator (handle as a secret). */
  exportSecretKey(): string {
    return b64url(this.secretKey);
  }

  async sign(msg: Uint8Array): Promise<string> {
    return b64url(await ed.signAsync(msg, this.secretKey));
  }

  async signChallenge(ch: Challenge): Promise<string> {
    return this.sign(
      signingMessage(Domains.agentChallenge, {
        agent_id: this.agentId,
        challenge_id: ch.challenge_id,
        challenge: ch.challenge,
        public_key: this.publicKeyB64,
      }),
    );
  }

  /** Rotation must be signed by both the current and the new key. */
  static rotationMessage(agentId: string, ch: Challenge, oldKeyVersion: number, newPublicKeyB64: string): Uint8Array {
    return signingMessage(Domains.agentRotate, {
      agent_id: agentId,
      challenge_id: ch.challenge_id,
      challenge: ch.challenge,
      old_key_version: oldKeyVersion,
      new_public_key: newPublicKeyB64,
    });
  }

  async signIntent(args: { merchantId: string; delegationId: string; intent: PurchaseIntent }): Promise<SignedVerifyRequest> {
    const intent: PurchaseIntent = { ...args.intent };
    if (!intent.category) delete intent.category; // Go omits empty category
    const payload: SignedIntentPayload = {
      agent_id: this.agentId,
      merchant_id: args.merchantId,
      delegation_id: args.delegationId,
      intent,
    };
    const signature = await this.sign(signingMessage(Domains.purchaseIntent, payload));
    return { ...payload, signature };
  }
}

export async function verifySignature(publicKeyB64: string, msg: Uint8Array, sigB64: string): Promise<boolean> {
  try {
    return await ed.verifyAsync(fromB64url(sigB64), msg, fromB64url(publicKeyB64));
  } catch {
    return false;
  }
}
