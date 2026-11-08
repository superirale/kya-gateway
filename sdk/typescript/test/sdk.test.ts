import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  AgentSigner,
  Domains,
  canonicalTimestamp,
  canonicalize,
  cartDigest,
  fromB64url,
  signingMessage,
  verifySignature,
} from '../src/index.js';

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../../testdata/signing-vectors.json', import.meta.url)), 'utf8'),
);

test('canonical JSON matches the Go implementation byte-for-byte', () => {
  assert.equal(canonicalize(vectors.canonical_input), vectors.canonical_output);
});

test('cart digest matches Go merchant', async () => {
  assert.equal(await cartDigest(vectors.cart), vectors.cart_digest);
});

test('intent signature matches Go (Ed25519 is deterministic)', async () => {
  const signer = await AgentSigner.fromSecretKey(vectors.intent.agent_id, fromB64url(vectors.secret_key_seed));
  assert.equal(signer.publicKeyB64, vectors.public_key);
  const msg = new TextDecoder().decode(signingMessage(Domains.purchaseIntent, vectors.intent));
  assert.equal(msg, vectors.intent_message);
  const signed = await signer.signIntent({
    merchantId: vectors.intent.merchant_id,
    delegationId: vectors.intent.delegation_id,
    intent: vectors.intent.intent,
  });
  assert.equal(signed.signature, vectors.intent_signature);
  assert.ok(await verifySignature(vectors.public_key, signingMessage(Domains.purchaseIntent, vectors.intent), signed.signature));
});

test('rejects non-integer and unsafe numbers', () => {
  assert.throws(() => canonicalize({ amount: 1.5 }));
  assert.throws(() => canonicalize({ amount: 2 ** 53 }));
  assert.equal(canonicalize({ a: undefined, b: -0 }), '{"b":0}');
});

test('empty category is omitted like Go omitempty', async () => {
  const signer = await AgentSigner.generate('agent_x');
  const s = await signer.signIntent({
    merchantId: 'm',
    delegationId: 'd',
    intent: { intent_id: 'i', action: 'purchase', amount_minor: 1, currency: 'USD', cart_digest: 'x', category: '', timestamp: 't', nonce: 'n' },
  });
  assert.ok(!('category' in s.intent));
});

test('canonical timestamp has no fractional seconds', () => {
  assert.equal(canonicalTimestamp(new Date('2026-11-08T15:00:00.123Z')), '2026-11-08T15:00:00Z');
});
