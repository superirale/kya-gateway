/**
 * Canonical JSON identical to KYA's Go implementation (internal/canonical):
 * sorted keys, no whitespace, minimal string escaping, integers only
 * (|n| <= 2^53-1). Keys whose value is `undefined` are omitted.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) {
        throw new Error(`canonical: only safe integers are allowed, got ${value}`);
      }
      return Object.is(value, -0) ? '0' : String(value);
    case 'string':
      return encodeString(value);
    case 'object': {
      if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return '{' + keys.map((k) => encodeString(k) + ':' + canonicalize(obj[k])).join(',') + '}';
    }
    default:
      throw new Error(`canonical: unsupported type ${typeof value}`);
  }
}

function encodeString(s: string): string {
  if (!s.isWellFormed()) throw new Error('canonical: string contains lone surrogates');
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    switch (ch) {
      case '"': out += '\\"'; break;
      case '\\': out += '\\\\'; break;
      case '\b': out += '\\b'; break;
      case '\f': out += '\\f'; break;
      case '\n': out += '\\n'; break;
      case '\r': out += '\\r'; break;
      case '\t': out += '\\t'; break;
      default:
        out += c < 0x20 ? '\\u' + c.toString(16).padStart(4, '0') : ch;
    }
  }
  return out + '"';
}

export const Domains = {
  agentChallenge: 'KYA-AGENT-CHALLENGE-V1',
  agentRotate: 'KYA-AGENT-ROTATE-V1',
  delegation: 'KYA-DELEGATION-V1',
  purchaseIntent: 'KYA-PURCHASE-INTENT-V1',
} as const;

/** "<domain>\n" + canonical(payload), as UTF-8 bytes. */
export function signingMessage(domain: string, payload: unknown): Uint8Array {
  return new TextEncoder().encode(domain + '\n' + canonicalize(payload));
}
