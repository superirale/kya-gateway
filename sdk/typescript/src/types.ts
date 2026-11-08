export type Decision = 'ALLOW' | 'REVIEW' | 'DENY';
export type EvidenceState = 'REQUESTED' | 'SETTLED' | 'FAILED' | 'UNVERIFIED';

export interface Challenge {
  challenge_id: string;
  challenge: string;
  purpose: 'register' | 'rotate';
  expires_at: string;
}

export interface Agent {
  agent_id: string;
  developer_label: string;
  status: 'active' | 'disabled';
  key_version: number;
  public_key: string;
  key_fingerprint: string;
  created_at: string;
  identity_note: string;
}

export interface PurchaseIntent {
  intent_id: string;
  action: string;
  amount_minor: number;
  currency: string;
  cart_digest: string;
  category?: string;
  timestamp: string;
  nonce: string;
}

export interface SignedIntentPayload {
  agent_id: string;
  merchant_id: string;
  delegation_id: string;
  intent: PurchaseIntent;
}

export interface SignedVerifyRequest extends SignedIntentPayload {
  signature: string;
}

export interface DelegationRequest {
  agent_id: string;
  merchant_id: string;
  actions: string[];
  max_amount_minor: number;
  cumulative_limit_minor?: number;
  categories?: string[];
  currency: string;
  expires_at?: string;
  expires_in_seconds?: number;
}

export interface DelegationClaims {
  delegation_id: string;
  subject_agent_id: string;
  merchant_id: string;
  actions: string[];
  max_amount_minor: number;
  cumulative_limit_minor?: number;
  categories?: string[];
  currency: string;
  issued_at: string;
  expires_at: string;
  issuer: string;
  audience: string;
  consumer_ref: string;
  kid: string;
}

export interface Delegation {
  delegation_id: string;
  claims: DelegationClaims;
  signed_payload: unknown;
  signature: string;
  revoked_at: string | null;
  spent_minor: number;
}

export interface TraceStep {
  step: string;
  status: 'pass' | 'fail' | 'warn' | 'skipped';
  reason?: string;
  detail?: string;
  duration_ms: number;
}

export interface TelegraphSummary {
  network: string;
  intent: string;
  simulated: boolean;
  settlement_status: EvidenceState;
  request_id: string | null;
  receipt_id: string | null;
  tx_hash: string | null;
  explorer_url: string | null;
  provider_id: string | null;
  observed_cost: { amount_minor: number; currency: string; decimals: number } | null;
  latency_ms: number | null;
  error_code: string | null;
  risk_level: string | null;
  risk_score: number | null;
  verification_note?: string;
}

export interface VerificationResponse {
  verification_id: string;
  decision: Decision;
  reason_codes: string[];
  explanation: string[];
  policy_version: string;
  evidence_id: string;
  evidence_hash: string;
  intent_hash: string;
  telegraph_called: boolean;
  trace?: TraceStep[];
  mode: string;
  created_at: string;
  telegraph: TelegraphSummary | null;
  agent_id?: string;
  amount_minor?: number;
  currency?: string;
  intent_id?: string;
}

export interface KyaErrorBody {
  error: { code: string; message: string };
}
