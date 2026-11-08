import { createContext, type ComponentChildren } from 'preact';
import { useCallback, useContext, useEffect, useState } from 'preact/hooks';
import { AgentSigner, DemoMerchantClient, KyaClient, createDemoAgent, fromB64url } from '@kya/sdk';

export const kya = new KyaClient(import.meta.env.VITE_KYA_URL ?? '/kya');
export const merchant = new DemoMerchantClient(import.meta.env.VITE_MERCHANT_URL ?? '/merchant');

const store = {
  get(k: string): string | null {
    try {
      return sessionStorage.getItem(k);
    } catch {
      return null;
    }
  },
  set(k: string, v: string | null) {
    try {
      v === null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v);
    } catch {
      /* storage unavailable: keep in memory only */
    }
  },
};

export interface Status {
  mode: string;
  policy_version: string;
  fail_closed_decision: string;
  accept_simulated: boolean;
  telegraph: { adapter: string; network: string; intent: string; simulated: boolean; payer_address?: string; max_price_minor: number; price_currency: string };
  spend?: { spent_today_minor: number; daily_cap_minor: number; currency: string };
  labels: Record<string, string>;
}

interface Session {
  status: Status | null;
  statusError: string | null;
  merchantId: string;
  token: string | null;
  consumerRef: string | null;
  agent: AgentSigner | null;
  login: (u: string, p: string) => Promise<void>;
  logout: () => void;
  ensureAgent: () => Promise<AgentSigner>;
  newAgent: () => Promise<AgentSigner>;
  ensureToken: () => Promise<string>;
  refreshStatus: () => void;
  bump: () => void;
  version: number;
}

const Ctx = createContext<Session>(null as unknown as Session);
export const useSession = () => useContext(Ctx);

export const DEMO_USER = 'alice';
export const DEMO_PASS = 'alice-demo-pass';

export function SessionProvider({ children }: { children: ComponentChildren }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [merchantId, setMerchantId] = useState('merchant_demo_001');
  const [token, setToken] = useState<string | null>(store.get('kya.token'));
  const [consumerRef, setConsumerRef] = useState<string | null>(store.get('kya.consumerRef'));
  const [agent, setAgent] = useState<AgentSigner | null>(null);
  const [version, setVersion] = useState(0);

  const refreshStatus = useCallback(() => {
    kya.status().then((s) => { setStatus(s as Status); setStatusError(null); }).catch((e) => setStatusError(String(e)));
  }, []);

  useEffect(() => {
    refreshStatus();
    merchant.merchant().then((m) => setMerchantId(m.merchant_id)).catch(() => {});
    const id = store.get('kya.agent.id');
    const sk = store.get('kya.agent.sk');
    if (id && sk) {
      AgentSigner.fromSecretKey(id, fromB64url(sk)).then(async (s) => {
        try {
          await kya.getAgent(id); // still registered (memory store may have restarted)
          setAgent(s);
        } catch {
          store.set('kya.agent.id', null);
        }
      });
    }
  }, []);

  const login = async (u: string, p: string) => {
    const r = await kya.login(u, p);
    setToken(r.token);
    setConsumerRef(r.consumer_ref);
    store.set('kya.token', r.token);
    store.set('kya.consumerRef', r.consumer_ref);
  };
  const logout = () => {
    setToken(null);
    store.set('kya.token', null);
  };
  const ensureToken = async () => {
    if (token) {
      try {
        await kya.listDelegations(token);
        return token;
      } catch {
        /* expired: log in again */
      }
    }
    const r = await kya.login(DEMO_USER, DEMO_PASS);
    setToken(r.token);
    setConsumerRef(r.consumer_ref);
    store.set('kya.token', r.token);
    store.set('kya.consumerRef', r.consumer_ref);
    return r.token;
  };
  const newAgent = async () => {
    const s = await createDemoAgent(kya, 'dashboard shopping agent');
    store.set('kya.agent.id', s.agentId);
    store.set('kya.agent.sk', s.exportSecretKey()); // synthetic demo key, session-scoped
    setAgent(s);
    return s;
  };
  const ensureAgent = async () => agent ?? newAgent();

  return (
    <Ctx.Provider
      value={{ status, statusError, merchantId, token, consumerRef, agent, login, logout, ensureAgent, newAgent, ensureToken, refreshStatus,
        bump: () => setVersion((v) => v + 1), version }}
    >
      {children}
    </Ctx.Provider>
  );
}
