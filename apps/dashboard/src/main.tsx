import { render } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { SessionProvider, useSession } from './session';
import { Tag, usdc } from './ui';
import { Launcher } from './views/Launcher';
import { Consumer } from './views/Consumer';
import { Checkout } from './views/Checkout';
import { Inspector } from './views/Inspector';
import { Operations } from './views/Operations';
import './styles.css';

const TABS = [
  ['launcher', 'Scenarios'],
  ['consumer', 'Consumer'],
  ['checkout', 'Checkout'],
  ['inspect', 'Evidence'],
  ['ops', 'Operations'],
] as const;
type Tab = (typeof TABS)[number][0];

function parseHash(): { tab: Tab; id: string | null } {
  const [, tab, id] = location.hash.split('/');
  return { tab: (TABS.some(([t]) => t === tab) ? tab : 'launcher') as Tab, id: id ?? null };
}

function StatusBar() {
  const { status, statusError } = useSession();
  if (statusError) return <div class="statusbar error">KYA API unreachable: {statusError}</div>;
  if (!status) return <div class="statusbar muted">Connecting…</div>;
  const t = status.telegraph;
  return (
    <div class="statusbar">
      {t.simulated ? (
        <Tag tone="warn" title="No Telegraph purchases are made in this deployment">Intelligence SIMULATED</Tag>
      ) : (
        <Tag tone="live" title={`Payer ${t.payer_address}`}>Telegraph LIVE · {t.network}</Tag>
      )}
      <Tag>{t.intent}</Tag>
      <Tag>mode {status.mode}</Tag>
      <Tag>policy {status.policy_version}</Tag>
      <Tag>fail-closed → {status.fail_closed_decision}</Tag>
      {status.spend && <Tag title="Daily Telegraph spend cap">spend {usdc(status.spend.spent_today_minor)} / {usdc(status.spend.daily_cap_minor)}</Tag>}
      <Tag tone="warn">checkout SIMULATED</Tag>
      <Tag tone="warn">synthetic consumers</Tag>
    </div>
  );
}

function App() {
  const [route, setRoute] = useState(parseHash());
  useEffect(() => {
    const on = () => setRoute(parseHash());
    addEventListener('hashchange', on);
    return () => removeEventListener('hashchange', on);
  }, []);
  const go = (tab: Tab, id?: string) => { location.hash = `/${tab}${id ? '/' + id : ''}`; };
  const inspect = (id: string) => go('inspect', id);

  return (
    <div class="shell">
      <header class="top">
        <div class="brand">
          <span class="logo" aria-hidden="true">✓</span>
          <div>
            <h1>KYA Gateway</h1>
            <p class="muted small">Know who the agent is, what it may do, and why to accept its transaction.</p>
          </div>
        </div>
        <nav class="tabs" role="tablist">
          {TABS.map(([id, label]) => (
            <a key={id} role="tab" aria-selected={route.tab === id} class={route.tab === id ? 'active' : ''} href={`#/${id}`}>{label}</a>
          ))}
        </nav>
      </header>
      <StatusBar />
      <main>
        {route.tab === 'launcher' && <Launcher inspect={inspect} />}
        {route.tab === 'consumer' && <Consumer />}
        {route.tab === 'checkout' && <Checkout inspect={inspect} />}
        {route.tab === 'inspect' && <Inspector selected={route.id} select={inspect} />}
        {route.tab === 'ops' && <Operations />}
      </main>
      <footer class="foot muted small">
        Cryptographic identity proves key control, not real-world identity or payment authorization. Telegraph intelligence is a risk input, not proof of consent.
      </footer>
    </div>
  );
}

render(
  <SessionProvider>
    <App />
  </SessionProvider>,
  document.getElementById('app')!,
);
