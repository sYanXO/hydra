import { useEffect, useState } from 'react';
import nacl from 'tweetnacl';

function loadIdentity() {
  const raw = localStorage.getItem('hydra.identity');
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function decodeMessage(ciphertextB64) {
  try {
    const bytes = fromB64(ciphertextB64 || '');
    const text = new TextDecoder().decode(bytes);
    const json = JSON.parse(text);
    return json.body || text;
  } catch {
    return '<unable to decode>';
  }
}

function canonicalRegister(p) {
  return [
    'pi-chat-register-v1',
    `user_id:${p.user_id}`,
    `identity_key_ed25519:${p.identity_key_ed25519}`,
    `dh_key_x25519:${p.dh_key_x25519}`,
    `nonce:${p.nonce}`,
    `signed_at:${p.signed_at}`
  ].join('\n');
}

function canonicalMessage(p) {
  return [
    'pi-chat-message-v1',
    `version:${p.version}`,
    `message_id:${p.message_id}`,
    `from_user_id:${p.from_user_id}`,
    `to_user_id:${p.to_user_id}`,
    `sender_identity_key_ed25519:${p.sender_identity_key_ed25519}`,
    `sender_dh_key_x25519:${p.sender_dh_key_x25519}`,
    `nonce:${p.nonce}`,
    `ciphertext:${p.ciphertext}`,
    `sent_at:${p.sent_at}`
  ].join('\n');
}

function sign(message, secretB64) {
  const sig = nacl.sign.detached(new TextEncoder().encode(message), fromB64(secretB64));
  return toB64(sig);
}

function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

function toB64(bytes) {
  let binary = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary);
}

function fromB64(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function parseHandle(raw) {
  const s = (raw || '').trim();
  const m = s.match(/^([a-z0-9_]{3,20})#([0-9]{4})$/i);
  if (!m) return null;
  return { username: m[1].toLowerCase(), discriminator: m[2] };
}

export default function App() {
  const [identity, setIdentity] = useState(loadIdentity());
  const [toUserId, setToUserId] = useState('');
  const [messageBody, setMessageBody] = useState('');
  const [pendingNotices, setPendingNotices] = useState([]);
  const [receivedMessages, setReceivedMessages] = useState([]);
  const [logLines, setLogLines] = useState([]);
  const [busy, setBusy] = useState(false);
  const [ackInFlight, setAckInFlight] = useState(false);

  const userId = identity?.user_id || 'not generated';
  const userHandle = identity?.handle?.full || 'not registered';
  const hasIdentity = Boolean(identity);

  function log(line) {
    setLogLines((prev) => [`${new Date().toISOString()} ${line}`, ...prev].slice(0, 200));
  }

  function persistIdentity(next) {
    localStorage.setItem('hydra.identity', JSON.stringify(next));
    setIdentity(next);
  }

  function generateIdentity() {
    const kp = nacl.sign.keyPair();
    const next = {
      user_id: crypto.randomUUID(),
      identity_key_ed25519: toB64(kp.publicKey),
      identity_secret_ed25519: toB64(kp.secretKey),
      dh_key_x25519: toB64(randomBytes(32))
    };
    persistIdentity(next);
    log(`generated identity ${next.user_id}`);
  }

  async function copyHandle() {
    const full = identity?.handle?.full;
    if (!full) return log('register first to get a handle');
    try {
      await navigator.clipboard.writeText(full);
      log(`copied handle ${full}`);
    } catch (e) {
      log(`copy handle failed: ${e.message}`);
    }
  }

  async function resolveRecipientUserID(raw) {
    const handle = parseHandle(raw);
    if (!handle) return raw.trim();
    const res = await fetch(`/users/by-handle/${encodeURIComponent(handle.username)}/${encodeURIComponent(handle.discriminator)}/keys`);
    const data = await res.json();
    if (!res.ok || !data.user_id) {
      throw new Error(`resolve recipient failed (${res.status})`);
    }
    return data.user_id;
  }

  async function registerUser() {
    if (!identity) return log('generate identity first');
    setBusy(true);
    try {
      const payload = {
        user_id: identity.user_id,
        identity_key_ed25519: identity.identity_key_ed25519,
        dh_key_x25519: identity.dh_key_x25519,
        nonce: toB64(randomBytes(16)),
        signed_at: new Date().toISOString()
      };
      payload.signature = sign(canonicalRegister(payload), identity.identity_secret_ed25519);

      const res = await fetch('/users/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      log(`register ${res.status}: ${JSON.stringify(data)}`);
      if (res.ok && data?.handle) {
        persistIdentity({ ...identity, handle: data.handle });
      }
    } catch (e) {
      log(`register failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function sendMessage() {
    if (!identity) return log('generate identity first');
    if (!toUserId.trim() || !messageBody.trim()) return log('recipient and message required');
    setBusy(true);
    try {
      const plaintext = JSON.stringify({
        type: 'text',
        body: messageBody,
        content_version: 1,
        created_at: new Date().toISOString()
      });
      const resolvedRecipient = await resolveRecipientUserID(toUserId);
      if (resolvedRecipient === identity.user_id) {
        return log('cannot send message to yourself');
      }
      const payload = {
        version: 1,
        message_id: crypto.randomUUID(),
        from_user_id: identity.user_id,
        to_user_id: resolvedRecipient,
        sender_identity_key_ed25519: identity.identity_key_ed25519,
        sender_dh_key_x25519: identity.dh_key_x25519,
        nonce: toB64(randomBytes(24)),
        ciphertext: toB64(new TextEncoder().encode(plaintext)),
        sent_at: new Date().toISOString()
      };
      payload.signature = sign(canonicalMessage(payload), identity.identity_secret_ed25519);

      const res = await fetch('/messages', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      log(`send ${res.status}: ${JSON.stringify(data)}`);
      if (res.ok) {
        setMessageBody('');
        await pollMessages({ background: true });
      }
    } catch (e) {
      log(`send failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function pollMessages(options = {}) {
    const background = options.background === true;
    if (!identity) {
      if (!background) log('generate identity first');
      return;
    }
    if (!background) setBusy(true);
    try {
      const res = await fetch(`/messages/poll?user_id=${encodeURIComponent(identity.user_id)}&limit=50`);
      const data = await res.json();
      if (!background) log(`poll ${res.status}: ${JSON.stringify(data)}`);
      if (Array.isArray(data.messages)) setPendingNotices(data.messages);
    } catch (e) {
      if (!background) log(`poll failed: ${e.message}`);
    } finally {
      if (!background) setBusy(false);
    }
  }

  async function ackAll() {
    if (!identity) return log('generate identity first');
    if (!pendingNotices.length) return log('no pending notifications to ack');
    if (ackInFlight) return log('ack already in progress');
    setAckInFlight(true);
    setBusy(true);
    try {
      const body = {
        user_id: identity.user_id,
        server_message_ids: pendingNotices.map((m) => m.server_message_id),
        acked_at: new Date().toISOString()
      };
      const res = await fetch('/messages/ack', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      log(`ack ${res.status}: ${JSON.stringify(data)}`);
      if (res.ok && Array.isArray(data.messages)) {
        if ((data.acked_count || 0) === 0) {
          log('nothing acked (possibly already acknowledged or stale notices)');
        }
        const decoded = data.messages.map((m) => ({
          server_message_id: m.server_message_id,
          from_user_id: m.envelope?.from_user_id,
          preview: decodeMessage(m.envelope?.ciphertext),
          received_at: m.received_at
        }));
        if (decoded.length) setReceivedMessages((prev) => [...decoded, ...prev]);
        setPendingNotices([]);
      }
    } catch (e) {
      log(`ack failed: ${e.message}`);
    } finally {
      setBusy(false);
      setAckInFlight(false);
    }
  }

  useEffect(() => {
    if (!identity) return undefined;
    const id = setInterval(() => {
      pollMessages({ background: true });
    }, 10000);
    return () => clearInterval(id);
  }, [identity]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="max-w-7xl mx-auto p-6 md:p-8">
        <header className="mb-8 flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <h1 className="text-3xl md:text-4xl font-semibold tracking-tight">Hydra Chat</h1>
            <p className="text-slate-400 mt-2">Poll shows notifications. Ack reveals message contents.</p>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900 px-4 py-3 text-sm">
            <div className="text-slate-400">Local user id</div>
            <div className="font-mono break-all mt-1">{userId}</div>
            <div className="text-slate-400 mt-2">Handle</div>
            <div className="font-mono break-all mt-1">{userHandle}</div>
            <button onClick={copyHandle} disabled={!identity?.handle?.full} className="mt-2 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 px-3 py-1.5 text-xs">Copy handle</button>
          </div>
        </header>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <section className="xl:col-span-1 rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl shadow-black/20">
            <h2 className="text-lg font-medium">Identity</h2>
            <p className="text-sm text-slate-400 mt-1">Generate and register device identity</p>
            <div className="mt-4 flex gap-3">
              <button onClick={generateIdentity} className="flex-1 rounded-lg bg-slate-800 hover:bg-slate-700 px-3 py-2 text-sm">Generate</button>
              <button onClick={registerUser} disabled={!hasIdentity || busy} className="flex-1 rounded-lg bg-brand-600 hover:bg-brand-500 disabled:opacity-50 px-3 py-2 text-sm">Register</button>
            </div>
          </section>

          <section className="xl:col-span-2 rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl shadow-black/20">
            <h2 className="text-lg font-medium">Send Message</h2>
            <div className="mt-4 space-y-3">
              <div>
                <label className="text-sm text-slate-300">Recipient (user id or handle)</label>
                <input value={toUserId} onChange={(e) => setToUserId(e.target.value)} className="mt-1 w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 outline-none focus:ring-2 focus:ring-brand-500" placeholder="user-id or username#1234" />
              </div>
              <div>
                <label className="text-sm text-slate-300">Message</label>
                <textarea rows={4} value={messageBody} onChange={(e) => setMessageBody(e.target.value)} className="mt-1 w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 outline-none focus:ring-2 focus:ring-brand-500" placeholder="Write a message" />
              </div>
              <button onClick={sendMessage} disabled={!hasIdentity || busy} className="rounded-lg bg-brand-600 hover:bg-brand-500 disabled:opacity-50 px-4 py-2 text-sm">Send</button>
            </div>
          </section>

          <section className="xl:col-span-2 rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl shadow-black/20">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-medium">Inbox</h2>
              <div className="flex gap-2">
                <button onClick={pollMessages} disabled={!hasIdentity || busy} className="rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 px-3 py-2 text-sm">Poll notices</button>
                <button onClick={ackAll} disabled={!hasIdentity || busy || ackInFlight || !pendingNotices.length} className="rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 px-3 py-2 text-sm">{ackInFlight ? 'Acking…' : 'Ack and fetch'}</button>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h3 className="text-sm text-slate-300 mb-2">Pending notices</h3>
                <div className="space-y-2 max-h-[260px] overflow-auto pr-1">
                  {pendingNotices.length === 0 && <p className="text-sm text-slate-400">No pending notices</p>}
                  {pendingNotices.map((m) => (
                    <article key={m.server_message_id} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                      <div className="text-xs text-slate-400">{m.server_message_id}</div>
                      <div className="mt-1 text-sm"><span className="text-slate-400">from</span> <span className="font-mono">{m.from_user_id}</span></div>
                    </article>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="text-sm text-slate-300 mb-2">Acknowledged messages</h3>
                <div className="space-y-2 max-h-[260px] overflow-auto pr-1">
                  {receivedMessages.length === 0 && <p className="text-sm text-slate-400">No acknowledged messages yet</p>}
                  {receivedMessages.map((m) => (
                    <article key={`${m.server_message_id}-${m.received_at}`} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                      <div className="text-xs text-slate-400">{m.server_message_id}</div>
                      <div className="mt-1 text-sm"><span className="text-slate-400">from</span> <span className="font-mono">{m.from_user_id}</span></div>
                      <p className="mt-2 text-sm text-slate-100">{m.preview}</p>
                    </article>
                  ))}
                </div>
              </div>
            </div>
          </section>

          <section className="xl:col-span-1 rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl shadow-black/20">
            <h2 className="text-lg font-medium">Logs</h2>
            <div className="mt-3 h-[320px] overflow-auto rounded-lg bg-slate-950 border border-slate-800 p-3 text-xs font-mono text-slate-300 space-y-1">
              {logLines.length === 0 && <div className="text-slate-500">No logs yet</div>}
              {logLines.map((line, idx) => <div key={idx}>{line}</div>)}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
