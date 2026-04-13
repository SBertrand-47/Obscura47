import { useCallback, useEffect, useMemo, useState } from "react";

const STORAGE_KEY = "obscura47_admin_key";
const REFRESH_MS = 10000;

function formatAge(seconds) {
  if (!Number.isFinite(seconds)) return "—";
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${Math.round(seconds / 3600)}h`;
}

function shortId(value) {
  if (!value) return "unknown";
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}…${value.slice(-6)}`;
}

async function sha256Fingerprint(pub) {
  if (!pub) return "no key";
  const bytes = new TextEncoder().encode(pub);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `fp:${hex.slice(0, 8)}`;
}

async function enrichPeers(peers) {
  if (!Array.isArray(peers)) return peers;
  return Promise.all(
    peers.map(async (peer) => ({ ...peer, fp: await sha256Fingerprint(peer.pub) })),
  );
}

async function api(path, adminKey, options = {}) {
  const headers = {
    Accept: "application/json",
    ...(options.headers || {}),
  };
  if (adminKey) headers.Authorization = `Bearer ${adminKey}`;
  if (options.body) headers["Content-Type"] = "application/json";

  const response = await fetch(path, { ...options, headers });
  const text = await response.text();
  if (!response.ok) {
    let detail;
    try { detail = JSON.parse(text)?.detail; } catch (_) {}
    throw new Error(detail || text || `Request failed with ${response.status}`);
  }
  const data = text ? JSON.parse(text) : {};
  return data;
}

// ── Sub-components ────────────────────────────────────────────

function Stat({ label, value, accent }) {
  return (
    <div className={`stat ${accent || ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  );
}

function RoleBadge({ role }) {
  return <span className={`role-badge ${role}`}>{role}</span>;
}

function StatusPill({ peer, ttl }) {
  const stale = peer.time_since_heartbeat > ttl;
  const pending = peer.role === "exit" && !peer.approved;
  const label = pending ? "pending" : stale ? "stale" : "online";
  return <span className={`pill ${label}`}>{label}</span>;
}

function Transport({ peer }) {
  if (!peer.ws_port) return <span className="transport">tcp</span>;
  const proto = peer.ws_tls ? "wss" : "ws";
  return <span className={`transport ${proto}`}>{proto}:{peer.ws_port}</span>;
}

function LiveIndicator({ lastRefresh }) {
  if (!lastRefresh) return null;
  const age = Math.round((Date.now() - lastRefresh) / 1000);
  return (
    <div className="live-indicator">
      <span className="live-dot" />
      {age < 5 ? "just now" : `${age}s ago`}
    </div>
  );
}

function AdminKeyForm({ adminKey, setAdminKey, onRefresh, loading }) {
  const [draft, setDraft] = useState(adminKey);

  function save(event) {
    event.preventDefault();
    localStorage.setItem(STORAGE_KEY, draft);
    setAdminKey(draft);
    onRefresh(draft);
  }

  return (
    <form className="toolbar" onSubmit={save}>
      <label>
        Admin key
        <input
          type="password"
          autoComplete="current-password"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="OBSCURA_REGISTRY_ADMIN_KEY"
        />
      </label>
      <button type="submit" disabled={loading}>Connect</button>
      <button type="button" className="secondary" onClick={() => onRefresh()} disabled={loading || !adminKey}>
        Refresh
      </button>
    </form>
  );
}

function PendingExits({ exits, ttl, onApprove, onReject, busyId }) {
  if (!exits.length) {
    return <div className="empty">No pending exit nodes.</div>;
  }
  return (
    <div className="pending-list">
      {exits.map((peer) => (
        <article className="item" key={peer.peer_id}>
          <div>
            <div className="item-title">{peer.host}:{peer.port}</div>
            <div className="item-meta">
              <span>{shortId(peer.peer_id)}</span>
              <span>{peer.fp || "…"}</span>
              {peer.ws_port && <span>{peer.ws_tls ? "wss" : "ws"}:{peer.ws_port}</span>}
              <span>seen {formatAge(peer.time_since_heartbeat)} ago</span>
            </div>
          </div>
          <div className="item-actions">
            <StatusPill peer={peer} ttl={ttl} />
            <button onClick={() => onApprove(peer.peer_id)} disabled={busyId === peer.peer_id}>
              Approve
            </button>
            <button className="danger" onClick={() => onReject(peer.peer_id)} disabled={busyId === peer.peer_id}>
              Reject
            </button>
          </div>
        </article>
      ))}
    </div>
  );
}

function PeerTable({ peers, ttl, onRemove, busyId }) {
  if (!peers.length) {
    return <div className="empty">No peers registered.</div>;
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Peer</th>
            <th>Role</th>
            <th>Status</th>
            <th>Transport</th>
            <th>Last seen</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {peers.map((peer) => (
            <tr key={peer.peer_id}>
              <td>
                <div className="peer-host">{peer.host}:{peer.port}</div>
                <div className="peer-meta">{shortId(peer.peer_id)} · {peer.fp || "…"}</div>
              </td>
              <td><RoleBadge role={peer.role} /></td>
              <td><StatusPill peer={peer} ttl={ttl} /></td>
              <td><Transport peer={peer} /></td>
              <td>{formatAge(peer.time_since_heartbeat)} ago</td>
              <td>
                <button className="secondary" onClick={() => onRemove(peer.peer_id)} disabled={busyId === peer.peer_id}>
                  Remove
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── App ───────────────────────────────────────────────────────

export default function App() {
  const [adminKey, setAdminKey] = useState(() => localStorage.getItem(STORAGE_KEY) || "");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [busyId, setBusyId] = useState("");
  const [lastRefresh, setLastRefresh] = useState(null);

  const sortedPeers = useMemo(() => {
    const peers = data?.peers || [];
    return [...peers].sort((a, b) => {
      const aPending = a.role === "exit" && !a.approved;
      const bPending = b.role === "exit" && !b.approved;
      if (aPending && !bPending) return -1;
      if (bPending && !aPending) return 1;
      return a.time_since_heartbeat - b.time_since_heartbeat;
    });
  }, [data]);

  const load = useCallback(async (key = adminKey, { silent = false } = {}) => {
    if (!key) {
      if (!silent) setError("Enter the registry admin key.");
      return;
    }
    if (!silent) setLoading(true);
    try {
      const next = await api("/admin/dashboard/data", key);
      next.peers = await enrichPeers(next.peers || []);
      next.pending_exits = await enrichPeers(next.pending_exits || []);
      setData(next);
      setLastRefresh(Date.now());
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [adminKey]);

  async function act(peerId, path) {
    setBusyId(peerId);
    setError("");
    try {
      await api(path, adminKey, { method: "POST" });
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId("");
    }
  }

  async function revive() {
    setError("");
    try {
      await api("/admin/revive", adminKey, { method: "POST" });
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  function confirmRemove(peerId) {
    if (!window.confirm(`Remove peer ${peerId}? This drops it from the registry.`)) return;
    act(peerId, `/admin/remove/${encodeURIComponent(peerId)}`);
  }

  function confirmReject(peerId) {
    if (!window.confirm(`Reject exit ${peerId}? The node will not receive traffic.`)) return;
    act(peerId, `/admin/reject/${encodeURIComponent(peerId)}`);
  }

  useEffect(() => {
    if (adminKey) load(adminKey);
  }, [adminKey, load]);

  useEffect(() => {
    if (!adminKey) return undefined;
    const id = setInterval(() => {
      if (!document.hidden) load(adminKey, { silent: true });
    }, REFRESH_MS);
    return () => clearInterval(id);
  }, [adminKey, load]);

  const summary = data?.summary || {};
  const network = data?.network || {};
  const ttl = data?.peer_ttl || 120;
  const killActive = network.kill_active;

  return (
    <main>
      <header className="topbar">
        <div className="topbar-left">
          <div className="topbar-icon">⬡</div>
          <div className="topbar-title">
            <p className="eyebrow">Obscura47</p>
            <h1>Registry Control</h1>
          </div>
        </div>
        <div className="topbar-right">
          <LiveIndicator lastRefresh={lastRefresh} />
          <div className={`network-state ${killActive ? "danger" : ""}`}>
            {killActive ? "Kill switch active" : "Network live"}
          </div>
          {killActive && (
            <button className="secondary" onClick={revive} disabled={loading || !adminKey}>
              Revive
            </button>
          )}
        </div>
      </header>

      <AdminKeyForm adminKey={adminKey} setAdminKey={setAdminKey} onRefresh={load} loading={loading} />

      {error && <div className="error">{error}</div>}

      <div className="stats">
        <Stat label="Total peers" value={summary.total ?? "—"} />
        <Stat label="Live" value={summary.live ?? "—"} accent="accent" />
        <Stat label="Stale" value={summary.stale ?? "—"} />
        <Stat label="Pending exits" value={summary.pending_exits ?? "—"} accent={summary.pending_exits > 0 ? "pending" : ""} />
        <Stat label="Approved exits" value={summary.approved_exits ?? "—"} accent="accent" />
      </div>

      <section>
        <div className="section-head">
          <div>
            <p className="eyebrow">Approval queue</p>
            <h2>Pending Exit Nodes</h2>
          </div>
          <span className="section-tag">Approved only · proxies see exits</span>
        </div>
        <PendingExits
          exits={data?.pending_exits || []}
          ttl={ttl}
          busyId={busyId}
          onApprove={(peerId) => act(peerId, `/admin/approve/${encodeURIComponent(peerId)}`)}
          onReject={confirmReject}
        />
      </section>

      <section>
        <div className="section-head">
          <div>
            <p className="eyebrow">Registry</p>
            <h2>Known Peers</h2>
          </div>
          <span className="section-tag">TTL {ttl}s</span>
        </div>
        <PeerTable
          peers={sortedPeers}
          ttl={ttl}
          busyId={busyId}
          onRemove={confirmRemove}
        />
      </section>
    </main>
  );
}
