import { useEffect, useMemo, useState } from "react";

const STORAGE_KEY = "obscura47_admin_key";

function formatAge(seconds) {
  if (!Number.isFinite(seconds)) return "unknown";
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${Math.round(seconds / 3600)}h`;
}

function shortId(value) {
  if (!value) return "unknown";
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

function fingerprint(pub) {
  if (!pub) return "no key";
  let hash = 0;
  for (let i = 0; i < pub.length; i += 1) {
    hash = (hash * 31 + pub.charCodeAt(i)) >>> 0;
  }
  return `fp-${hash.toString(16).padStart(8, "0")}`;
}

async function api(path, adminKey, options = {}) {
  const headers = {
    Accept: "application/json",
    ...(options.headers || {}),
  };
  if (adminKey) headers.Authorization = `Bearer ${adminKey}`;
  if (options.body) headers["Content-Type"] = "application/json";

  const response = await fetch(path, {
    ...options,
    headers,
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(data.detail || `Request failed with ${response.status}`);
  }
  return data;
}

function Stat({ label, value }) {
  return (
    <div className="stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StatusPill({ peer, ttl }) {
  const stale = peer.time_since_heartbeat > ttl;
  const pending = peer.role === "exit" && !peer.approved;
  const label = pending ? "pending" : stale ? "stale" : "online";
  return <span className={`pill ${label}`}>{label}</span>;
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
          onChange={(event) => setDraft(event.target.value)}
          placeholder="OBSCURA_REGISTRY_ADMIN_KEY"
        />
      </label>
      <button type="submit" disabled={loading}>
        Connect
      </button>
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
            <div className="muted">{shortId(peer.peer_id)} · {fingerprint(peer.pub)} · seen {formatAge(peer.time_since_heartbeat)} ago</div>
            {peer.ws_port ? (
              <div className="muted">{peer.ws_tls ? "wss" : "ws"}://{peer.host}:{peer.ws_port}</div>
            ) : null}
          </div>
          <div className="actions">
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
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {peers.map((peer) => (
            <tr key={peer.peer_id}>
              <td>
                <strong>{peer.host}:{peer.port}</strong>
                <span>{shortId(peer.peer_id)} · {fingerprint(peer.pub)}</span>
              </td>
              <td>{peer.role}</td>
              <td><StatusPill peer={peer} ttl={ttl} /></td>
              <td>{peer.ws_port ? `${peer.ws_tls ? "wss" : "ws"}:${peer.ws_port}` : "tcp only"}</td>
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

export default function App() {
  const [adminKey, setAdminKey] = useState(() => localStorage.getItem(STORAGE_KEY) || "");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [busyId, setBusyId] = useState("");

  const sortedPeers = useMemo(() => {
    const peers = data?.peers || [];
    return [...peers].sort((a, b) => {
      if (a.role === "exit" && !a.approved && !(b.role === "exit" && !b.approved)) return -1;
      if (b.role === "exit" && !b.approved && !(a.role === "exit" && !a.approved)) return 1;
      return a.time_since_heartbeat - b.time_since_heartbeat;
    });
  }, [data]);

  async function load(key = adminKey) {
    if (!key) {
      setError("Enter the registry admin key.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const next = await api("/admin/dashboard/data", key);
      setData(next);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

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

  useEffect(() => {
    if (adminKey) load(adminKey);
  }, []);

  const summary = data?.summary || {};
  const network = data?.network || {};
  const ttl = data?.peer_ttl || 120;

  return (
    <main>
      <header className="topbar">
        <div>
          <p className="eyebrow">Obscura47</p>
          <h1>Registry Control</h1>
        </div>
        <div className={`network-state ${network.kill_active ? "danger" : ""}`}>
          {network.kill_active ? "Kill switch active" : "Network accepting peers"}
        </div>
      </header>

      <AdminKeyForm adminKey={adminKey} setAdminKey={setAdminKey} onRefresh={load} loading={loading} />

      {error ? <div className="error">{error}</div> : null}

      <section className="stats">
        <Stat label="Total peers" value={summary.total ?? "-"} />
        <Stat label="Live" value={summary.live ?? "-"} />
        <Stat label="Stale" value={summary.stale ?? "-"} />
        <Stat label="Pending exits" value={summary.pending_exits ?? "-"} />
        <Stat label="Approved exits" value={summary.approved_exits ?? "-"} />
      </section>

      <section>
        <div className="section-head">
          <div>
            <p className="eyebrow">Approval queue</p>
            <h2>Pending Exit Nodes</h2>
          </div>
          <span className="muted">Only approved exits are returned to proxies.</span>
        </div>
        <PendingExits
          exits={data?.pending_exits || []}
          ttl={ttl}
          busyId={busyId}
          onApprove={(peerId) => act(peerId, `/admin/approve/${encodeURIComponent(peerId)}`)}
          onReject={(peerId) => act(peerId, `/admin/reject/${encodeURIComponent(peerId)}`)}
        />
      </section>

      <section>
        <div className="section-head">
          <div>
            <p className="eyebrow">Registry</p>
            <h2>Known Peers</h2>
          </div>
          <span className="muted">Stale threshold: {ttl}s</span>
        </div>
        <PeerTable
          peers={sortedPeers}
          ttl={ttl}
          busyId={busyId}
          onRemove={(peerId) => act(peerId, `/admin/remove/${encodeURIComponent(peerId)}`)}
        />
      </section>
    </main>
  );
}
