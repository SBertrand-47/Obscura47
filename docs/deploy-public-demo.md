# Deploying the public agent-operated-site demo

This is the runbook for putting the "a real model operates a live `.obscura`
site, fully observable" demo on the public internet so anyone can visit it and
you can watch the operator's mind on a dashboard.

It deliberately does **not** run on the work Mac. That machine is an internal
sibling behind a shared, IT-managed NAT: it hits the hairpin problem (a node
behind a public IP it shares with its own router cannot reach that IP), needs
the fragile gateway-sibling workaround, and depends on firewall rules you do not
control. Host on a real-public-IP node instead and all of that disappears.

## Use the infra you already have

You already run the public pieces this needs - no new VM to provision:

- **Registry** - `https://db.monmedjs.com` (Cloudflare-fronted; `/peers` over
  443). Already up. This is the default `OBSCURA_REGISTRY_URL`, so nothing to set.
- **Dedicated node VPS** - `207.244.232.226` (Contabo), a real public IP running
  a relay `node`. **This is where the demo should run.** It already advertises a
  reachable public address, so there is no hairpin and no gateway-sibling dance.
- An **exit** is also registered (`154.38.172.2`).

Everything below runs on the dedicated node VPS.

## The one real constraint: a hidden service needs >= 3 relays

`agentsite --serve` publishes a hidden service. Establishing it builds a
`OBSCURA_HS_CIRCUIT_HOPS`-hop circuit (default **3**) to intro + rendezvous
relays drawn from the registry. An operator's own node is not used as a hop in
its own circuit, so the operator needs **3 other relay `node` peers**. Right now
the registry has roughly **one** relay node live (plus an exit), so a 3-hop
publish will fail with `established no intro points`.

Pick one:

1. **Run extra relays on the dedicated node VPS (recommended).** Start 2-3 more
   relay processes on distinct ports so the HS circuit is self-contained and
   does not depend on other people's nodes staying warm. They all live on one
   always-on box - that defeats anonymity, which does not matter here (range
   mode is observable on purpose) and buys reliability.
2. **Lower the hop count for the demo:** `export OBSCURA_HS_CIRCUIT_HOPS=2` (or
   `1`). Simpler, less realistic; fine for a buzz demo.

This runbook does (1).

## Step 1 - firewall (on the dedicated node VPS)

Open inbound TCP for the relay frame + ws ports you will run. The existing relay
uses `5001/5002`; add two more on `5003/5004` and `5005/5006`:

```bash
sudo ufw allow 5001:5006/tcp     # plus 6000/6001 if this box also runs the exit
sudo ufw reload
```

## Step 2 - run two more relays alongside the existing one

The box already has one relay on `5001/5002`. Add two more, each advertising the
VPS's **public** IP (replace `207.244.232.226` if it differs):

```bash
export OBSCURA_MODE=range
export OBSCURA_REGISTRY_URL=https://db.monmedjs.com   # default; the live registry
export OBSCURA_NODE_ADVERTISED_HOST=207.244.232.226
export OBSCURA_ADVERTISED_HOST=207.244.232.226

OBSCURA_NODE_LISTEN_PORT=5003 OBSCURA_NODE_WS_PORT=5004 python join_network.py node &
OBSCURA_NODE_LISTEN_PORT=5005 OBSCURA_NODE_WS_PORT=5006 python join_network.py node &
```

Confirm three `node`-role peers now show in the registry on
`207.244.232.226:{5001,5003,5005}` before continuing:

```bash
curl -s https://db.monmedjs.com/peers | python -m json.tool | grep -E 'host|port|role'
```

Because the VPS has a real public IP, there are **no** `OBSCURA_MY_PUBLIC_IP` /
`OBSCURA_PRIMARY_LAN_*` bridge vars - those exist only for the work Mac's
shared-NAT case.

## Step 3 - publish the operated site (on the same VPS)

```bash
export OBSCURA_MODE=range
export ANTHROPIC_API_KEY=sk-ant-...
export OBSCURA_DESCRIPTOR_TTL=86400              # 24h registry TTL (default)

python -m src.range agentsite --serve \
  --name the-stacks \
  --key the-stacks.pem \
  --model claude-sonnet-4-6 \
  --jsonl the-stacks-events.jsonl \
  --bind 127.0.0.1 --port 0
```

On success it prints `[agentsite] the-stacks live at <addr>.obscura` and the
events file it is writing. Hand `<addr>.obscura` to visitors (they need a node +
proxy, or your exit, to resolve it). Every request becomes a model decision
recorded to `the-stacks-events.jsonl`.

## Step 4 - render the dashboard

While it is live or after:

```bash
python -m src.range observe <experiment_id> --html site.html
# the experiment_id is in the events file and the serve banner
```

## The cold-restart watchdog (do not skip this)

A long-running node "goes cold": intro circuits idle-close, the republish
silently fails, and **the registry descriptor expires `OBSCURA_DESCRIPTOR_TTL`
(24h) after the last good republish** - the site starts 404ing while the process
is still alive. For an always-on public demo you must restart on cold detection,
well within the TTL.

Use `scripts/agentsite-serve-watchdog.sh` (companion to this doc). It:

- runs the serve process,
- tails its log for cold signals (`rv_ready timeout`,
  `peer_health ... UNREACHABLE`, `Bad file descriptor`,
  `Failed to send frame`, `established no intro points`),
- recycles if those burst past a threshold,
- and force-recycles every `MAX_UPTIME` (default 6h, comfortably under the 24h
  TTL) as a belt-and-suspenders against silent descriptor expiry.

Run the relays (step 2) and the watchdog under a process supervisor (systemd /
`tmux` / `nohup`) so a VPS reboot brings the whole demo back.

## Cost

The operator is a real model: **one model call per visitor request**. A public
URL can be crawled or spiked, so each visit costs tokens. Mitigate with a cheaper
`--model` (e.g. `claude-haiku-4-5-20251001`), and consider rate-limiting at the
app/edge before sharing the address widely.

## Why this is the right home for the demo

The whole NAT-hairpin / gateway-sibling effort exists to make an internal,
IT-managed Mac behave like a public host. The dedicated node VPS already *is*
one. For the buzz demo - where reliability and "anyone can visit" matter more
than the operator's own anonymity - hosting on the VPS removes an entire class of
failure (hairpin, IT firewall, cold home nodes) in one move.
