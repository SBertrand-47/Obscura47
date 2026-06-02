# Obscura47

Obscura47 is an observability-first range for studying how autonomous AI agents
behave under adversarial conditions. Agents act, trade, deceive, and defend in a
live society, and you observe and contain every move - then get a ship/no-ship
verdict you can put in front of a release committee.

It runs on a private, Tor-style overlay network (relays, exits, `.obscura`
hidden services) - the same architecture as Tor, inverted: in range mode,
instead of hiding traffic it makes every action attributable. So you can watch a
real model agent probe a network, scam a buyer, get caught and banned, and read
the whole story - reasoning beside traffic - on one dashboard.

```bash
# run the whole observable society and write its dashboard
OBSCURA_MODE=range python -m src.range society --html society.html
```

See [`docs/live-society.md`](docs/live-society.md) for the live society and
[`src/range/README.md`](src/range/README.md) for the range.

### The overlay is also a working private network

The substrate is a real, usable Tor-style overlay in its own right, and running
nodes is how the network grows. The agent-range observability is **off by
default** (it is a deliberate privacy regression, gated on `OBSCURA_MODE=range`),
so the consumer network is unaffected - you can simply:

- run a local proxy
- join the network as a relay
- publish a local site or TCP service at a `.obscura` address
- optionally browse an opt-in `.obscura` directory

It aims to resist traffic analysis - see
[Traffic-Analysis Resistance](#traffic-analysis-resistance) for what that
protects against and, just as importantly, what it does not.

Code in this repository is licensed under [Apache-2.0](./LICENSE). The
Obscura47 name and branding are governed separately by
[TRADEMARKS.md](./TRADEMARKS.md).

## What You Can Do

**Study AI agents (the range)**

- **Run a live agent society** and watch it on one dashboard: real and scripted
  agents trade, probe, and deceive; controls catch them; a regulator issues a
  ship/no-ship verdict (`python -m src.range society --html society.html`)
- **Measure which controls are load-bearing** by ablating one and watching the
  verdict flip (`python -m src.range society --without defender`)
- **Replay captured real-model runs** deterministically, with no API key, so
  genuine agent behaviour is regression-locked

**Use the network**

- **Connect to the network** from the desktop app, tray app, or CLI
- **Browse through Obscura** using the local proxy, or point Firefox at it for
  one browser that handles both `.obscura` and the clearnet (see
  [Use Your Own Browser](#use-your-own-browser-firefox))
- **Open `.obscura` sites** from the built-in desktop and tray flows
- **Publish your own `.obscura` site** from a folder or local TCP service
- **Run a relay node** to contribute bandwidth
- **Apply to run an exit node** if you understand the operational risk

## Shared Public Network

The shared public network is operator-run and ready to use out of the box.

- Bootstrap registry: `https://db.monmedjs.com`
- Exit capacity is operator-curated for reliability and safety
- Backed by operator-managed exit infrastructure

## Quick Start

Get the code, then run the one launcher for your OS. It creates an isolated
Python environment on first run, installs everything, and opens the desktop
app, then you just click **Connect**.

```bash
git clone https://github.com/SBertrand-47/Obscura47.git
cd Obscura47
```

**macOS**: double-click **`run.command`** in Finder, or from a terminal:

```bash
./run.sh
```

**Linux**

```bash
./run.sh
```

**Windows**: double-click **`run.bat`**, or from a terminal:

```bat
run.bat
```

That's it. The launcher handles the parts that differ between platforms
(creating the virtualenv, finding the right Python) for you, so there's
nothing to activate and no `.env` to edit for the defaults. The first run
downloads dependencies; later runs start immediately. **If you already set up
a virtualenv, it's reused, never recreated or wiped.**

> **Prerequisite:** Python 3.10+ from [python.org](https://www.python.org/downloads/)
> (on Windows tick *"Add python.exe to PATH"*). On Linux the desktop GUI also
> needs Tk: `sudo apt install -y python3-tk`. The launcher tells you if it's
> missing.

### Manual setup (any platform)

Prefer to drive it yourself? Create a virtualenv once and use its Python
directly. Note the create/activate commands differ per platform:

| | Create venv | Activate (optional) |
|---|---|---|
| macOS / Linux | `python3 -m venv venv` | `source venv/bin/activate` |
| Windows (PowerShell) | `py -m venv venv` | `venv\Scripts\Activate.ps1` |
| Windows (cmd) | `py -m venv venv` | `venv\Scripts\activate.bat` |

```bash
# after activating (or just call venv/bin/python, venv\Scripts\python.exe on Windows):
pip install -r requirements.txt
python app.py              # desktop app   (or: tray_app.py / join_network.py)
```

For the shared public network the default `OBSCURA_REGISTRY_URL` already points
at `https://db.monmedjs.com`. The CLI launcher is `python join_network.py`;
common direct commands:

```bash
python join_network.py node
python join_network.py proxy
python join_network.py host ./site --name mysite
python join_network.py open alpha.obscura
```

## Main Ways To Use It

> In the commands below, `python` means the project venv's Python. If you used
> `./run.sh` / `run.bat` it's already set up, call `venv/bin/python` (or
> `venv\Scripts\python.exe` on Windows), or activate the venv first.

### Desktop App

```bash
./run.sh            # Linux / macOS terminal  (macOS Finder: run.command; Windows: run.bat), recommended
python app.py       # if your venv is already active
```

The desktop app is the main user-facing surface. From `Quick Actions` you can:

- connect to the network
- open a `.obscura` address in a browser
- browse a directory and open a listing
- add, publish, and remove hosted sites
- review your saved hosted site addresses

### System Tray

```bash
python tray_app.py
```

The tray app keeps Obscura47 running in the background and exposes the same
core everyday flows:

- open a `.obscura` address
- browse a directory
- add or publish a site
- review and open your hosted sites

### CLI

```bash
python join_network.py
```

The CLI remains the most complete surface for operators and power users.

Useful commands:

```bash
python join_network.py node
python join_network.py proxy
python join_network.py host ./site --name mysite
python join_network.py host list
python join_network.py host publish ./site --name mysite --directory directory.obscura
python join_network.py directory list directory.obscura
python join_network.py directory get directory.obscura alpha.obscura
python join_network.py open alpha.obscura
```

## Everyday Flows

### Visit a Site

Use the desktop app, tray app, or:

```bash
python join_network.py open alpha.obscura
```

Obscura47 can start the local proxy, prepare browser routing, and open the site
for you. You do not need to manually reconfigure your everyday browser when you
use the built-in open flow.

### Use Your Own Browser (Firefox)

Prefer to browse from Firefox directly? Point it at the local Obscura47 proxy
once and you get the best of both worlds: `.obscura` sites and the regular
clearnet, side by side in the same browser, with no switching back and forth.

1. Make sure Obscura47 is running and connected (desktop app, tray app, or
   `python join_network.py proxy`). The proxy listens on `127.0.0.1:9047`.
2. In Firefox open **Settings -> Network Settings -> Settings...**
3. Choose **Manual proxy configuration** and set:
   - **HTTP Proxy:** `localhost`  **Port:** `9047`
   - Tick **Also use this proxy for HTTPS**
4. Save. That's it.

Now Firefox routes everything through Obscura47: type a `name.obscura` address
to reach a hidden service, or any normal `https://` site to browse the clearnet
through the network. Both just work in the same window, so there's nothing for
you to think about while browsing.

> Tip: use a separate Firefox profile (`firefox -P`) or a container if you want
> an always-on Obscura window alongside an untouched everyday browser.

### Publish a Site

To publish a local folder:

```bash
python join_network.py host ./mysite --name mysite
```

To publish and announce it through a directory:

```bash
python join_network.py host publish ./mysite --name mysite --directory directory.obscura
```

Obscura47 stores the site key under `~/.obscura47/sites/`, remembers the saved
target, and can install a per-site background service.

### Browse Discovery

If you know a directory address:

```bash
python join_network.py directory list directory.obscura
```

Or use `Browse Directory` from the desktop or tray app.

## Hidden Services

`.obscura` addresses are self-authenticating names derived from a service
public key. If you lose the private key, you lose the address.

Obscura47 supports:

- stable per-site keys
- multiple named hosted sites on one machine
- per-site background daemons
- opt-in `/.well-known/obscura.json` manifests
- optional directory registration for discoverability

## Traffic-Analysis Resistance

An adversary who can watch the network at both the **entry** and the **exit**
tries to **correlate** flows - matching traffic going in to traffic coming out
- by their packet **sizes** and **timing**. Obscura47 layers several defenses
against this. Two are always on; the timing defenses are opt-in because they
trade latency and bandwidth for protection.

| Defense | Status | What it hides | Cost |
|---|---|---|---|
| **Fixed-size cells** | always on | message *length* - every frame is padded to one of a few fixed bucket sizes, so the ciphertext length on the wire reveals only the bucket, not the real payload size | minimal bandwidth |
| **Stream multiplexing** | always on | per-stream connection boundaries - many streams share one connection to each hop, so an observer cannot count concurrent flows or line up stream open/close with TCP connect/close events | none (also fewer sockets) |
| **Forward jitter** | opt-in | fine-grained timing - each relay delays each frame by a small random amount | mild latency |
| **Cover traffic** | opt-in | whether a link is idle or busy - relays emit indistinguishable "drop" cells at a Poisson rate, padding the link | extra bandwidth |
| **Poisson mixing** | opt-in | end-to-end *timing correlation* - each relay holds cells in a pool and releases them after an exponential delay, statistically decoupling output timing from input timing | **high latency** |

Within a single stream, cell ordering is always preserved; only cells of
*different* streams are reordered - which is exactly what frustrates
correlation without corrupting any byte stream.

**What this does and does not buy you.** Fixed-size cells and multiplexing
close the *size* and *connection-shape* side channels cheaply, bringing the
default posture roughly in line with Tor. But defeating *timing* correlation
against a global passive adversary is an unsolved problem for any low-latency
network - **including Tor, which does not defend against it.** Only Poisson
mixing genuinely frustrates timing correlation, and it does so by making the
network high-latency (end-to-end delay grows with hop count × mean mix delay).
With the timing defenses left at their off-by-default settings, assume a
global passive observer can still correlate your flows. Choose the point on
that latency/anonymity curve your use case can tolerate.

## Exit Nodes

Exit nodes are not open enrollment on the shared public network.

- new exits require operator approval
- exit capacity is intentionally curated
- only run an exit if you understand the legal and operational implications

If you are contributing for the first time, run a relay node instead.

## Operator Notes

`admin_cli.py` is for the network operator only. It manages exit approval,
peer removal, and operator control paths for a registry you run or control.

Important rules:

- never commit `.env`, admin tokens, or private operator keys
- keep operator credentials outside the repo
- if you are only joining as a relay, host, or visitor, you can ignore
  `admin_cli.py`

## Project Stewardship

This repository is public and contributions are welcome, but the project is not
ownerless.

- **Obscura47** is the upstream project name
- the official shared public network refers to the operator-run infrastructure
  connected to this upstream project
- forks and derivative deployments should use their own branding and should not
  imply they are the official Obscura47 network unless explicitly authorized

If you fork the code, please make it clear whether your deployment is an
independent network, a private lab, or an unofficial variant.

For the code license, see [LICENSE](./LICENSE). For name and brand use, see
[TRADEMARKS.md](./TRADEMARKS.md).

## Configuration

All settings are environment variables. See [`.env.example`](.env.example) for
the full annotated list.

The most important ones are:

| Variable | Default | Purpose |
|---|---|---|
| `OBSCURA_PROXY_PORT` | `9047` | Local HTTP CONNECT listener |
| `OBSCURA_REGISTRY_URL` | `https://db.monmedjs.com` | Registry for the shared public network |
| `OBSCURA_GUARD_ENABLED` | `true` | Pin the first hop to a persistent guard set |
| `OBSCURA_EXIT_DENY_PRIVATE_IPS` | `true` | Block exits to RFC1918 + loopback |
| `OBSCURA_PROXY_TOKEN` | unset | Optional local proxy access token |
| `OBSCURA_MODE` | `public` | `range` enables operator observability + the agent research range (off by default) |
| `OBSCURA_MIX_JITTER_ENABLED` | `false` | Add random per-hop forward jitter |
| `OBSCURA_MIX_JITTER_MAX_MS` | `0` | Max jitter (ms) when jitter is enabled |
| `OBSCURA_COVER_ENABLED` | `false` | Emit cover-traffic "drop" cells |
| `OBSCURA_COVER_MEAN_INTERVAL_MS` | `1000` | Mean gap between cover cells |
| `OBSCURA_MIX_ENABLED` | `false` | Poisson mixing - defeats timing correlation, high latency |
| `OBSCURA_MIX_MEAN_DELAY_MS` | `200` | Mean per-hop mix delay when mixing is enabled |

See [Traffic-Analysis Resistance](#traffic-analysis-resistance) for what the
mixing knobs trade off. Persistent local state lives under `~/.obscura47/`.

## Observability and the agent research range

Two areas of the codebase sit beside the public product surface. Both are
opt-in and off by default, so the consumer network is unaffected unless an
operator turns them on (`OBSCURA_MODE=range`).

- **Operator observability.** Two separate, out-of-band telemetry planes:
  operational diagnostics (`src/utils/diag.py`, "is the network healthy?") and
  a structured research plane (`src/agent/observatory.py`, "what are hosted
  services doing?"), plus per-hop distributed trace spans (`src/utils/trace.py`)
  and immutable, replayable experiment records (`src/utils/experiment.py`).
  These are operator-only and deliberately a privacy regression, so production
  consumer use must leave them off. See
  [`docs/observability.md`](docs/observability.md).

- **Agent research range (`src/range/`).** A fully instrumented harness for
  studying how autonomous agents behave under adversarial conditions. Two ways
  to run it: an in-process simulation (score a run, compare configurations, gate
  on a safety policy, replay it, export an evidence report; agents scripted or
  model-driven), and a **live observable society** on the real overlay - agents
  trading, probing, and deceiving, policed by a full control suite (defender,
  escrow, moderator, reputation gate), investigated into case files, and
  regulated into a ship/no-ship verdict, with reputation that persists across
  runs. See [`docs/live-society.md`](docs/live-society.md) and
  [`src/range/README.md`](src/range/README.md). Run one with
  `python -m src.range society` or `python -m src.range run`.

## Building

```bash
./build_mac.sh
./build_linux.sh
build_windows.bat
```

## Tests

```bash
python -m pytest tests/ -q --ignore=tests/test_e2e_tunnel.py
```

## Contributing

Bug reports and pull requests are welcome.

If your change touches routing, hidden services, discovery, or operator flows,
please add or update tests before submitting.
