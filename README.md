# Obscura47

Obscura47 is a Tor-style anonymous overlay network written in Python. It lets
people route traffic through relay nodes and publish private `.obscura` hidden
services without exposing those services directly to the clearnet.

The public framing of this project is intentionally simple:

- run a local proxy
- join the network as a relay
- publish a local site or TCP service at a `.obscura` address
- optionally browse an opt-in `.obscura` directory

This README focuses on that public product surface, not every internal module
or experimental direction in the codebase.

## What You Can Do

- **Connect to the network** from the desktop app, tray app, or CLI
- **Browse through Obscura** using the local proxy
- **Open `.obscura` sites** from the built-in desktop and tray flows
- **Publish your own `.obscura` site** from a folder or local TCP service
- **Run a relay node** to contribute bandwidth
- **Apply to run an exit node** if you understand the operational risk

## Shared Public Network

The shared public network is operator-run and still intentionally small.

- Bootstrap registry: `https://db.monmedjs.com`
- Exit capacity is curated and limited
- The current public deployment includes one operator-managed exit VPS

Treat the shared public network as experimental infrastructure, not a
mass-market anonymity service.

## Quick Start

```bash
git clone https://github.com/SBertrand-47/Obscura47.git
cd Obscura47
pip install -r requirements.txt
python join_network.py
```

That opens the interactive launcher. The easiest direct commands are:

```bash
python join_network.py node
python join_network.py proxy
python join_network.py host ./site --name mysite
python join_network.py open alpha.obscura
```

For the shared public network, point `OBSCURA_REGISTRY_URL` at
`https://db.monmedjs.com`.

## Main Ways To Use It

### Desktop App

```bash
python app.py
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

Persistent local state lives under `~/.obscura47/`.

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
