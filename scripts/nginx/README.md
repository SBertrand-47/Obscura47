# nginx reverse-proxy config (VPS-1: registry + exit)

`db.monmedjs.com.conf` is the TLS-terminating reverse proxy that fronts the
registry on `127.0.0.1:8470`. The live copy lives at
`/etc/nginx/sites-available/db.monmedjs.com` (symlinked into `sites-enabled/`).
This file is the version-controlled source of truth - keep them in sync.

## Why it matters
The vhost proxies an **explicit list** of paths to the registry and serves the
static dashboard at `/`. Any client-facing endpoint *not* listed falls through
to `location /` (static), which answers `POST` with **405** and `GET` with the
dashboard HTML. That silently breaks registry calls. Every client-facing
registry route MUST have a matching `location` block here:

`/register` (covers `/register/verify`), `/deregister`, `/diag`, `/whoami`,
`/peers`, `/health`, `/hs/` - plus `/admin/` and `/network/` for the dashboard.

**When you add a new client-facing registry endpoint, add its `location` here too.**

## Apply changes to the live box
```bash
sudo cp scripts/nginx/db.monmedjs.com.conf /etc/nginx/sites-available/db.monmedjs.com
sudo nginx -t && sudo systemctl reload nginx
```
The `ssl_certificate*` lines are managed by Certbot and assume the
`db.monmedjs.com` Let's Encrypt cert already exists on the host.
