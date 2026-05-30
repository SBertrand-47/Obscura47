#!/usr/bin/env bash
# Obscura47 - shared setup helpers, sourced by vps-setup.sh / vps-node-setup.sh.
#
# Design notes:
#  * RUN-IN-PLACE: callers derive APP_DIR from the script's own location
#    (the checkout you ran it from), so there is never a second clone under a
#    hardcoded path to drift out of sync. See oc_app_dir().
#  * Helpers are idempotent and safe to re-run.
#  * No global state beyond the functions; callers pass what they need.

# --- output -----------------------------------------------------------------
oc_c_reset=$'\033[0m'; oc_c_grn=$'\033[32m'; oc_c_ylw=$'\033[33m'; oc_c_red=$'\033[31m'; oc_c_dim=$'\033[2m'
oc_log()  { printf '%s[+]%s %s\n' "$oc_c_grn" "$oc_c_reset" "$*"; }
oc_step() { printf '%s[*]%s %s\n' "$oc_c_dim" "$oc_c_reset" "$*"; }
oc_warn() { printf '%s[!]%s %s\n' "$oc_c_ylw" "$oc_c_reset" "$*" >&2; }
oc_err()  { printf '%s[x]%s %s\n' "$oc_c_red" "$oc_c_reset" "$*" >&2; }
oc_die()  { oc_err "$*"; exit 1; }

# --- run-in-place path derivation -------------------------------------------
# Echo the repo root given the *calling script's* path. Scripts live in
# <repo>/scripts, so the root is one level up. Resolves symlinks.
oc_app_dir() {
    local script_path="$1"
    local script_dir
    script_dir="$(cd "$(dirname "$(readlink -f "$script_path")")" && pwd)"
    cd "$script_dir/.." && pwd
}

oc_require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        oc_die "Run as root (or with sudo): sudo bash $1"
    fi
}

# --- prompts (guided, with defaults; auto-accept when non-interactive) ------
# OBSCURA_ASSUME_YES=1 or a non-tty stdin -> take the default silently.
oc_ask() {  # oc_ask "Prompt" "default" -> echoes chosen value
    local prompt="$1" default="$2" ans=""
    if [ "${OBSCURA_ASSUME_YES:-0}" = "1" ] || [ ! -t 0 ]; then
        echo "$default"; return
    fi
    read -r -p "  $prompt [$default]: " ans </dev/tty || true
    echo "${ans:-$default}"
}

oc_confirm() {  # oc_confirm "Question" (default yes) -> returns 0/1
    local prompt="$1" ans=""
    if [ "${OBSCURA_ASSUME_YES:-0}" = "1" ] || [ ! -t 0 ]; then return 0; fi
    read -r -p "  $prompt [Y/n]: " ans </dev/tty || true
    case "${ans:-y}" in [Nn]*) return 1;; *) return 0;; esac
}

# --- secrets ----------------------------------------------------------------
oc_gen_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

# --- public IP detection ----------------------------------------------------
# Best-effort IPv4. Tries the registry's /whoami first (authoritative: it's
# what peers will see), then public echo services, then local interfaces.
oc_detect_public_ip() {
    local registry_url="${1:-}" ip=""
    if [ -n "$registry_url" ]; then
        ip="$(curl -4 -fsS --max-time 5 "${registry_url%/}/whoami" 2>/dev/null \
              | sed -n 's/.*"ip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        case "$ip" in *:*) ip="";; esac   # ignore IPv6 from /whoami
    fi
    [ -z "$ip" ] && ip="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    [ -z "$ip" ] && ip="$(curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
    [ -z "$ip" ] && ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "$ip"
}

# --- firewall ---------------------------------------------------------------
# Open inbound TCP on the given ports using whatever firewall is present.
# Idempotent; prints what it did. Mirrors peer_health._firewall_open_plan.
oc_open_firewall() {  # oc_open_firewall 8470 6000 6001
    local opened="" tool=""
    if command -v ufw >/dev/null 2>&1 && ufw status >/dev/null 2>&1; then
        tool=ufw
        for p in "$@"; do ufw allow "$p/tcp" >/dev/null 2>&1 && opened="$opened $p"; done
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        tool=firewalld
        for p in "$@"; do
            firewall-cmd --permanent --add-port="$p/tcp" >/dev/null 2>&1 && opened="$opened $p"
        done
        firewall-cmd --reload >/dev/null 2>&1 || true
    elif command -v iptables >/dev/null 2>&1; then
        tool=iptables
        for p in "$@"; do
            iptables -C INPUT -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1 \
                || iptables -I INPUT -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1
            opened="$opened $p"
        done
        oc_warn "iptables rules are not persisted across reboot; install iptables-persistent to keep them."
    else
        oc_warn "No supported firewall tool (ufw/firewall-cmd/iptables) found - open ports [$*] manually."
        return 1
    fi
    oc_log "Firewall ($tool): opened TCP$opened"
}

# --- service user -----------------------------------------------------------
# Decide which user the service runs as. Prefers the hardened low-privilege
# 'obscura' system user; falls back to the checkout owner when the code isn't
# reachable by 'obscura' (e.g. cloned under a 0700 home like /root). Echoes
# "USER GROUP". The service only needs *read* on APP_DIR (standard 755/644
# clone perms suffice), so APP_DIR is never chown'd - that keeps `git pull`
# working for the human owner and avoids dubious-ownership errors.
oc_pick_run_user() {  # oc_pick_run_user APP_DIR DATA_DIR
    local app_dir="$1" data_dir="$2"
    local sysuser="obscura"
    if ! id "$sysuser" >/dev/null 2>&1; then
        useradd --system --shell /usr/sbin/nologin --home-dir "$data_dir" "$sysuser" \
            && oc_step "Created system user: $sysuser" >&2
    fi
    if sudo -u "$sysuser" test -r "$app_dir/server.py" 2>/dev/null \
       && sudo -u "$sysuser" test -x "$app_dir/venv/bin/python" 2>/dev/null; then
        echo "$sysuser $sysuser"
    else
        local owner group
        owner="$(stat -c '%U' "$app_dir")"; group="$(stat -c '%G' "$app_dir")"
        oc_warn "'$sysuser' can't read $app_dir (likely a 0700 home). Service will run as '$owner'." >&2
        oc_warn "For the hardened low-privilege setup, clone to /opt/obscura47 or /srv/obscura47." >&2
        echo "$owner $group"
    fi
}

# --- venv -------------------------------------------------------------------
oc_setup_venv() {  # oc_setup_venv APP_DIR
    local app_dir="$1"
    if [ ! -d "$app_dir/venv" ]; then
        python3 -m venv "$app_dir/venv" || oc_die "python3 venv creation failed (is python3-venv installed?)"
        oc_log "Created virtualenv"
    fi
    "$app_dir/venv/bin/pip" install --quiet --upgrade pip
    "$app_dir/venv/bin/pip" install --quiet -r "$app_dir/requirements.txt"
    oc_log "Dependencies installed"
}

# --- systemd unit rendering -------------------------------------------------
# Render a .template (with __TOKEN__ placeholders) to /etc/systemd/system.
oc_render_unit() {  # oc_render_unit TEMPLATE DEST_NAME APP_DIR RUN_USER RUN_GROUP DATA_DIR EXEC
    local tmpl="$1" dest_name="$2" app_dir="$3" run_user="$4" run_group="$5" data_dir="$6" exec_cmd="$7"
    [ -f "$tmpl" ] || oc_die "unit template not found: $tmpl"
    sed -e "s#__APP_DIR__#${app_dir}#g" \
        -e "s#__RUN_USER__#${run_user}#g" \
        -e "s#__RUN_GROUP__#${run_group}#g" \
        -e "s#__DATA_DIR__#${data_dir}#g" \
        -e "s#__EXEC__#${exec_cmd}#g" \
        "$tmpl" > "/etc/systemd/system/${dest_name}"
    systemctl daemon-reload
    oc_log "Installed /etc/systemd/system/${dest_name} (User=${run_user}, WorkingDirectory=${app_dir})"
}

# --- post-start network verification ----------------------------------------
# Reuses join_network.py diagnose (registry/path reachability) and, for a
# node/exit, the registry's external ws_port verdict via peer_health.
oc_verify() {  # oc_verify APP_DIR ROLE WS_PORT
    local app_dir="$1" role="${2:-}" ws_port="${3:-}"
    local py="$app_dir/venv/bin/python"
    oc_step "Running network diagnostics (registry reachability)..."
    "$py" "$app_dir/join_network.py" diagnose 2>/dev/null || oc_warn "diagnose run failed"
    if [ -n "$role" ] && [ -n "$ws_port" ]; then
        oc_step "Checking that your $role ws_port ($ws_port) is reachable from the network..."
        "$py" - "$role" "$ws_port" <<'PY' || true
import sys
from src.core import peer_health, internet_discovery
role, ws_port = sys.argv[1], int(sys.argv[2])
try:
    host = internet_discovery.learn_public_ip()
except Exception:
    host = None
host = host or internet_discovery._my_public_ip
v = peer_health.diagnose_ws_reachability(role, host or "", ws_port)
ok = v.get("reachable")
mark = "OK" if ok else "UNREACHABLE"
print(f"  ws_port verdict: {mark} (source={v.get('source')}) - {v.get('detail')}")
if not ok and v.get("fix_command"):
    print(f"  Fix: {v['fix_command']}  (or set OBSCURA_AUTO_OPEN_PORTS=1)")
PY
    fi
}
