#!/usr/bin/env bash
# ShellGate installer for Linux / WSL2. Run from the repository root as your normal user (not root).
set -euo pipefail

APP_DIR="${HOME}/.local/share/shellgate"
CFG_DIR="${HOME}/.config/shellgate"
ENV_FILE="${CFG_DIR}/env"
UNIT_DIR="${HOME}/.config/systemd/user"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$(id -u)" = "0" ]; then
  echo "Please run as your normal user, not root." >&2; exit 1
fi

command -v python3 >/dev/null || { echo "python3 not found: sudo apt install -y python3 python3-venv" >&2; exit 1; }
python3 - <<'PY' || { echo "Python 3.10+ is required." >&2; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY
python3 -c "import venv, ensurepip" 2>/dev/null || { echo "python3-venv missing: sudo apt install -y python3-venv" >&2; exit 1; }

echo "==> Installing into ${APP_DIR}/venv"
mkdir -p "${APP_DIR}"
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install -q --upgrade pip
"${APP_DIR}/venv/bin/pip" install -q "${REPO_DIR}"
command -v rg >/dev/null || echo "    tip: 'sudo apt install -y ripgrep' makes search_files much faster"

NEW_TOKEN=""
if [ ! -f "${ENV_FILE}" ]; then
  echo "==> Creating ${ENV_FILE}"
  mkdir -p "${CFG_DIR}"; chmod 700 "${CFG_DIR}"
  NEW_TOKEN="$("${APP_DIR}/venv/bin/python" -c 'import secrets;print(secrets.token_urlsafe(40))')"
  umask 077
  sed "s|^SHELLGATE_TOKEN=.*|SHELLGATE_TOKEN=${NEW_TOKEN}|" "${REPO_DIR}/deploy/env.example" > "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
else
  echo "==> Keeping existing ${ENV_FILE}"
fi

if systemctl --user show-environment >/dev/null 2>&1; then
  echo "==> Installing systemd user service"
  mkdir -p "${UNIT_DIR}"
  sed "s|@APP_DIR@|${APP_DIR}|g; s|@ENV_FILE@|${ENV_FILE}|g" "${REPO_DIR}/deploy/shellgate.service" > "${UNIT_DIR}/shellgate.service"
  systemctl --user daemon-reload
  systemctl --user enable --now shellgate.service
  systemctl --user restart shellgate.service
  if ! loginctl show-user "$USER" 2>/dev/null | grep -q "Linger=yes"; then
    echo "    To keep it running without an open terminal: sudo loginctl enable-linger $USER"
  fi
else
  echo "!! systemd is not available. In WSL, add to /etc/wsl.conf:"
  echo "     [boot]"
  echo "     systemd=true"
  echo "   then run 'wsl --shutdown' in Windows and re-run this script."
  echo "   Or start it manually: ${APP_DIR}/venv/bin/shellgate --env-file ${ENV_FILE}"
fi

PORT="$(grep -E '^SHELLGATE_PORT=' "${ENV_FILE}" | cut -d= -f2)"; PORT="${PORT:-8790}"
sleep 2
if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
  echo "==> Health check OK: http://127.0.0.1:${PORT}/health"
else
  echo "!! Health check failed. Logs: journalctl --user -u shellgate -n 50"
fi

echo
echo "Next: point a Cloudflare Tunnel hostname at http://127.0.0.1:${PORT}"
echo "      (see deploy/cloudflared-ingress.example.yml), then register https://<hostname>/mcp"
echo "      in your MCP client with header  Authorization: Bearer <token>"
if [ -n "${NEW_TOKEN}" ]; then
  echo
  echo "Your token (shown once, also stored in ${ENV_FILE}):"
  echo "  ${NEW_TOKEN}"
fi
