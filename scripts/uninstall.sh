#!/usr/bin/env bash
# Removes the ShellGate service and virtualenv. Keeps config and audit log unless --purge.
set -euo pipefail
systemctl --user disable --now shellgate.service 2>/dev/null || true
rm -f "${HOME}/.config/systemd/user/shellgate.service"
systemctl --user daemon-reload 2>/dev/null || true
rm -rf "${HOME}/.local/share/shellgate"
if [ "${1:-}" = "--purge" ]; then
  rm -rf "${HOME}/.config/shellgate" "${HOME}/.local/state/shellgate"
  echo "Removed service, program, config and audit log."
else
  echo "Removed service and program. Kept ~/.config/shellgate and ~/.local/state/shellgate (use --purge to delete)."
fi
