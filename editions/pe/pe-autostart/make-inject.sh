#!/bin/sh
# make-inject.sh <shellgate.exe> [out.7z]
# Builds the Ventoy injection archive (put it at <stick>/ventoy/shellgate-inject.7z and add to ventoy.json:
#   "injection": [{ "parent": "/ISO", "archive": "/ventoy/shellgate-inject.7z" }] ).
# The archive holds only VentoyAutoRun.bat and shellgate\shellgate.exe: NO token. The token lives in
# <stick>/shellgate/shellgate.env, written on your own computer with `shellgate --init-config`.
set -eu
exe=${1:?usage: make-inject.sh <shellgate.exe> [out.7z]}
out=${2:-shellgate-inject.7z}
here=$(cd "$(dirname "$0")" && pwd)
z=$(command -v 7zz || command -v 7z || command -v 7za || true)
[ -n "$z" ] || { echo "need 7-Zip (7zz / 7z / 7za) on PATH" >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -r "$tmp"' EXIT
mkdir -p "$tmp/shellgate"
cp "$here/ventoy-inject/VentoyAutoRun.bat" "$tmp/"
cp "$exe" "$tmp/shellgate/shellgate.exe"
if grep -a -i -E '^(SHELLGATE_)?(token|tunnel_token)=' "$tmp/VentoyAutoRun.bat" >/dev/null; then
  echo "refusing: a token line is in VentoyAutoRun.bat" >&2; exit 1
fi
case "$out" in /*) dst=$out ;; *) dst=$PWD/$out ;; esac
rm -f "$dst"
(cd "$tmp" && "$z" a -t7z -bso0 -bsp0 "$dst" VentoyAutoRun.bat shellgate/shellgate.exe)
echo "wrote $dst"
