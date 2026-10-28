#!/bin/sh
# ShellGate installer for OpenWrt / ImmortalWrt. Run as root on the router.
#   sh install.sh                 download the latest release for this CPU
#   sh install.sh ./shellgate     install a binary you copied over yourself
set -e
REPO="lovexy-me/shellgate-mcp"
BIN=/usr/bin/shellgate
CONF_DIR=/etc/shellgate
CONF=$CONF_DIR/env
RAW="https://raw.githubusercontent.com/$REPO/main/openwrt/files"

fetch() { # url dest
	if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
	elif command -v uclient-fetch >/dev/null 2>&1; then uclient-fetch -q -O "$2" "$1"
	else wget -q -O "$2" "$1"; fi
}

case "$(uname -m)" in
	aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
	armv7*) TARGET=armv7-unknown-linux-musleabihf ;;
	x86_64) TARGET=x86_64-unknown-linux-musl ;;
	*) echo "Unsupported CPU: $(uname -m)"; exit 1 ;;
esac

DIR=$(cd "$(dirname "$0")" && pwd)
if [ -n "$1" ]; then
	echo "==> Installing $1"
	cp "$1" "$BIN.new"
else
	echo "==> Downloading shellgate-$TARGET"
	fetch "https://github.com/$REPO/releases/latest/download/shellgate-$TARGET" "$BIN.new"
fi
chmod 755 "$BIN.new"
"$BIN.new" --version >/dev/null || { echo "binary does not run on this device"; rm -f "$BIN.new"; exit 1; }
[ -x /etc/init.d/shellgate ] && /etc/init.d/shellgate stop 2>/dev/null || true
mv "$BIN.new" "$BIN"

if [ -f "$DIR/shellgate.init" ]; then cp "$DIR/shellgate.init" /etc/init.d/shellgate
else fetch "$RAW/shellgate.init" /etc/init.d/shellgate; fi
chmod 755 /etc/init.d/shellgate

NEW_TOKEN=""
if [ ! -f "$CONF" ]; then
	echo "==> Creating $CONF"
	mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
	[ -f "$DIR/env.example" ] && cp "$DIR/env.example" "$CONF.tmp" || fetch "$RAW/env.example" "$CONF.tmp"
	NEW_TOKEN="$(head -c 64 /dev/urandom | md5sum | cut -c1-32)$(head -c 64 /dev/urandom | md5sum | cut -c1-32)"
	sed "s|^SHELLGATE_TOKEN=.*|SHELLGATE_TOKEN=$NEW_TOKEN|" "$CONF.tmp" > "$CONF"
	rm -f "$CONF.tmp"; chmod 600 "$CONF"
else
	echo "==> Keeping existing $CONF"
fi

# keep binary, service and config across sysupgrade
for f in "$BIN" /etc/init.d/shellgate "$CONF_DIR/"; do
	grep -qxF "$f" /etc/sysupgrade.conf 2>/dev/null || echo "$f" >> /etc/sysupgrade.conf
done

/etc/init.d/shellgate enable
/etc/init.d/shellgate restart
sleep 2
HOST=$(sed -n 's/^SHELLGATE_HOST=//p' "$CONF"); PORT=$(sed -n 's/^SHELLGATE_PORT=//p' "$CONF")
if fetch "http://${HOST:-127.0.0.1}:${PORT:-8790}/health" /tmp/.sg_health 2>/dev/null; then
	echo "==> Health check OK: $(cat /tmp/.sg_health)"
else
	echo "!! Health check failed. Logs: logread -e shellgate"
fi
rm -f /tmp/.sg_health

if [ -n "$NEW_TOKEN" ]; then
	echo
	echo "Token (shown once, also stored in $CONF):"
	echo "  $NEW_TOKEN"
fi
