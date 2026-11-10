#!/usr/bin/env bash
# Emulator end-to-end test, run by android.yml (the emulator runner executes each script line
# in its own shell, so the whole test lives here).
set -euxo pipefail
P=io.shellgate.app
adb install -r dist/test-debug.apk
adb shell pm grant $P android.permission.POST_NOTIFICATIONS || true
adb shell am start -n $P/.MainActivity
for i in $(seq 1 30); do adb shell run-as $P test -s files/logs/admin.key && break; sleep 1; done
adb forward tcp:18790 tcp:8790
adb forward tcp:18791 tcp:8791
curl -sf http://127.0.0.1:18790/health; echo
adb shell run-as $P cat files/logs/shellgate.log | sed -E 's/k=[0-9a-f]+/k=<key>/' | tail -20

TOKEN=$(adb shell run-as $P cat files/shellgate.env | tr -d '\r' | sed -n 's/^\(SHELLGATE_\)\{0,1\}[Tt][Oo][Kk][Ee][Nn]=//p' | tail -1)
test ${#TOKEN} -ge 32
KEY=$(adb shell run-as $P cat files/logs/admin.key | tr -d '\r')
curl -sf -H "x-admin-key: $KEY" http://127.0.0.1:18791/api/status | head -c 600; echo
# admin page refuses requests without the key
test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18791/api/status)" != 200

mcp() {
  curl -sf -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
    http://127.0.0.1:18790/mcp \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"
  echo
}
# MCP without the token is refused
test "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18790/mcp -d '{}')" = 401
out=$(mcp run_command '{"command":"id; uname -m; getprop ro.build.version.release; echo HOME=$HOME"}'); echo "$out"
echo "$out" | grep -q 'u0_a'
mcp connection_info '{}'
mcp lan_scan '{"targets":"10.0.2.2-3","ports":"53,5037"}'
out=$(mcp http_request '{"url":"https://www.cloudflare.com/cdn-cgi/trace","max_bytes":200}'); echo "$out"
echo "$out" | grep -q 'fl='

# cloudflared runs on Android and reaches Cloudflare: quick tunnel to the MCP port
LIB=$(adb shell pm dump $P | tr -d '\r' | sed -n 's/^ *legacyNativeLibraryDir=//p' | head -1)/x86_64
adb shell run-as $P "$LIB/libcloudflared.so" --version
adb shell "run-as $P sh -c 'cd files && nohup $LIB/libcloudflared.so tunnel --no-autoupdate --url http://127.0.0.1:8790 > logs/quick.log 2>&1 &'"
URL=
for i in $(seq 1 30); do
  URL=$(adb shell run-as $P cat files/logs/quick.log | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | head -1 || true)
  [ -n "$URL" ] && break; sleep 2
done
adb shell run-as $P cat files/logs/quick.log | tail -12
test -n "$URL"
ok=
for i in $(seq 1 20); do curl -sf "$URL/health" && { ok=1; break; }; sleep 3; done
test -n "$ok"; echo; echo "quick tunnel from Android works"
# through the tunnel, MCP still needs the token
test "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL/mcp" -d '{}')" = 401

# settings + restart from the admin API: the process re-execs in place and comes back
curl -sf -X POST -H "x-admin-key: $KEY" http://127.0.0.1:18791/api/restart; echo
sleep 4
curl -sf http://127.0.0.1:18790/health; echo
# service survives the activity being closed
adb shell am force-stop com.android.settings || true
adb shell input keyevent 3
sleep 3
curl -sf http://127.0.0.1:18790/health; echo
echo ALL OK
