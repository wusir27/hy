#!/usr/bin/env bash
# P6.D1 Darwin utun checks for GitHub macos-14 (passwordless sudo, no utun10).
set -euo pipefail

HY="${HY:-$(pwd)/target/release/hy}"
test -x "$HY"

WORK="$(mktemp -d /tmp/hy-p6d1.XXXXXX)"
cd "$WORK"
SERVER_LOG="$WORK/server.log"
CLIENT_LOG="$WORK/client.log"
CLIENT_PID=""
SERVER_PID=""

cleanup() {
  set +e
  if [[ -n "${CLIENT_PID}" ]]; then
    sudo -n kill "$CLIENT_PID" 2>/dev/null
    kill "$CLIENT_PID" 2>/dev/null
    wait "$CLIENT_PID" 2>/dev/null
  fi
  if [[ -n "${SERVER_PID}" ]]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  pkill -f "$HY client" 2>/dev/null
  pkill -f "$HY server" 2>/dev/null
  sleep 1
  if ifconfig utun123 >/dev/null 2>&1; then
    echo "WARN leftover utun123" >&2
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

cat > server.yaml <<'Y'
listen: 127.0.0.1:18443
tls:
  cert: cert.pem
  key: key.pem
auth:
  type: password
  password: test
Y

cat > client-c.yaml <<'Y'
server: 127.0.0.1:18443
auth: test
tls: { sni: localhost, insecure: true }
tun:
  name: utun123
Y

cat > client-e.yaml <<'Y'
server: 127.0.0.1:18443
auth: test
tls: { sni: localhost, insecure: true }
tun:
  name: utun123
  route:
    ipv4Exclude: ["127.0.0.0/8"]
Y

cat > client-d.yaml <<'Y'
server: 127.0.0.1:18443
auth: test
tls: { sni: localhost, insecure: true }
tun:
  name: utun123
  route:
    ipv4: ["1.1.1.1/32"]
Y

cat > empty.yaml <<'Y'
server: 127.0.0.1:1
auth: x
tls: { insecure: true }
tun: { name: "" }
Y

cat > bad-utun.yaml <<'Y'
server: 127.0.0.1:1
auth: x
tls: { insecure: true }
tun: { name: utun }
Y

cat > bad-hy0.yaml <<'Y'
server: 127.0.0.1:1
auth: x
tls: { insecure: true }
tun: { name: hy0 }
Y

expect_fail() {
  local cfg="$1" needle="$2" label="$3"
  set +e
  out="$("$HY" client -c "$cfg" 2>&1)"
  rc=$?
  set -e
  echo "$out"
  test "$rc" -ne 0
  echo "$out" | grep -q "$needle"
  echo "OK $label"
}

expect_fail empty.yaml "name is empty" "empty name"
expect_fail bad-utun.yaml "bad tun name" "utun"
expect_fail bad-hy0.yaml "bad tun name" "hy0"

"$HY" server -c server.yaml >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  grep -q "server listening" "$SERVER_LOG" && break
  sleep 0.2
done
grep -q "server listening" "$SERVER_LOG"

set +e
out="$("$HY" client -c client-c.yaml 2>&1)"
rc=$?
set -e
echo "$out"
test "$rc" -ne 0
echo "$out" | grep -qi "failed to create tun"
if ifconfig utun123 >/dev/null 2>&1; then
  echo "leftover utun123 after no-root"
  exit 1
fi
echo "OK no-root create fails, no leftover"

default_if() { route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}'; }
BEFORE="$(default_if)"

start_client() {
  local cfg="$1"
  : >"$CLIENT_LOG"
  sudo -n "$HY" client -c "$cfg" >"$CLIENT_LOG" 2>&1 &
  CLIENT_PID=$!
  for _ in $(seq 1 40); do
    if grep -q "TUN listening" "$CLIENT_LOG"; then
      return 0
    fi
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
      echo "client died:"
      cat "$CLIENT_LOG"
      return 1
    fi
    sleep 0.25
  done
  echo "no TUN listening:"
  cat "$CLIENT_LOG"
  return 1
}

stop_client() {
  if [[ -n "${CLIENT_PID}" ]]; then
    sudo -n kill "$CLIENT_PID" 2>/dev/null || true
    wait "$CLIENT_PID" 2>/dev/null || true
    CLIENT_PID=""
  fi
  for _ in $(seq 1 20); do
    ifconfig utun123 >/dev/null 2>&1 || return 0
    sleep 0.2
  done
  echo "utun123 still up after stop"
  ifconfig utun123 || true
  return 1
}

start_client client-c.yaml
ifconfig utun123
ifconfig utun123 | grep -q "100.100.100.101"
ifconfig utun123 | grep -qi "2001::ffff:ffff:ffff:fff1"
AFTER="$(default_if)"
test "$BEFORE" = "$AFTER"
stop_client
if ifconfig utun123 >/dev/null 2>&1; then
  echo "C leftover utun123"
  exit 1
fi
echo "OK C: utun123 up with v4+official v6, default route unchanged, gone after exit"

start_client client-e.yaml
AFTER="$(default_if)"
test "$BEFORE" = "$AFTER"
rts="$(netstat -rn -f inet | awk '/utun123/{print $1}')"
echo "$rts"
echo "$rts" | grep -Eq '(^|[[:space:]])1/8([[:space:]]|$)'
echo "$rts" | grep -Eq '(^|[[:space:]])2/7([[:space:]]|$)'
echo "$rts" | grep -Eq '(^|[[:space:]])4/6([[:space:]]|$)'
echo "$rts" | grep -Eq '(^|[[:space:]])8/5([[:space:]]|$)'
echo "$rts" | grep -Eq '(^|[[:space:]])16/4([[:space:]]|$)'
echo "$rts" | grep -Eq '(^|[[:space:]])32/3([[:space:]]|$)'
echo "$rts" | grep -Eq '(^|[[:space:]])64/2([[:space:]]|$)'
echo "$rts" | grep -Eq '128(\.0\.0\.0)?/1'
stop_client
echo "OK E: Darwin 8 prefixes on utun123, default route unchanged"

set +e
if start_client client-d.yaml; then
  if curl -sS --connect-timeout 8 --max-time 12 -o /dev/null -w "%{http_code}" https://1.1.1.1 | grep -qE '^[0-9]{3}$'; then
    echo "OK D optional TCP via utun to 1.1.1.1"
  else
    echo "WARN D optional TCP did not complete (not a gate)"
  fi
  stop_client
else
  echo "WARN D optional client did not start (not a gate)"
fi
set -e

echo "P6.D1 darwin-utun checks passed"
