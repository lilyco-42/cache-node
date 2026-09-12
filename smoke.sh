#!/usr/bin/env bash
# cache-node 冒烟测试 —— 在任何平台对任何 cache-node 实例跑完整验收。
# 用法: BASE=http://192.168.10.165:9910 bash smoke.sh   （BASE 默认本机 9910）
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:9910}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
code() { curl -s -m 8 -o "$T/body" -w '%{http_code}' "$@"; }

echo "== healthz =="
curl -s -m 8 "$BASE/healthz" | grep -q cache-node || fail "healthz"

echo "== PUT create (201) =="
printf "smoke payload %s\n" "$(date +%s)" > "$T/p"
H=$(sha256sum "$T/p" | cut -d' ' -f1)
[ "$(code -X PUT --data-binary @"$T/p" "$BASE/cache/$H")" = 201 ] || fail "create"

echo "== PUT dedup (200) =="
[ "$(code -X PUT --data-binary @"$T/p" "$BASE/cache/$H")" = 200 ] || fail "dedup"

echo "== GET roundtrip =="
[ "$(code "$BASE/cache/$H")" = 200 ] || fail "get"
cmp -s "$T/p" "$T/body" || fail "roundtrip differs"

echo "== tamper reject (400) =="
echo evil > "$T/e"
[ "$(code -X PUT --data-binary @"$T/e" "$BASE/cache/$H")" = 400 ] || fail "tamper accepted!"

echo "== 404 =="
[ "$(code "$BASE/cache/$(printf 'a%.0s' {1..64})")" = 404 ] || fail "404"

echo "ALL GREEN @ $BASE"
