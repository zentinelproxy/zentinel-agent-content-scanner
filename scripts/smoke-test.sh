#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary> [harness args...]]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request. Extra
# arguments go to the harness (e.g. `--transport grpc`).
#
# clamd: with CLAMD_SOCKET pointing at a running clamd (the release workflow
# starts one on Linux when the ClamAV signature download works) that one is
# used; otherwise scripts/smoke/fake-clamd.py stands in, which recognises
# only the EICAR test signature.
#
# With scripts/smoke/config.yaml (scan application/zip and
# application/octet-stream uploads):
#   * the v2 handshake works and an ordinary GET is forwarded (200) without
#     being marked;
#   * a text/plain upload is forwarded with X-Scan-Skipped:
#     content-type-excluded, the agent's request-headers decision;
#   * a clean application/zip upload is forwarded (200);
#   * with the agent stopped the ordinary request is refused.
#
# Body cases (SMOKE_BODY_CASES=1): an upload carrying the EICAR test
# signature gets 403 and never reaches the upstream. Off by default, because
# no Zentinel release passes it yet: 26.10_7 sends request bodies to agents
# only when the config has a `waf` block (which the harness does not write),
# and Zentinel main (zentinelproxy/zentinel#609) sends the body and answers
# 403 but has already opened the upstream request, so the upstream sees the
# request headers. Turn it on once a Zentinel release holds the upstream
# request until the body agents have decided.

set -euo pipefail

if [ $# -ge 2 ]; then AGENT_BIN=$1 ZENTINEL_BIN=$2; shift 2; fi
AGENT_BIN=${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}
ZENTINEL_BIN=${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}
HERE="$(cd "$(dirname "$0")" && pwd)"

# Unix socket paths are limited to ~104 bytes, and macOS's $TMPDIR is long.
work=$(mktemp -d "${SMOKE_SOCKET_DIR:-/tmp}/cs-smoke.XXXXXX")
fake_pid=
cleanup() {
    if [ -n "$fake_pid" ]; then kill "$fake_pid" 2>/dev/null || true; fi
    rm -rf "$work"
}
trap cleanup EXIT

if [ -n "${CLAMD_SOCKET:-}" ]; then
    clamd_socket=$CLAMD_SOCKET
    echo "Using clamd at $clamd_socket"
else
    clamd_socket=$work/clamd.sock
    python3 "$HERE/smoke/fake-clamd.py" "$clamd_socket" &
    fake_pid=$!
    for _ in $(seq 50); do [ -S "$clamd_socket" ] && break; sleep 0.1; done
    [ -S "$clamd_socket" ] || { echo "fake clamd did not start" >&2; exit 1; }
    echo "No CLAMD_SOCKET: using the stand-in clamd (scripts/smoke/fake-clamd.py)"
fi

# The EICAR test file is assembled here so that no file in the repository
# carries the signature.
python3 - "$work/cases.json" "${SMOKE_BODY_CASES:-0}" <<'PY'
import json, sys
eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
cases = [
    {"name": "text/plain upload not scanned, marked", "method": "POST", "path": "/upload",
     "headers": {"Content-Type": "text/plain"}, "body": "some notes", "expect": 200,
     "upstream_headers": {"X-Scan-Skipped": "content-type-excluded"}},
    {"name": "clean zip upload forwarded", "method": "POST", "path": "/upload",
     "headers": {"Content-Type": "application/zip"}, "body": "PK harmless bytes", "expect": 200},
]
if sys.argv[2] == "1":
    cases.append({"name": "EICAR upload blocked", "method": "POST", "path": "/upload",
                  "headers": {"Content-Type": "application/zip"}, "body": eicar, "expect": 403})
json.dump(cases, open(sys.argv[1], "w"))
PY

python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name content-scanner \
    --events request_headers,request_body \
    --agent-arg=--config --agent-arg "$HERE/smoke/config.yaml" \
    --agent-arg=--clamd-socket --agent-arg "$clamd_socket" \
    --clean '{"name": "ordinary GET", "path": "/smoke", "upstream_lacks_headers": ["X-Scan-Skipped", "X-Content-Scanned"]}' \
    --cases "$work/cases.json" \
    "$@"
