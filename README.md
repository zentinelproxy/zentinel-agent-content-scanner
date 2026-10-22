<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Content scanner agent</h3>

<p align="center">Scans request bodies for malware with ClamAV before they reach the upstream, in the request body phase.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-content-scanner/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-content-scanner/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-9b4d8a?style=flat&amp;labelColor=1f161e">
  <img alt="Agent protocol v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&amp;labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/content-scanner/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For services that accept file uploads and want them checked before the upstream
stores or processes them. The agent picks the requests to scan from their method,
path and `Content-Type`, streams the body to a local ClamAV daemon (`clamd`) with the
`INSTREAM` command, and blocks the request with `403` when ClamAV reports a
signature. If `clamd` cannot be reached or returns an error, `settings.fail_action`
decides: `allow` (the default) forwards the request unscanned, `block` answers `503`.
If the agent itself is unreachable, the filter's `failure-mode` decides.

## Quick start

You need a running `clamd` (see [ClamAV](#clamav) below).

```bash
zentinel bundle install content-scanner
zentinel-content-scanner-agent --example-config > config.yaml
zentinel-content-scanner-agent --config config.yaml --socket /tmp/zentinel-content-scanner.sock
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}

agents {
    agent "content-scanner" type="custom" {
        unix-socket "/tmp/zentinel-content-scanner.sock"
        events "request_headers" "request_body"
        request-body-mode "buffer"
        max-request-body-bytes 52428800
        timeout-ms 30000
    }
}

filters {
    filter "content-scanner" {
        type "agent"
        agent "content-scanner"
        failure-mode "closed"
    }
}

routes {
    route "uploads" {
        matches { path-prefix "/upload" }
        upstream "backend"
        filters "content-scanner"
    }
}
```

Check it with the EICAR test string, which every antivirus engine detects
(this needs a Zentinel that sends request bodies to agents, see
[Zentinel versions](#zentinel-versions)):

```bash
# clean: forwarded to the upstream
echo "Hello World" | curl -X POST -H "Content-Type: application/octet-stream" --data-binary @- http://localhost:8080/upload

# EICAR: 403 Malware detected in upload
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  | curl -X POST -H "Content-Type: application/octet-stream" --data-binary @- http://localhost:8080/upload
```

## Install

### Bundle (recommended)

```bash
zentinel bundle install content-scanner
```

Downloads the release binary pinned in Zentinel's bundle lock and installs it as `zentinel-content-scanner-agent`.

### Release binaries

Tarballs for `linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are attached to each [release](https://github.com/zentinelproxy/zentinel-agent-content-scanner/releases).

### From source

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-content-scanner
```

Installs `zentinel-content-scanner-agent`. Building needs `protoc` (the agent protocol crate compiles its protobuf definitions).

### ClamAV

The agent talks to `clamd` over its Unix socket only (no TCP). On Debian and Ubuntu:

```bash
sudo apt-get install clamav-daemon
sudo systemctl start clamav-daemon
```

That package listens on `/var/run/clamav/clamd.ctl`, the agent's default. Other
distributions and Homebrew use a different socket path and need `LocalSocket` set
in `clamd.conf`; point `clamd.socket_path` at it.

## Configuration

The agent reads a YAML file and the flags below. It also accepts configuration over the
protocol (`on_configure`), but only validates it and keeps running with the file it
started with, and Zentinel 0.6.50 does not forward an `agent { config { ... } }`
block anyway, so set everything in the file.

| Option | Default | Meaning |
|---|---|---|
| `-c`, `--config` | `config.yaml` if it exists, else built-in defaults | Path to the YAML configuration file. Env `CONTENT_SCANNER_CONFIG`. A file named with this flag must exist. |
| `-s`, `--socket` | `/tmp/zentinel-content-scanner.sock` | Unix socket to serve agent protocol v2 on. Env `AGENT_SOCKET`. |
| `-g`, `--grpc-address` | unset | Serve gRPC on this address (e.g. `127.0.0.1:50051`) instead of the Unix socket; the proxy then connects with `grpc "http://..."`. Env `CONTENT_SCANNER_GRPC_ADDRESS`. |
| `--clamd-socket` | | Overrides `clamd.socket_path`. Env `CLAMD_SOCKET`. |
| `--example-config` | | Print an example configuration and exit. |
| `--validate` | | Load and validate the configuration, then exit. |

Up to 0.4.0 (whose binary was built from 0.2.0 code) the agent served gRPC
only, on `0.0.0.0:50051` by default, and would not start without `config.yaml`.

Configuration file:

```yaml
settings:
  fail_action: block          # block uploads while clamd is down

body:
  max_size: 52428800
  content_types:
    - "application/octet-stream"
    - "application/pdf"
    - "application/vnd.openxmlformats-officedocument.*"
    - "multipart/form-data"

clamd:
  socket_path: "/var/run/clamav/clamd.ctl"

skip_paths:
  - "/health"
```

| Option | Default | Meaning |
|---|---|---|
| `settings.enabled` | `true` | Master switch. `false` allows every request unscanned. |
| `settings.fail_action` | `allow` | What to do when `clamd` is unreachable, times out or returns an error: `allow` forwards the request, `block` answers `503`. |
| `settings.log_detections` | `true` | Log each detection at `info`. |
| `settings.log_clean` | `false` | Log clean scans at `debug`. |
| `body.max_size` | `52428800` | Bodies larger than this many bytes are forwarded unscanned (`x-scan-skipped: size-exceeded`). |
| `body.content_types` | `[]` (all) | Content types to scan. Exact (`application/pdf`), wildcard subtype (`application/*`) or prefix glob (`application/vnd.*`); parameters such as `; charset=` are ignored. A request without a `Content-Type` header is never scanned. |
| `clamd.enabled` | `true` | `false` allows every request unscanned. |
| `clamd.socket_path` | `/var/run/clamav/clamd.ctl` | Path of the `clamd` Unix socket. |
| `clamd.timeout_ms` | `30000` | Timeout for each socket operation with `clamd`, in milliseconds. |
| `clamd.chunk_size` | `65536` | Size of the chunks streamed to `clamd`, in bytes. |
| `skip_paths` | `[]` | Paths never scanned: an exact match, or the path followed by `/`. Matched against the request URI, so a query string defeats an exact match. |
| `scan_methods` | `[]` (`POST`, `PUT`, `PATCH`) | HTTP methods to scan, case-insensitive. |

Values can reference environment variables as `${VAR_NAME}`; an unset variable
expands to an empty string.

Full reference: <https://registry.zentinelproxy.io/content-scanner/>

## How it works

- On `request_headers` the agent decides whether the request is a candidate
  (enabled, method, `skip_paths`, `Content-Type`). Non-candidates are allowed at once.
- On the first `request_body` chunk it sends the body to `clamd` and decides.
  Only that first chunk is scanned, so keep `request-body-mode "buffer"` (the
  default), which delivers the whole body as one chunk, and set the proxy's
  `max-request-body-bytes` to at least `body.max_size`.
- Headers it adds to the request forwarded upstream: `x-content-scanned: true` and
  `x-scan-time-ms` after a clean scan, `x-scan-skipped` (`size-exceeded`,
  `content-type-excluded`, `clamd-unavailable`) when it did not scan.
- Headers on its block responses: `x-malware-detected: true`, `x-malware-name` and
  `x-scan-time-ms` on the `403`; `x-scan-error: clamd-unavailable` on the `503`.
- Audit tags: `content-scanner:clean`, `content-scanner:malware:<name>`,
  `content-scanner:size-exceeded`, `content-scanner:clamd-unavailable:allowed|blocked`.
- Metrics reported over the protocol: `content_scanner_requests_total`,
  `content_scanner_requests_blocked_total`, `content_scanner_scan_errors_total`,
  `content_scanner_bytes_scanned_total` and the gauge
  `content_scanner_in_flight_requests`. Health turns `degraded` while `clamd` is
  unreachable.

### Zentinel versions

Every scan decision is made in the request-body phase, so what the agent can
do depends on the proxy:

- Zentinel 26.10_7 (0.6.50) sends request bodies to agents only when the
  config has a `waf` block, and rejects a `waf` block whose mode is not `off`.
  In practice the agent sees headers only: it marks excluded content types
  (`x-scan-skipped: content-type-excluded`) but scans nothing.
- Zentinel `main` (after zentinelproxy/zentinel#609) sends the body and answers
  `403` for an infected upload, but has already opened the upstream request,
  so the upstream receives the request headers (not the body), and the headers
  the agent sets after a clean scan (`x-content-scanned`, `x-scan-time-ms`) do
  not reach it.

## Development

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Needs stable Rust (CI uses `dtolnay/rust-toolchain@stable`) and `protoc` (CI
installs `protobuf-compiler`). The tests do not need a running `clamd`.

`scripts/smoke-test.sh` runs the release binary behind a real Zentinel with
the shared harness (`agent-smoke/smoke.py` from
[zentinelproxy/.github](https://github.com/zentinelproxy/.github)) and
`scripts/smoke/config.yaml`. It uses the `clamd` at `CLAMD_SOCKET` if set,
otherwise `scripts/smoke/fake-clamd.py`, which recognises only EICAR. It
checks that an ordinary request is forwarded unmarked, a `text/plain` upload
is forwarded with `x-scan-skipped: content-type-excluded`, a clean upload is
forwarded, and that stopping the agent changes the answer. CI runs it on
every push; a release runs it on every platform before anything is
published. The EICAR case runs only with `SMOKE_BODY_CASES=1`: no Zentinel
release passes it yet (see [Zentinel versions](#zentinel-versions)).

```bash
AGENT_SMOKE=../.github/agent-smoke/smoke.py scripts/smoke-test.sh target/release/zentinel-content-scanner-agent ./zentinel
```

## Related

- [Registry page](https://registry.zentinelproxy.io/content-scanner/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

MIT, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
