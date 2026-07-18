# Subsystem: implant (`implant/sliver/`)

> Authored at an architectural level (structure, control flow, build-tag layout). For
> capability internals, read the specific package. Keep documentation architectural rather
> than exploitation-focused — this is authorized-testing tooling.

## Purpose

The implant is the agent that runs on a target host and communicates with the Sliver
server's C2 listeners. It is **compiled per-engagement** by `server/generate` from a config
(which C2 endpoints, format, limits, obfuscation). It lives in its **own source tree with a
separate `implant/vendor/`**, so its dependency set and build matrix are independent of the
server/client module.

## Entrypoint & control flow — `implant/sliver/sliver.go`

- `func main()` selects mode and calls either **`beaconStartup()`** or **`sessionStartup()`**.
- **Session mode** (`sessionStartup` → `sessionMainLoop`): a persistent connection; the
  implant receives tasks and streams results in real time.
- **Beacon mode** (`beaconStartup` → `beaconMainLoop`): periodic check-ins; the implant
  connects, pulls queued tasks, returns results, and disconnects until the next interval.
- Transport selection and the connect/register loop are driven from
  `implant/sliver/transports/` (`StartBeaconLoop`, session connection setup).

## Transports — `implant/sliver/transports/`

The implant-side halves of each C2 channel (pair these with `server/c2` on the server):

| Path | Channel |
|---|---|
| `transports/mtls/` | mTLS over TCP |
| `transports/httpclient/` | HTTP(S) |
| `transports/dnsclient/` | DNS |
| `transports/wireguard/` | WireGuard |
| `transports/pivotclients/` | pivot channels (implant-to-implant) |
| `session.go`, `beacon.go`, `connection.go`, `tunnel.go` | mode loops + tunnel plumbing |
| `transports_windows.go` / `transports_generic.go` | per-OS transport wiring (build tags) |

## Handlers — `implant/sliver/handlers/`

Server tasks arrive as `sliverpb` envelopes and are dispatched through a **handler map** to
the matching function. Handlers are split by platform via build tags:

- `handlers.go` — shared/dispatch core (large: the handler map).
- `handlers_linux.go`, `handlers_windows.go`, `handlers_darwin.go`, `handlers_generic.go` —
  per-OS implementations.
- `rpc-handlers*.go` — request/response (non-tunnel) task handlers, also per-OS + a
  `-cgo`/`-generic` split.
- `tun*.go`, `tunnel_handlers/` — streaming/tunnel tasks (shell, portfwd).
- `pivot-handlers.go`, `handlers-wireguard.go`, `extensions-wasm.go`, `kill-handlers*.go`.

To find "what happens when the operator runs command X": look up X's `sliverpb` message type,
then find its entry in the handler map in `handlers*.go`.

## Capability packages (under `implant/sliver/`)

| Package | Role |
|---|---|
| `extension/` | load/run extensions (BOF/COFF, etc.) |
| `taskrunner/` | in-memory execution / injection primitives |
| `procdump/` | process memory dump |
| `ps/`, `netstat/` | process / network enumeration |
| `priv/` | privilege operations |
| `registry/` | Windows registry access |
| `service/` | Windows service operations |
| `screen/` | screenshots (`screenshot_{linux,windows,generic}.go`; generic covers darwin) |
| `mount/` | filesystem mount listing |
| `shell/` | interactive shell |
| `pivots/`, `rportfwd/`, `forwarder/`, `proxy/`, `tcpproxy/` | pivoting & port forwarding |
| `evasion/`, `spoof/` | evasion / argument spoofing |
| `syscalls/`, `winhttp/` | low-level OS/Windows plumbing |
| `cryptography/`, `encoders/` | wire crypto + encoding (mirror server side) |
| `hostuuid/`, `locale/`, `version/`, `constants/` | host/env info |
| `limits/` | execution guardrails (e.g. don't run under debugger/sandbox) |
| `netstack/` | userspace network stack (for WireGuard/tunnels) |

## Build tags & platform split

- Per-OS files use `//go:build` tags (`_windows.go`, `_linux.go`, `_darwin.go`, `_generic.go`
  naming plus explicit `//go:build` lines).
- A `-cgo` vs `-generic` split exists for handlers that need cgo (e.g. some darwin/linux paths).
- The implant is **trimmed per build**: `server/generate` selects which C2s/features compile
  in based on the implant config, so not every package is present in every produced binary.
- Because of the separate `implant/vendor/`, dependency changes here are isolated from the
  main module.

## Key files to know

- `implant/sliver/sliver.go` — entrypoint, session/beacon selection, main loops.
- `implant/sliver/transports/transports.go` + `session.go` + `beacon.go` — connect/register/task loop.
- `implant/sliver/handlers/handlers.go` — the task→handler dispatch map (start here for tasking).
- `implant/sliver/handlers/handlers_{linux,windows,darwin}.go` — platform task impls.
- `implant/sliver/extension/` + `handlers/extensions-wasm.go` — extension/BOF execution.
- `implant/sliver/limits/` — anti-analysis guardrails that can abort startup.

## Gotchas

- Don't assume a file compiles into every implant — check its build tags and whether
  `server/generate` includes its feature.
- Implant crypto/encoders must stay in lockstep with the server counterparts
  (`server/cryptography`, `util/encoders`) or sessions won't establish.
- The implant tree has its **own vendor**; run implant-side dependency operations there,
  not against the root module.
