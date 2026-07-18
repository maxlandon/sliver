# Sliver Protobuf / RPC Contract & Shared Util — Architecture Context

Repo: `/home/user/code/github.com/maxlandon/sliver` (a fork of `bishopfox/sliver`; Go module path in generated code is `github.com/bishopfox/sliver`).

## 1. Purpose

The `protobuf/` tree is the single **tri-party contract** binding the three Sliver components together:

- **Client ⟷ Server**: a gRPC service, `SliverRPC`, defined in `protobuf/rpcpb/services.proto`. The operator console/client calls unary and streaming RPCs; the server implements them.
- **Server ⟷ Implant**: implants do not speak gRPC. Instead the server wraps tasking in a `sliverpb.Envelope` (`protobuf/sliverpb/sliver.proto`) — a `{ID, Type, Data}` triple — and ships it over whatever C2 transport is active (mTLS, HTTP(S), DNS, WireGuard, named pipes, etc.). The implant decodes the `Data` bytes into the concrete `sliverpb` message selected by `Type`.
- Because all three components compile against the same generated Go structs, wire compatibility is guaranteed by construction. The `sliverpb.constants.go` header warns that the message-type numbering is **append-only** to preserve backward compatibility with already-deployed implants.

`protobuf/protobufs.go` embeds the raw `.proto` files (`commonpb/*`, `sliverpb/*`, `dnspb/*`) into an `embed.FS` (`protobufs.FS`) so the server can serve/introspect them at runtime.

## 2. The .proto packages

| Package | File(s) | What it defines | Key messages |
|---|---|---|---|
| `commonpb` | `protobuf/commonpb/common.proto` | Generic primitives shared by `clientpb` and `sliverpb`; the request/response **headers** used across all gRPC calls | `Empty`, `Request` (Async, Timeout, BeaconID, SessionID, CmdLine), `Response` (Err, Async, BeaconID, TaskID), `File`, `Process`, `EnvVar` |
| `sliverpb` | `protobuf/sliverpb/sliver.proto` (181 messages), `constants.go`, `sliver.pb.go` | **Implant-facing** messages / task requests+responses. May travel client→server→implant. | `Envelope`, `Register`/`BeaconRegister`/`SessionRegister`, task pairs like `LsReq`/`Ls`, `DownloadReq`/`Download`, `ExecuteAssemblyReq`, `PsReq`/`Ps`, `TunnelData`, `SocksData`, plus `Invoke*` server-only variants |
| `clientpb` | `protobuf/clientpb/client.proto` (128 messages), `client.pb.go` | **Client/server-only** domain objects and management RPC payloads. Never sent to the implant. | `Session`, `Beacon`/`Beacons`/`BeaconTask`, `Job`/`Jobs`, `ImplantConfig`/`ImplantBuild`/`GenerateReq`, `MTLSListenerReq`/`DNSListenerReq`/`HTTPListenerReq`, `Loot`, `Credentials`, `Event`, `Version`, `User`/`Users` |
| `rpcpb` | `protobuf/rpcpb/services.proto`, `services.pb.go`, `services_grpc.pb.go` | The **gRPC `SliverRPC` service** definition — the client↔server API surface | `service SliverRPC { ... }`; generated `SliverRPCClient` / `SliverRPCServer` Go interfaces |
| `dnspb` | `protobuf/dnspb/dns.proto`, `dns.pb.go` | Space-optimized wire format for the **DNS C2 transport** only (used by `server/c2/dns.go` and `implant/.../dnsclient`) | `DNSMessageType` enum (TOTP, INIT, POLL, DATA_TO_IMPLANT, DATA_FROM_IMPLANT, …), `DNSMessage` (Type, ID, Start, Stop, Size, Data) |

**sliverpb vs clientpb vs rpcpb** — this is the core mental model, documented in `protobuf/README.md`:
- `sliverpb` = things the **implant** understands (file ops, exec, tokens, tunnels). A message here can be forwarded to the implant.
- `clientpb` = things only the **client and server** exchange (listeners, jobs, implant build config, loot, creds, events). These are never serialized into an Envelope for the implant.
- `rpcpb` = the **verbs** (the gRPC methods) that tie the two together; each method's request/response types are drawn from `commonpb`, `sliverpb`, or `clientpb` depending on whether the operation stays server-side or gets forwarded.
- Naming convention (README): unary request = subject + `Req`, response = subject (e.g. `Foo`). Server-only messages destined for the implant after server-side work carry the `Invoke` prefix (e.g. `sliverpb.InvokeGetSystemReq`) and never appear in gRPC signatures.

## 3. The SliverRPC service (`protobuf/rpcpb/services.proto`)

- **~185 `rpc` methods** in a single `service SliverRPC`. Generated into the `SliverRPCClient` and `SliverRPCServer` interfaces in `services_grpc.pb.go` (interface decls at lines 215 and 2271; `UnsafeSliverRPCServer` at 3053).
- **Categories** (marked by `// *** ... ***` section comments in the .proto):
  - Teamclient/version/users, Client Logs, Generic (Kill, Reconfigure, Rename, ImplantHistory)
  - Sessions, Beacons (tasks, cancel, integrity), Jobs
  - Threat Monitoring, Listeners (MTLS/WG/DNS/HTTPS/HTTP), Stager Listeners
  - Loot, Creds, Hosts, Implants, HTTP C2 Profiles, Builders, Certificates, Crackstation, Payloads, Websites
  - **Session Interactions** — the large block of implant task RPCs (Ls, Cd, Download, Upload, Ps, Execute, ExecuteAssembly, Migrate, GetSystem, Screenshot, RegistryRead/Write, Services, etc.)
  - Pivots, Beacon-only commands (OpenSession/CloseSession), Extensions, Wasm Extensions, WireGuard-specific, Realtime, Socks5, Tunnels, Events
- **Envelope/header pattern**: the actual per-message routing header is `commonpb.Request` (embedded in the implant-facing `*Req` messages, e.g. carries `SessionID`/`BeaconID`, `Async`, `Timeout`) and `commonpb.Response` (embedded in replies, carries `Err`, `TaskID`, `Async`). Client↔server errors use normal gRPC status codes; the `Response.Err` string is reserved for errors the *implant* needs to bubble back.
- **Streaming methods** (server- or bidi-stream):
  - `ClientLog(stream ClientLogData)`, `ImplantHistory(stream ImplantCommand)` — client-streaming
  - `BuilderRegister(...) returns (stream Event)`, `Crack(...) returns (stream Event)`, `Events(Empty) returns (stream Event)` — server-streaming
  - `SocksProxy(stream SocksData) returns (stream SocksData)` and `TunnelData(stream TunnelData) returns (stream TunnelData)` — full-duplex bidi streams used for interactive shells, port-forwarding, and SOCKS.

## 4. Code generation

- Generated by the `pb` Makefile target (`Makefile` line 165). It runs `protoc` once per package with `--go_out=paths=source_relative:protobuf/`, and for `rpcpb` additionally `--go-grpc_out ... --go-grpc_opt=paths=source_relative`:
  ```
  protoc -I protobuf/ protobuf/commonpb/common.proto  --go_out=...
  protoc -I protobuf/ protobuf/sliverpb/sliver.proto  --go_out=...
  protoc -I protobuf/ protobuf/clientpb/client.proto  --go_out=...
  protoc -I protobuf/ protobuf/dnspb/dns.proto        --go_out=...
  protoc -I protobuf/ protobuf/rpcpb/services.proto   --go_out=... --go-grpc_out=...
  ```
- Required tools are checked at make time: `PB_COMPILERS = protoc protoc-gen-go protoc-gen-go-grpc` (Makefile line 71); running `make pb` errors early if any are missing from `PATH` (lines 72–75).
- Outputs (checked into the repo): `*.pb.go` for messages and `services_grpc.pb.go` for the gRPC stubs.
- **TypeScript note**: there is **no `.pb.ts` generation in this repo** — no `*.pb.ts` files and no TS toolchain in the Makefile. TypeScript bindings live in the separate Sliver GUI/web-client project, not here. Only Go is generated in this tree.
- **Warning**: `*.pb.go` / `*_grpc.pb.go` are machine-generated — do not hand-edit. Change the `.proto` and re-run `make pb`. Hand-written companions that you *do* edit are `protobuf/sliverpb/constants.go` and `protobuf/protobufs.go`.

## 5. util/ package map

| Subpackage / file | Role |
|---|---|
| `util/*.go` (package `util`) | Grab-bag shared helpers: `generics.go` (`Contains`, `Keys`, …), `files.go` (`DeflateBuf`, `ChmodR`, `ByteCountBinary`, `ReadFileFromTarGz`, `CopyFile`), `cryptography.go` (`RC4EncryptUnsafe`, Prelude AES encrypt/decrypt + pad/unpad), `implant.go` (`AllowedName` validation), `resource_ids.go` (`RemoveElement`), `paths_generic.go`/`paths_windows.go` (OS-specific `ResolvePath`) |
| `util/encoders` | C2 **encoder registry** and lossless binary encoders. Defines the `Encoder` interface, `EncoderFS`, and `EncodersList` (Base32/Base58/Base64/English/Gzip/Hex/PNG IDs). Implementations: `base32.go`, `base58.go` (+ generated alphabet), `base64.go`, `hex.go`, `gzip.go`, `english.go` (word-list encoder), `images.go` (PNG), `nop.go` |
| `util/encoders/basex` | Generic base-X radix encoder (vendored, own LICENSE) backing base58 |
| `util/encoders/traffic` | **WASM traffic-encoder** runtime wrapper — `compiler.go`, `interpreter.go`, `traffic-encoder.go`, `testers.go`. Encodes/decodes C2 messages via user-supplied WASM callbacks; default encoders ship in `server/assets/traffic-encoders/` |
| `util/leaky` | `LeakyBuf` — a fixed-size buffer free-list/pool for tunnel/proxy byte buffers |
| `util/minisign` | Minisign (Ed25519) signing/verification — used for signed armory/extension packages. `minisign.go`, `public.go`, `private.go`, `signature.go` (+ tests and testdata keys) |

## 6. Envelope / tasking model

Defined in `protobuf/sliverpb/sliver.proto` (lines 25–31) and driven by `protobuf/sliverpb/constants.go`:

```
message Envelope {
  int64  ID   = 1;  // request/response correlation ID
  uint32 Type = 2;  // message type -> selects which sliverpb message Data holds
  bytes  Data = 3;  // marshaled concrete sliverpb message
  bool   UnknownMessageType = 4;  // implant sets this if it doesn't recognize Type
}
```

Routing:
- `constants.go` declares a long **append-only** `const` block of `Msg*` type numbers via `iota` (`MsgRegister = 1`, `MsgTaskReq`, `MsgPing`, `MsgLsReq`/`MsgLs`, …). Request and response constants are paired. The banner comment stresses: **only append**, or you break running implants.
- `func MsgNumber(request proto.Message) uint32` (line 371, ~638 lines total) is a big type-switch mapping a concrete `sliverpb` Go struct to its `Msg*` constant. The server uses it to stamp `Envelope.Type` when tasking an implant; the implant's handler map uses `Type` in reverse to unmarshal `Data` into the right struct and dispatch to the matching handler.
- `sliverpb.BeaconTasks` (a repeated `Envelope`) is how a beacon receives a batch of queued tasks per check-in (note the deliberate name clash warning: distinct from `clientpb.BeaconTasks`).
- If the implant receives a `Type` it doesn't implement (e.g., an older implant vs. newer server), it returns the Envelope with `UnknownMessageType = true` rather than crashing.
- The DNS transport is the exception that adds a second envelope layer: `dnspb.DNSMessage` fragments/reassembles the encrypted Envelope stream across DNS queries (`Start`/`Stop`/`Size` offsets), because DNS is space-constrained.

## 7. Key files to know

- `protobuf/README.md` — authoritative statement of the `commonpb`/`clientpb`/`sliverpb`/`rpcpb` split and the `Req`/`Invoke` naming conventions.
- `protobuf/rpcpb/services.proto` — the entire client↔server API in one file; read the `// *** ***` section headers to navigate.
- `protobuf/rpcpb/services_grpc.pb.go` — generated `SliverRPCClient`/`SliverRPCServer` interfaces (what server code implements and client code calls).
- `protobuf/sliverpb/sliver.proto` — every implant task message; contains `Envelope`.
- `protobuf/sliverpb/constants.go` — the `Msg*` type-number registry + `MsgNumber()` dispatch; the append-only invariant lives here.
- `protobuf/commonpb/common.proto` — `Request`/`Response` headers embedded throughout; understand these before reading any task message.
- `protobuf/dnspb/dns.proto` — DNS C2 framing; only relevant to the DNS transport.
- `protobuf/protobufs.go` — embeds the `.proto` sources at runtime.
- `Makefile` (target `pb`, lines 71–75, 164–170) — the regeneration recipe.
- `util/encoders/encoders.go` — encoder registry / `Encoder` interface; entry point to the C2 encoding layer.
- `util/encoders/traffic/README.md` + `traffic-encoder.go` — WASM traffic-encoder subsystem.

## 8. Gotchas

- **Append-only message numbers**: never insert or reorder constants in `sliverpb/constants.go`; only append. Reordering silently breaks wire compat with deployed implants.
- **Don't hand-edit generated files**: `*.pb.go`, `services_grpc.pb.go` are overwritten by `make pb`. Edit the `.proto` (and `constants.go`/`MsgNumber` for new implant messages).
- **New implant message = two edits**: add the `message` in `sliver.proto` *and* add its `Msg*` constant plus a `MsgNumber` switch case, or the Envelope router won't dispatch it.
- **Package placement matters**: putting a message in `clientpb` vs `sliverpb` decides whether it can be forwarded to an implant. Cross-package leakage (e.g., referencing `clientpb` from an implant path) breaks the implant build, which must stay lean and must not depend on server-only types.
- **Two `BeaconTasks` types**: `sliverpb.BeaconTasks` (Envelopes for the implant) vs `clientpb.BeaconTasks` (task metadata for the console) — the proto comment explicitly warns not to confuse them.
- **gRPC errors vs `Response.Err`**: client↔server failures use gRPC status codes; `commonpb.Response.Err` is only for errors originating *inside the implant* and tunneled back. Don't conflate them.
- **The module path is `bishopfox/sliver`** even in this `maxlandon` fork — generated `go_package` options and imports all reference `github.com/bishopfox/sliver/protobuf/...`.
- **TS bindings are out-of-tree**: despite the tri-party framing, this repo generates Go only; any `.pb.ts` referenced elsewhere comes from the separate GUI project.
- **DNS double-enveloping**: the DNS transport wraps the standard Envelope inside `dnspb.DNSMessage` fragments; debugging DNS C2 means reasoning about both layers and the reassembly offsets.
