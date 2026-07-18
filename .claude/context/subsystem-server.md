# Sliver Server Subsystem — Architecture Context

## 1. Purpose
The `server/` tree is the Sliver C2 (command-and-control) **teamserver**: a single Go binary (`sliver-server`) that (a) exposes a gRPC API to operator clients (local console + remote multiplayer clients), and (b) runs the implant-facing C2 listeners (mTLS, HTTP(S), DNS, WireGuard) that compromised hosts beacon/session back to. It also compiles implants (Go toolchain + shellcode generation), manages certificates/crypto, persists all state in a GORM database, and integrates with external tools (Metasploit, shikata-ga-nai). It is built on the `reeflective/team` teamserver framework, so operator identity/transport are handled by that library while Sliver layers its own RBAC and RPC services on top.

## 2. Entrypoint & startup flow
- **`server/main.go`** — trivial; calls `cli.Execute()`.
- **`server/cli/cli.go`** — the real bootstrap:
  1. `transport.NewTeamserver()` builds the `reeflective/team/server.Server` with two handler stacks (mTLS-gRPC + Tailscale-gRPC), Sliver's home dir (`~/.sliver/`), slog logger, DB client, default port `31337`.
  2. `client.NewSliverClient(opts...)` creates an **in-memory teamclient** (the server is a client of itself over a `bufconn`, no TLS).
  3. `sliverServerCLI()` assembles the cobra command tree: server commands (from `client/command`), teamserver management commands (`server/command`), and the closed-loop console (`client/command/console`).
  4. `preRunServerS()` is the daemon/console pre-run hook — it calls `assets.Setup()`, `encoders.Setup()`, `certs.SetupCAs()`, `certs.SetupWGKeys()`, `cryptography.AgeServerKeyPair()`, `cryptography.MinisignServerPrivateKey()`, then (for `console`/`teamserver daemon`) `teamserver.ListenerStartPersistents()` + `c2.StartPersistentJobs()`, and finally `teamserver.Serve(con.Teamclient)`.
- **DB init** happens lazily via `db.Client = newDBClient()` (package-level var in `server/db/db.go` → `server/db/sql.go`), which reads `configs.GetDatabaseConfig()` and `AutoMigrate`s ~45 models.
- **Cert init** via `server/certs` (`SetupCAs`, `SetupWGKeys`).
- **Listeners**: operator-facing gRPC listeners started by the team core; implant-facing C2 listeners started as **jobs** via `server/c2/jobs.go` (`StartPersistentJobs` restores from `configs`/DB).

Three invocation modes are documented in `cli.go`: `sliver <cmd>` (one-shot, e.g. `generate`), `sliver console` (interactive), `sliver teamserver serve` (blocking daemon).

## 3. Package map

| Package path | Role |
|---|---|
| `server/main.go` | Binary entrypoint; calls `cli.Execute()`. |
| `server/cli` | Assembles cobra CLI tree, wires teamserver+in-memory teamclient, pre-run hooks. |
| `server/command` | Server-binary-only commands (teamserver user mgmt w/ `-P` permissions, assets, certs, builder, version). |
| `server/transport` | gRPC teamserver backends (mTLS + Tailscale) implementing `team/server.Handler`; auth/authz/audit middleware. |
| `server/rpc` | ~184 gRPC method implementations of the `SliverRPC` service (session/beacon/generate/etc.). |
| `server/c2` | Implant-facing C2 listeners: `mtls.go`, `http.go`, `dns.go`, `wireguard.go`, `tcp-stager.go`; job wrappers in `jobs.go`. |
| `server/core` | In-memory runtime state: Sessions, Jobs, Clients, Tunnels, Pivots, Hosts, EventBroker, Crackstations, Builders. |
| `server/db` | GORM client, 77 helper functions (`helpers.go`), dialect selection, logger. |
| `server/db/models` | GORM model structs (Beacon, ImplantBuild/Config, Operator, Host, Loot, Certificate, jobs, http-c2, crackstation…). |
| `server/certs` | X.509 CA management: mTLS server/implant CAs, HTTPS, operator, WireGuard keys, ACME. |
| `server/cryptography` | Age keypair, Minisign signing, symmetric keys, implant-server key exchange crypto. |
| `server/assets` | Unpacks embedded assets (Go toolchain, traffic encoders, etc.) into `~/.sliver/`; `GetRootAppDir()`. |
| `server/generate` | Implant binary generation: Go build (`binaries.go`), profiles, canaries, donut, SRDI shellcode, external builds. |
| `server/builder` | External/remote builder client (`rpcpb.SliverRPCClient`) that offloads implant compilation. |
| `server/gogo` | Thin wrapper invoking the bundled Go compiler/toolchain (`GoConfig`, `GetGoRootDir`). |
| `server/encoders` | Native + WASM "traffic encoders" registry used to obfuscate implant traffic. |
| `server/sgn` | Shikata-ga-nai shellcode encoder wrapper. |
| `server/msf` | Metasploit integration (`msfconsole`/`msfvenom` shell-outs). |
| `server/handlers` | Server-side handlers for **implant-originated** messages (register, tunnel data, ping, socks, beacon tasks, pivots). |
| `server/loot` | Loot store (files/creds) with a `LootBackend` interface; DB-backed. |
| `server/configs` | JSON/DB configs: `server.json`, database config, HTTP-C2 profiles, crack config. |
| `server/codenames` | Random adjective/noun name generation for implants/sessions. |
| `server/log` | logrus named loggers + slog root handler; audit logger (`~/.sliver/logs/`). |
| `server/netstack` | Userspace TCP/IP (gVisor-style) TUN stack, used by WireGuard C2. |
| `server/watchtower` | Monitors implant binaries against threat-intel providers (VirusTotal etc.) to detect "burned" builds. |
| `server/website` | Serves attacker-controlled web content (HTTP-C2 cover traffic); DB-backed. |

## 4. RPC layer
- The gRPC service is defined in `protobuf/rpcpb/services_grpc.pb.go` (`SliverRPCServer` interface, `RegisterSliverRPCServer`). The interface declares ~175 methods; `server/rpc/*.go` implements **~184** `func (rpc *Server) ...` methods (one file per feature area, e.g. `rpc-sessions.go`, `rpc-beacons.go`, `rpc-generate.go`, `rpc-crackstations.go`).
- **Registration**: `server/transport/server.go` `serve()` does `sliverServer := rpc.NewServer(h.Server); rpcpb.RegisterSliverRPCServer(grpcServer, sliverServer)`.
- **`Server` struct** (`server/rpc/rpc.go`) embeds `rpcpb.UnimplementedSliverRPCServer` and holds `team *server.Server`. `NewServer()` also calls `core.StartEventAutomation()`.
- **Protobuf relationship**: request/response types come from `protobuf/{clientpb,sliverpb,commonpb}`. `GenericHandler`/`asyncGenericHandler` marshal a request, dispatch to a live `core.Session` (sync) or store a `BeaconTask` (async beacon), and unmarshal the response.
- **Session vs beacon RPCs**: `rpc-sessions.go` (live interactive sessions via `core.Sessions`), `rpc-beacons.go` (async, DB-backed via `db.ListBeacons`/`BeaconByID`/`BeaconTask`). Errors are centralized in `server/rpc/errors.go` (`ErrInvalidSessionID`, `ErrInvalidBeaconID`, `ErrDatabaseFailure`…).

## 5. Transport / C2
Two distinct network surfaces:

**Operator-facing (server/transport):**
- Built on `reeflective/team/server`. `NewTeamserver()` registers two `server.Handler` backends: `teamserver` (TCP+mTLS gRPC, `mtls.go`) and `tailscaleTeamserver` (`tailscale.go`, wraps the mTLS core inside a `tsnet.Server`, requires `TS_AUTHKEY`). Both share `serve(ln)` in `server.go`.
- **`server/transport/middleware.go`** is the security core:
  - `initAuthMiddleware()`: remote connections get `permissions*Interceptor` + `grpc_auth` with `tokenAuthFunc`; the **in-memory local console** (`localListener != nil`) uses `serverAuthFunc` which injects a synthetic all-permissions operator (no auth).
  - `tokenAuthFunc`: teamserver core does **authentication only** (`ts.Authenticate` → user name); Sliver then does **authorization** by resolving `db.OperatorByName(user.Name)` into a typed `models.Operator`, stored in context under the `Operator` key.
  - `permissionsUnaryServerInterceptor`/`permissionsStreamServerInterceptor` enforce RBAC: `PermissionAll` = everything; `PermissionBuilder`/`PermissionCrackstation` are restricted to hardcoded method allowlists (`builderMethods`, `crackstationMethods`).
  - Also: mTLS creds (`tlsAuthMiddlewareOptions` via `s.UsersTLSConfig()`), 2GB message limits, logrus logging, and an **audit log** interceptor (`auditLogUnaryServerInterceptor`) writing JSON per request with session/beacon context.
- `authz_e2e_test.go` exercises the permission model end-to-end.

**Implant-facing (server/c2):** listeners created as `core.Job`s via `server/c2/jobs.go` (`StartMTLSListenerJob`, `StartDNSListenerJob`, `StartHTTPListenerJob`, `StartHTTPStagerListenerJob`, `StartWGListenerJob`, `StartPersistentJobs`). Protocols: `mtls.go` (`StartMutualTLSListener`), `http.go` (HTTP(S) sessions, largest/most complex), `dns.go` (DNS C2 sessions/canaries), `wireguard.go` (`StartWGListener`, uses `server/netstack` userspace stack), `tcp-stager.go`. Inbound implant messages are dispatched by `server/handlers`.

## 6. Data layer
- **Engine**: GORM. Default dialect **sqlite**; also supports Postgres and MySQL (`server/db/sql.go` switch on `configs.GetDatabaseConfig().Dialect`). Config in `server/configs/database.go`.
- **Sqlite driver is build-tag-gated** (see §7): `sql-go.go` (`go_sqlite`, pure-Go `glebarez/sqlite`), `sql-cgo.go` (`cgo_sqlite`, `mattn/go-sqlite3`), `sql-wasm.go` (`wasm_sqlite`, `ncruces/go-sqlite3`).
- `server/db/db.go` exposes the package-global `db.Client *gorm.DB` and `db.Session()` (full-save-associations). Init `AutoMigrate`s ~45 models one-by-one (so one failure doesn't block the rest).
- **Key models** (`server/db/models/`): `Beacon` + `BeaconTask`, `ImplantBuild`/`ImplantConfig`/`ImplantProfile`/`ImplantC2`, `Operator` (RBAC), `Host`, `Certificate`, `Loot`, `Credential`, `Website`/`WebContent`, `HttpC2Config` (+ headers/segments/params), listener-job models (`ListenerJob`, `HTTPListener`, `DNSListener`, `WGListener`, `MtlsListener`, `MultiplayerListener`), crackstation models, `WGKeys`/`WGPeer`, `DNSCanary`/`CanaryDomain`.
- **`server/db/helpers.go`** is the primary query surface — 77 helper functions (`BeaconByID`, `ImplantBuildByName`, `OperatorByName`, `SaveOperator`, `LoadHTTPC2s`, …). Note: live session state is **in-memory** (`core.Sessions`), not DB; beacons/tasks/builds/hosts/loot are persisted.

## 7. Build tags
- **`server`** — gates the platform-specific asset embed files `server/assets/assets_<os>_<arch>.go` (each is `//go:build server` + `//go:embed fs/...`). This is the only non-DB use of the `server` tag in-tree; it selects which embedded toolchain/asset zip is compiled in per target platform. Building without it omits the embedded assets.
- **`go_sqlite` / `cgo_sqlite` / `wasm_sqlite`** — mutually exclusive; select the sqlite driver in `server/db/sql-*.go`. `go_sqlite` (pure Go, no cgo) is the standard/default server build tag. `cgo_sqlite` uses the C library; `wasm_sqlite` uses a WASM sqlite (with `server/db/wasmsqlite/`).
- These are the only build tags inside `server/`; the DB tag choice is the load-bearing one for compilation (cgo vs pure-Go).

## 8. Key files to know
- `server/cli/cli.go` — startup orchestration; the map of how everything is wired.
- `server/transport/server.go` — `NewTeamserver()`, gRPC registration, in-memory client bufconn.
- `server/transport/middleware.go` — auth (teamserver) vs authz (Sliver RBAC), audit log, interceptors, method allowlists.
- `server/transport/mtls.go` / `tailscale.go` — the two `team/server.Handler` transport backends.
- `server/rpc/rpc.go` — `Server` struct, `NewServer`, `GenericHandler`/`asyncGenericHandler` (sync session vs async beacon dispatch).
- `server/handlers/handlers.go` — inbound implant message → handler map (register/tunnel/beacon/pivot).
- `server/core/sessions.go` — in-memory session registry (`core.Sessions`), the runtime heart of live implant control.
- `server/c2/jobs.go` — how all implant listeners are started/stopped/persisted as jobs.
- `server/c2/http.go` — largest/most intricate C2 protocol (HTTP-C2 sessions).
- `server/db/db.go` + `server/db/sql.go` — DB client, dialect selection, full model migration list.
- `server/db/helpers.go` — 77 query helpers; the DB access API.
- `server/db/models/operator.go` — the RBAC model (`PermissionAll/Builder/Crackstation`).
- `server/generate/binaries.go` — implant compilation via the Go toolchain.
- `server/certs/certs.go` + `certs/ca.go` — CA/cert lifecycle (mTLS, WireGuard, operator).
- `server/configs/server.go` / `configs/database.go` — server + DB configuration structs.

## 9. Gotchas / where to look for X
- **"Who can call this RPC?"** → `server/transport/middleware.go`: `builderMethods`/`crackstationMethods` allowlists + `permissions*Interceptor`. RBAC comes from `models.Operator`, persisted by `saveOperatorPermissions` in `server/command/server.go` (the `-P/--permissions` flag on `teamserver user`).
- **Auth vs authz split**: the `reeflective/team` core now owns identity/tokens only; Sliver owns permissions. The `Operator.Token` field is legacy/unused for auth. Local console bypasses auth entirely (`serverAuthFunc`, all-permissions "server" operator).
- **Sessions are not in the DB** — live sessions live in `core.Sessions` (memory); beacons/tasks are in the DB. Session vs beacon RPCs diverge accordingly (`rpc-sessions.go` vs `rpc-beacons.go`).
- **Adding an RPC**: implement `func (rpc *Server) Foo(...)` in `server/rpc/rpc-*.go`, but the method signature must match the generated `SliverRPCServer` interface in `protobuf/rpcpb/services_grpc.pb.go` (regenerate proto first). New restricted methods must be added to the allowlists if not `PermissionAll`.
- **Where listeners come from on boot**: `preRunServerS` → `c2.StartPersistentJobs()` (`server/c2/jobs.go`) + `teamserver.ListenerStartPersistents()`. Persisted job config in `server/configs/server.go` (`JobConfig`) and/or DB listener-job models.
- **Build won't compile / sqlite errors** → check the DB build tag (`go_sqlite` is standard). Missing embedded toolchain at runtime → check the `server` tag / `server/assets/assets_<os>_<arch>.go`.
- **Implant compilation** lives in `server/generate` (local, uses `server/gogo` toolchain) but can be offloaded to `server/builder` (remote builder acting as a gRPC client with `PermissionBuilder`).
- **Tailscale transport** requires the `TS_AUTHKEY` env var (`server/transport/tailscale.go`); it wraps the same mTLS gRPC core.
- **App state on disk** is under `~/.sliver/` (override via `SLIVER_ROOT_DIR`), resolved by `assets.GetRootAppDir()`; DB default `~/.sliver/sliver.db`, logs `~/.sliver/logs/sliver.{log,json}`, audit log separate.
- **Two protobuf namespaces**: `clientpb` (operator/client-facing types), `sliverpb` (implant wire messages), `commonpb` (shared Request/Response). RPC handlers routinely convert `models.* → clientpb.*` via `ToProtobuf()`.
