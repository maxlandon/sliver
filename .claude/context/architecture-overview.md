# Sliver — Architecture Overview (seed context)

> Fork under active work: `github.com/maxlandon/sliver` (module path stays
> `github.com/bishopfox/sliver`). This fork's distinguishing work is the migration to the
> **`reeflective/team`** teamserver/teamclient library and **`reeflective/console`** REPL,
> plus a typed **operator RBAC** owned by Sliver (see the auth work in `merger-fixes`).

## What Sliver is

Sliver is an adversary-emulation / C2 (command-and-control) framework used for authorized
red-team and security testing. Three cooperating programs share one protobuf contract:

- **server** — the teamserver: hosts operator-facing gRPC, drives implant generation, runs
  the implant-facing C2 listeners, owns the database.
- **client** — the operator console (a REPL + CLI) that talks to the server over gRPC.
- **implant** — the agent that runs on the target and beacons/sessions back to the server's
  C2 listeners.

## Repo layout (top level)

| Dir | Role |
|---|---|
| `server/` | Teamserver: RPC, C2 listeners, DB, implant generation, certs. (169 Go files) |
| `client/` | Operator console + CLI + command tree. (301 Go files) |
| `implant/` | The agent. **Separate module-ish tree with its own `implant/vendor/`.** (224 Go files) |
| `protobuf/` | The tri-party contract: `commonpb`, `sliverpb`, `clientpb`, `rpcpb`, `dnspb`. |
| `util/` | Shared helpers (encoders, etc.) usable by all three. |
| `vendor/` | Vendored deps for the server+client module. |
| `docs/` | The Sliver docs website content. |

## Module & workspace

- Module: `github.com/bishopfox/sliver`, **Go 1.23.6**.
- One `replace` in `go.mod`: `rsteube/carapace` → `reeflective/carapace`.
- **Go workspace:** `GOWORK=/home/user/code/go.work` resolves `reeflective/team` (and
  friends) to their local checkouts. **Because a workspace is active, do NOT add `replace`
  directives for those and do NOT use `-mod=vendor`** — workspace mode is incompatible with
  vendoring. (This was a mistake made and corrected during the auth migration.)

## Entrypoints

| main package | Program |
|---|---|
| `server/main.go` | `sliver-server` |
| `client/main.go` | `sliver-client` |
| `implant/sliver/sliver.go` | the implant |

(`implant/sliver/encoders/base58_genalphabet.go` and `util/encoders/base58_genalphabet.go`
are `//go:build ignore` codegen helpers, not real entrypoints.)

## Build tags (critical)

| Tag | Gates |
|---|---|
| `server` | server-only code (assets, generation). Needed to build/test the server. |
| `client` | client-only code. |
| `go_sqlite` | pure-Go sqlite driver (vs cgo). Needed by anything touching the DB. |

Canonical build/test invocations:
```bash
go build -tags "server go_sqlite" ./server
go build -tags "client go_sqlite" ./client
go test  -tags "server go_sqlite" ./server/...
```
The implant is built per-target-OS with its own build-tag matrix and its own vendor tree.

## Build system

Root `Makefile` targets: `default`, `client`, `servers`, `clients`,
`macos-amd64`/`macos-arm64`/`linux-amd64`/`linux-arm64`/`windows-amd64`, `pb` (regenerate
protobuf), `debug`, `clean`/`clean-all`, `validate-go-version`. Protobuf `.pb.go`/`.pb.ts`
are **generated** (`make pb`) — never hand-edit them.

## The reeflective integration (what makes this fork special)

- **`reeflective/team`** — provides the teamserver/teamclient plumbing (user auth,
  transport handlers, config). In this fork the library is **auth-only**: it authenticates
  users but carries **no permission model**. Authorization is **Sliver's** job again.
- **Authorization** lives in `server/transport/middleware.go`: a gRPC interceptor resolves
  the authenticated user name → a typed `*models.Operator` (booleans `PermissionAll`,
  `PermissionBuilder`, `PermissionCrackstation`) and gates builder/crackstation method
  allow-lists. Local console connections get a synthetic all-permissions operator.
- **`reeflective/console`** — the client REPL. `client/cli` builds the cobra tree,
  `client/console` runs the menu/REPL and holds `SliverClient`.
- Team core now speaks **slog** (not logrus); Sliver adapts via `server/log`.

See `reconciliation-dev-vs-merger-fixes.md` for the branch history and why `merger-fixes`
is canonical.

## Where to go next

Subsystem deep-dives live alongside this file:
- `subsystem-server.md`
- `subsystem-client.md`
- `subsystem-implant.md`
- `subsystem-protobuf-rpc.md`
