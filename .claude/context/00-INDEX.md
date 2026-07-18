# Sliver context pack — index

Durable context files for Claude instances working on this Sliver fork
(`github.com/maxlandon/sliver`). Skim this index, then the brief, then the relevant
subsystem file **before** opening code. Keep these current: when you learn something durable
and non-obvious, add or update a file here and add its line below.

## Read in this order

1. **`NEXT-INSTANCE-BRIEF.md`** — inherited state, environment gotchas, and what to do next. Start here.
2. **`architecture-overview.md`** — what Sliver is, repo layout, module/workspace, build tags, the reeflective integration.

## Subsystem deep-dives

- **`subsystem-server.md`** — teamserver: RPC, C2 listeners, DB, generation, certs, auth middleware.
- **`subsystem-client.md`** — operator console + CLI + command tree + transport dialer.
- **`subsystem-implant.md`** — the agent: session/beacon loops, transports, handlers, capabilities.
- **`subsystem-protobuf-rpc.md`** — the tri-party protobuf contract and the `SliverRPC` service.

## Project history / decisions

- **`reconciliation-dev-vs-merger-fixes.md`** — proof that `merger-fixes` is canonical and the
  `dev` branch has nothing left to preserve (its extra files are upstream-removed stale code).
  Records the auth-only `reeflective/team` migration outcome too.

## Testing

- **`teamserver-test-suite.md`** — the in-process sandbox suite under `tests/teamserver/`
  (real teamserver+teamclient over bufconn), how to run it, and the live bug list it
  found: fixed version-panic; open gRPC-global-logger race, missing panic-recovery
  interceptor, and a per-cycle goroutine leak.

## Suggested future additions (not yet written)

- `data-model.md` — catalog of `server/db/models/*` GORM tables + relations.
- `rpc-index.md` — every `rpcpb.SliverRPC` method by category with request/response types.
- `c2-matrix.md` — per-channel server-listener ↔ implant-dialer pairing.
- `command-to-rpc.md` — how each `client/command/<group>` maps to RPC calls.
- `generation-pipeline.md` — `server/generate` + `server/builder`: config → implant binary.
