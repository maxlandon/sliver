# Brief for the next Claude instance

You are picking up a Sliver fork (`github.com/maxlandon/sliver`) after another instance
completed a teamserver-library migration and a branch reconciliation. **Read this first,
then `architecture-overview.md`, then the subsystem files as needed.** Everything here has
been verified against the codebase — trust it, but re-verify any file/flag before acting on
it (the tree evolves).

## State you are inheriting (do not re-litigate)

1. **Auth-only `reeflective/team` migration is DONE** on `merger-fixes` (`920b88d6f`):
   the team library authenticates only; Sliver owns authorization via typed
   `*models.Operator` RBAC in `server/transport/middleware.go`. Verified end-to-end by
   `server/transport/authz_e2e_test.go` (passing).
2. **`dev` ↔ `merger-fixes` reconciliation is DONE and PROVEN COMPLETE.** `merger-fixes` is
   canonical. `dev`'s only original contribution (`bindServerConfig`) was grafted. Its other
   apparently-unique files (`client/prelude/*`, `prelude-operator/*`, `generate-stager.go`)
   are **stale code upstream deliberately removed** — do NOT restore them. Full proof:
   `reconciliation-dev-vs-merger-fixes.md`.

## Environment gotchas (learned the hard way)

- **Go workspace is active** (`GOWORK=/home/user/code/go.work`) resolving `reeflective/*`
  to local checkouts. **Never add `replace` directives for them; never use `-mod=vendor`.**
- Use build tags: `server go_sqlite` (server), `client go_sqlite` (client).
- Do **not** modify anything under `/home/user/code/github.com/reeflective/team` — that side
  is finished/owned elsewhere.
- The shell's `go` wrapper can choke on inline env vars; the raw binary is
  `/home/user/.local/go/bin/go`. Tests that touch assets/DB want `SLIVER_ROOT_DIR` pointed
  at a temp dir so they never touch a real `~/.sliver`.
- Building/surveying **implant** (offensive agent) code can trip automated cybersecurity
  safeguards on some models. Keep implant documentation **architectural** (structure, data
  flow, build tags) rather than exploitation detail — that stays within defensive/authorized
  scope.

## Your likely mission: expand this context pack

These files are a seed. To deepen them, good next passes:
- **Data model catalog** — enumerate `server/db/models/*` (GORM tables) and their relations.
- **RPC method index** — list the `rpcpb.SliverRPC` methods by category with request/response
  types (from `protobuf/rpcpb` + `server/rpc/*`).
- **C2 channel matrix** — for each transport (mtls/http/dns/wg/tailscale), the server listener
  (`server/c2`, `server/transport`) ↔ implant dialer (`implant/sliver/transports`) pairing.
- **Command → RPC map** — how a `client/command/<group>` cobra command calls which RPC.
- **Generation pipeline** — `server/generate` + `server/builder`: how an implant binary is
  produced from a config.
- **Sequence traces** — "operator runs `execute-assembly`" or "a new session registers"
  end to end across all three programs.

Prefer parallel read-only exploration (the `Explore` agent) to map, then write findings
into new files here. Keep each file focused and cite paths.

## How to use these files

- Start every Sliver task by skimming `00-INDEX.md` → this brief → the relevant subsystem
  file. Only then open code.
- When you learn something durable and non-obvious, **add or update a file here** so the next
  instance inherits it. Keep the INDEX current.
