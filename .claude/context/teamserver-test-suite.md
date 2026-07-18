# Teamserver/teamclient sandbox test suite

Durable notes on the in-process integration suite under `tests/teamserver/` and the
bugs it has already surfaced. Read this before extending the suite or touching the
teamserver/teamclient connection or logging wiring.

## What the suite is

An in-process, sandboxed integration harness for the teamserver ↔ teamclient
boundary. Each test stands up a **real** teamserver and connects a **real**
teamclient in the same process, over the same in-memory gRPC `bufconn` transport
that Sliver's single-player console uses (`server/transport.clientOptionsFor`,
`server/transport/server.go`). No socket, no TLS, no token on this path — it is
exactly the local `sliver-server console` flow.

- `tests/teamserver/harness_test.go` — the `sandbox` harness: `newSandbox(t)` does
  `transport.NewTeamserver()` → `console.NewSliverClient(opts)` → `team.Serve(con.Teamclient)`,
  then dials its **own** `rpcpb.SliverRPCClient` over the same bufconn (the console's
  `con.Rpc` is populated by an unexported, cobra-driven step unreachable from an
  external test package, so we make an equivalent client directly). Every blocking
  op is wrapped in `within(t, d, ...)`, a watchdog that fails with a full goroutine
  dump instead of hanging.
- `tests/teamserver/connect_test.go` — first tests: connect+`GetVersion` round-trip;
  repeated connect/disconnect teardown stress with a goroutine-leak gauge.
- `tests/teamserver/run.sh` — runner. **Must** export a throwaway `SLIVER_ROOT_DIR`
  before `go test` starts, because `server/db` opens the DB at package-init (before
  `TestMain`), so setting it inside a test is too late. `TestMain` hard-fails if the
  var is unset, to prevent ever touching a real `~/.sliver`.

### Running it
```
./tests/teamserver/run.sh                 # full suite, -race, isolated temp root
./tests/teamserver/run.sh -run TestConnectAndVersion -v
```
Tags: `server,osusergo,netgo,go_sqlite` (matches `go-tests.sh`). On this box the go
build tmp must live off the 1 GB `/tmp` tmpfs: `export GOTMPDIR=/home/user/.cache/go-tmp`.

## Findings (in priority order)

1. **[FIXED] `GetVersion` and client version handlers panic on a non-`X.Y.Z` version.**
   `client/version.SemanticVersion()` split `Version` on `.` with no length guard, so
   an unstamped build (plain `go build`/tests) or a short tag (`v1.5`) yielded a slice
   shorter than 3, and `semVer[1]`/`semVer[2]` panicked in `server/rpc/rpc-teamclient.go:37`
   (`GetVersion`) and `client/console/teamclient.go` (`VersionClient`). Because there is
   no recovery interceptor (finding 3), that panic **crashed the whole teamserver**.
   Fix: `SemanticVersion()` now always returns exactly 3 ints (zero-padded, extras
   ignored) — `client/version/sliver-version.go`. Safe for all 4 callers (updates.go,
   readline.go, teamclient.go, rpc-teamclient.go).

2. **[FIXED] Data race on gRPC's global logger in single-player mode.**
   `client/transport/middleware.go` and `server/transport/middleware.go` each called
   `grpc_logrus.ReplaceGrpcLogger` → `grpclog.SetLoggerV2` at runtime (client on every
   dial, server on handler Init). In single-player the server's gRPC `Serve` loop was
   already reading that global logger while the client's connect wrote it → `-race`
   failed. gRPC's global logger is documented set-once-before-any-use.
   Fix: both runtime writes removed; the global gRPC logger is now installed **exactly
   once** in an `init()` in `client/transport/middleware.go` (imported by both binaries,
   so it runs at startup before any Serve/Connect), to a discarding logger matching the
   package's existing nil-default. The per-RPC `grpc_logrus` interceptors still log all
   call/payload activity. Verified: `tests/teamserver` now passes under `-race`.

3. **[FIXED] No panic-recovery interceptor on the teamserver gRPC chain.**
   The chain was audit → tags → logrus → auth/permissions with no recovery, so any
   handler panic unwound through gRPC and **crashed the whole server process** (how
   finding 1 manifested as a crash). Fix: `recoveryUnaryServerInterceptor` /
   `recoveryStreamServerInterceptor` in `server/transport/middleware.go`, installed as
   the OUTERMOST interceptor in `mtls.go` `Init` (prepended before log/auth). Panics
   become `codes.Internal` + a logged stack. Covered by `server/transport/recovery_test.go`.

5. **[FIXED] Remote/multiplayer authorization was completely broken (wrong interceptor order).**
   In `initAuthMiddleware` (`server/transport/middleware.go`) the remote chain was
   `[permissions, tokenAuth]`. Chained gRPC interceptors run in slice order, so the
   permissions interceptor ran BEFORE `tokenAuthFunc` populated the `*models.Operator`
   in context — it always read a nil operator and rejected **every** authenticated
   remote operator with `Unauthenticated: "Authentication failure"`. No operator could
   connect to a remote sliver-server. It hid behind the authz e2e unit test, which
   manually ran auth-then-permissions. Fix: swap to `[tokenAuth, permissions]` for both
   unary and stream. Caught by `server/transport/multiplayer_test.go` (real TCP+mTLS +
   token), which is the first true end-to-end remote-path test.

4. **[MITIGATED] Goroutine leak on listener teardown.**
   The team core NEVER calls `Handler.Close()` (only `ln.Close()` on the net.Listener,
   jobs.go:221), so a `Close()`→`GracefulStop` wrapper would never fire. Instead
   `serve()` (`server/transport/server.go`) now calls `grpcServer.Stop()` once
   `grpcServer.Serve(ln)` returns (which happens exactly when a listener is closed via
   `ListenerClose`), releasing the per-connection handler goroutines that previously
   leaked for the rest of the process on every listener close — a real fix for the
   remote path. Residual: the single-player bufconn server has no shutdown hook at all
   (nothing ever closes that in-memory listener), so `TestRepeatedConnectDisconnect`
   still shows ~2 goroutines/cycle. That is test-scoped: a production teamserver serves
   one core for the process lifetime, so it never repeatedly creates/destroys servers.

   Related deadlock hot-spot (NOT fixed — lives in read-only `reeflective/team`):
   `ListenerClose` sends on an unbuffered `kill` channel (jobs.go:142); a second close
   racing the kill goroutine's `LoadAndDelete` (jobs.go:223) can block forever.
   `TestListenerCloseInvalidID` pins the deterministic not-found path; the double-close
   race is documented but not reproduced (flaky, and unfixable from Sliver).

6. **[FIXED] `UserCreate` inserted a duplicate identity on every call.**
   `internal/db.User.Name` has no unique index and `UserCreate` did a plain `Save`
   with a zero primary key, so each `teamserver user --name X` re-provisioning
   INSERTED a brand-new row. The teamserver authorization model is keyed by Name,
   so N rows sharing a name make all per-name state ambiguous: `updateLastSeen(name)`
   and Sliver's `isOperatorOnline(name)` both match EVERY row of that name, so the
   duplicates move in lockstep (all "0s", all Offline) — exactly the garbled
   `teamclient users` table. Fix (team `server/users.go` `UserCreate`): delete any
   user(s) already holding the requested name before Save, so re-creating a user
   ROTATES its credentials in place and collapses pre-existing duplicates to a single
   row; the token cache is reset so the old token stops authenticating. Deliberately
   did NOT add a `uniqueIndex` on Name — an existing DB that already has duplicates
   would fail AutoMigrate and the server would refuse to start.

7. **[FIXED] Server certificate not revalidated after a users-CA rotation.**
   `UsersTLSConfig` only regenerated the server cert on `ErrCertDoesNotExist`, so
   after the users-CA was rotated the daemon kept presenting an orphaned cert that no
   longer chained to the live CA — every remote handshake failed `tls: bad
   certificate` while clients (whose bundles carry the NEW CA) rejected the old cert.
   Fix (team `server/users.go`): after loading the key pair, verify the leaf still
   chains to the current users-CA and is within its validity window
   (`serverCertValidFor` — `CheckSignatureFrom` + NotBefore/NotAfter); regenerate and
   reload otherwise, so the daemon self-heals on restart.

### Users/operator display semantics (NOT bugs — read before "fixing" the table)
- **`Online` requires a live event stream.** Sliver derives it from
  `core.Clients.ActiveOperators()`, populated ONLY while a client holds an open
  `Events` RPC stream (`server/rpc/rpc-events.go` adds on subscribe, removes on
  disconnect). A one-shot `teamclient users` (or any non-console RPC) authenticates
  but never opens `Events`, so it is legitimately `Offline`. Only a full interactive
  `slc` console shows as Online. The operator name comes from the TLS client-cert
  CommonName (`getClientCommonName`), which team sets to the user name.
- **`LastSeen` is stamped on every authenticated RPC** (team `Authenticate` →
  `updateLastSeen`, on both the cache-hit and DB paths). So a freshly-queried user
  reads `0s ago`; the renderer now prints `never` for a zero `LastSeen` (a user that
  never authenticated) instead of the raw `Mon, 01 Jan 0001 ... LMT` zero-time
  (`time.Unix(zeroTime.Unix(),0).IsZero()` is true, so `IsZero` is the right
  discriminator across the Unix-seconds round-trip). Fixed in team
  `client/commands/users.go`.

Related Sliver-side fix (already committed, `server/transport/mtls.go`): the daemon
selects bufconn-vs-TCP by ADDRESS (`addr == ":0"` is the in-memory sentinel), not by
the consumable `localListener` flag. Previously the daemon reused the in-memory
bufconn and never bound TCP unless a persistent listener happened to exist — remote
clients timed out with `context deadline exceeded`. Any real `host:port` now always
`net.Listen("tcp")` + mTLS + tokenAuth.

## Coverage

- **Single-player (bufconn):** `tests/teamserver` — connect+`GetVersion`, repeated
  connect/disconnect teardown. Runs under `-race`.
- **Multiplayer (real TCP+mTLS+token):** `server/transport/multiplayer_test.go` —
  authorized connect+RPC, unauthorized-user denial, `ListenerClose`, and
  `TestMultiplayerConcurrentOperators` (8 operators × 5 concurrent RPCs each,
  GetVersion+GetUsers) — all race-clean.
- **Interceptors:** `server/transport/recovery_test.go` (panic containment),
  `authz_e2e_test.go` (permission matrix).

## Constraint
`reeflective/team` is a workspace sibling. It was long treated as **read-only /
finished** (findings 2–5 were all fixed in Sliver-owned code — `client/transport`,
`server/transport`), but findings 6–7 could ONLY be fixed in the team lib (the cert
regeneration path and the user-record write are behind team's unexported `ts.certs`
and `db.User`), and were done there with explicit user direction.

When editing the team lib, mirror the change into BOTH:
- the sibling `/home/user/code/github.com/reeflective/team` (what `make`/workspace
  builds compile), and
- `vendor/github.com/reeflective/team/...` (what `-mod=vendor` and the deploy pipeline
  build) — keep the two byte-identical (`diff` them).

This vendor mirror is NOT durable: `go.mod` still pins team at a pseudo-version, so a
plain `go mod vendor` reverts the hand-edit. To ship for real (e.g. a BishopFox PR):
publish the team commit, re-pin `go.mod`, then regenerate vendor. Do NOT add `replace`
directives or switch the build to `-mod=vendor` (project constraint).
