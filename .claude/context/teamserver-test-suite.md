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
`reeflective/team` is a workspace sibling but is **read-only / finished** — do not
modify it. Findings 2–4 are all fixable in Sliver-owned code (`client/transport`,
`server/transport`). Finding 4 is partly rooted in team-lib listener lifecycle, so a
Sliver-side wrapper is the right layer.
