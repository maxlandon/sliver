# Sliver Client Subsystem — Architecture Context

## 1. Purpose

The `client/` tree is the **operator-facing side** of Sliver: the `sliver-client` binary and the shared library code that powers both it and the console embedded in `sliver-server`. It is an *interface-agnostic* client that talks to one or more remote Sliver **teamservers** over mutual-TLS gRPC. It provides three ways to drive the framework, all built on the same command tree:

- A **closed-loop REPL console** (the classic `sliver >` prompt).
- An **exec-once CLI** (`sliver-client <cmd> …` runs a single command and exits).
- A **Go API** (`SliverClient` methods + the gRPC `Rpc` client) for embedding.

The central object is `console.SliverClient` (`client/console/console.go`), which bundles a `reeflective/console` app, a `reeflective/team` client, the gRPC RPC stub, the active target, logging, and event handling.

## 2. Entrypoint & startup flow

`client/main.go` → seeds insecure rand, calls `cli.Execute()`.

`client/cli/cli.go`:
1. `client.NewSliverClient()` (`client/console/console.go`) builds the `SliverClient`: creates the `reeflective/console` app, loads settings/assets, creates the two menus (server `""` and implant `"implant"`), wires prompts/interrupt handlers, and constructs the `reeflective/team` client with a `transport.TeamClient` dialer (`transport.NewClient`).
2. `SliverCLI(con)` builds the whole cobra tree:
   - `command.ServerCommands(con, teamclientCmds)` → root cobra command (empty `Use`, renamed to `"sliver-client"`). Teamclient management commands come from `reeflective/team/client/commands.Generate`.
   - Adds the **console** subcommand (`client/command/console/console.go` → `sliverConsole.Command`).
   - Adds the **implant** subcommand (`client/cli/implant.go` → `implantCmd`) which exposes `command.SliverCommands(con)` from a system shell, gated by `--use/-s`.
   - `command.BindPreRun(root, con.PreRunConnect)` and `command.BindPostRun(root, con.PostRunDisconnect)` recursively attach connect/disconnect runners to every leaf command.
   - `bindServerConfig(con, root)` (`client/cli/version.go`) adds the persistent `--config/-c` flag ("Force connecting to a specific Sliver server") with a carapace completer sourced from `commands.ConfigsAppCompleter`.
   - `carapace.Gen(root)` generates completion.
3. `rootCmd.AddCommand(cmdVersion)` and `rootCmd.Execute()`.

**Connection** happens lazily inside `con.PreRunConnect` (`client/console/teamclient.go`): it filters commands for availability, skips connect for `isOffline` commands, runs pre-connect hooks, calls `con.loadConfig(cmd)` (reads `--config` if set, else the teamclient prompts among saved configs), then `con.Teamclient.Connect()` (a `sync.Once`), then `con.connect(con.dialer.Conn)` which instantiates `rpcpb.NewSliverRPCClient`, starts the event loop and tunnel loop, and registers history sources. The actual TLS dial is in `transport.TeamClient.Dial()`.

> Note: `bindServerConfig` was extracted into `client/cli/version.go` as part of the `dev`
> reconciliation graft (see `reconciliation-dev-vs-merger-fixes.md`).

## 3. Command architecture

- Every command group lives in `client/command/<group>/` with a `commands.go` exposing one or more **binder functions** of type `func(con *console.SliverClient) []*cobra.Command`. Example: `client/command/exec/commands.go` `Commands(con)`.
- Groups that behave differently in server vs implant menus export both `Commands` and `SliverCommands` (e.g. `sessions`, `info`, `transports`, `tcp`, `wireguard`).
- `client/command/server.go` (`ServerCommands`) and `client/command/sliver.go` (`SliverCommands`) are the two aggregators. Each creates a parent `*cobra.Command`, then uses the `makeBind` helper (`client/command/command.go`) to attach binder outputs under a named **help group** (constants like `consts.NetworkHelpGroup`), auto-creating cobra groups.
- Commands are built with plain cobra + `pflag`. Flags are attached via `flags.Bind(desc, persistent, cmd, func(f *pflag.FlagSet){…})` (`client/command/flags/flags.go`). Long help text comes from `help.GetHelpFor([]string{...})` reading the giant table in `client/command/help/long-help.go`.
- **Completions** use `carapace` (carapace-sh). Helpers in `client/command/completers/completers.go`: `NewCompsFor` (= `carapace.Gen`), `NewFlagCompsFor` (bind an `ActionMap` to flags), plus reusable completers (client interfaces, local proxy). Per-command completers are declared inline in each `commands.go`.
- **SliverCommands vs ServerCommands split**: server commands run without a target (payload gen, jobs, listeners, sessions/beacons list, armory, creds…). Sliver/implant commands require an active session/beacon (exec, filesystem, processes, pivots, portfwd…). `SliverCommands` additionally loads third-party **aliases** and **extensions** from `assets` manifests at build time.
- **Target filtering**: `command.RestrictTargets(...)`/`flags.RestrictTargets(...)` set a `console.CommandFilterKey` annotation ("windows", "beacon", "wireguard", etc.). `ActiveTarget.Filters()` (`client/console/implant.go`) computes forbidden filters from the current target; `con.FilterCommands` (`client/console/command.go`) hides mismatched commands.

## 4. Package map

| Package path | Role |
|---|---|
| `client/main.go` | Binary entrypoint; seeds rand, calls `cli.Execute()`. |
| `client/cli` | Root cobra tree assembly (`SliverCLI`), `version`, `--config` binding, implant-from-shell command. |
| `client/command` | Command aggregation: `ServerCommands`/`SliverCommands`, binders, pre/post-run wiring, target restriction. |
| `client/command/<~60 groups>` | One package per command group, each a `commands.go` yielding cobra commands (exec, filesystem, sessions, generate, armory, portfwd, …). |
| `client/command/completers` | Shared carapace completion helpers. |
| `client/command/flags` | `flags.Bind` flagset helper + `RestrictTargets`. |
| `client/command/help` | `GetHelpFor` + `long-help.go` (large static help text table). |
| `client/command/console` | The `console` subcommand that launches the closed-loop REPL. |
| `client/console` | Core `SliverClient` type: console app, teamclient, RPC, active target, events, logging, prompt, history. |
| `client/assets` | App dir layout, settings, and installed aliases/armories/c2profiles/extensions manifests (embedded `fs/`). |
| `client/constants` | Menu names, help-group IDs, command-filter tokens, command name strings, file names. |
| `client/core` | Client-side runtime state for tunnels, SOCKS proxies, port forwards, reactions, BOF arg buffers, cursed (chrome) processes. |
| `client/credentials` | Password/hash utilities: hash-type detection, hashcat mode mapping, credential sniffing (`sniff.go`). |
| `client/transport` | gRPC dialer implementing `team/client.Dialer` + TLS/token auth and logrus logging middleware. |
| `client/version` | Build version info (`SemanticVersion`, `GitCommit`, `Compiled`) and update-check logic (`updates.go`). |
| `client/spin` | Terminal spinner used for progress display. |
| `client/tcpproxy` | Embedded TCP proxy implementation used by port-forwarding/SOCKS. |
| `client/overlord` | Chrome DevTools (chromedp/CDP) driver for the "cursed" browser-injection features. |
| `client/packages` | Output-schema formatting for extension/alias structured output (tables from JSON). |
| `client/licenses` | Embedded GPL/third-party license text for the `licenses` command. |

## 5. Console & UX

- Built on **`reeflective/console`** (`con.App`, a `*console.Console`) and **`reeflective/readline`**.
- Two **menus** created in `newClient()`: server menu (name `""`, `consts.ServerMenu`) and implant menu (`consts.ImplantMenu`). Each has its own prompt (`con.GetPrompt` in `client/console/readline.go`), interrupt handlers (Ctrl-C exits console; Ctrl-D exits implant menu back to server), and history sources.
- `StartConsole()` (`console.go`) flips `isCLI=false`, switches `printf` to `App.TransientPrintf` (so async event logs can redraw around the prompt), registers a `PreCmdRunLineHooks` to capture each command line (needed for beacon task command-line attachment), and calls `con.App.Start()` (blocking).
- The `console` subcommand (`client/command/console/console.go`) binds `serverCmds` to the server menu and `command.SliverCommands(con)` to the implant menu via `menu.SetCommands`, loads reactions, then starts.
- **Menu switching** is automatic via `ActiveTarget.Set/Background` (`client/console/implant.go`): selecting a session/beacon switches to the implant menu and re-filters commands; backgrounding returns to server menu.
- **Pre/Post runners**: in CLI mode, `command.BindPreRun`/`BindPostRun` attach `PreRunConnect`/`PostRunDisconnect` to leaf commands so each invocation connects and disconnects. In console mode there is a single long-lived connection (the console command connects once). `PreRunConnect` also runs command-availability checks and, for completion invocations (`compCommandCalled`), skips log/asciicast streaming.

## 6. Transport

`client/transport/` implements the `reeflective/team/client.Dialer` interface:
- `client.go` — `TeamClient` holds `[]grpc.DialOption`, the `*grpc.ClientConn` (`Conn`, exposed so the console can build the RPC stub), and an injected `*logrus.Logger`. `Init()` assembles options (2 GB max recv size, logging middleware, and TLS+token auth via `TLSAuthMiddleware` when the config has a private key; otherwise treats it as an in-memory dialer with no TLS). `Dial()` does `grpc.DialContext(host:port, …)`; `Close()` closes the conn.
- `middleware.go` — `LogMiddlewareOptions` sets up `grpc_logrus` unary interceptors (plus a raw-JSON request-logging interceptor) with a `codeToLevel` mapping; `grpc.WithBlock()` is used. `TLSAuthMiddleware` builds mTLS creds from `CACertificate/Certificate/PrivateKey` and per-RPC `TokenAuth` bearer credentials. `ClientMaxReceiveMessageSize` = ~2 GB.
- Note the slog/logrus bridge: `reeflective/team` core now emits **slog**, but the gRPC middleware still needs **logrus**, so `NewSliverClient` creates one logrus logger (`initTeamclientLog`) for the middleware and a slog `TextHandler` over the same writer for the team core.

## 7. Build tags

- Client binary is built with `CGO_ENABLED=0 go build -tags go_sqlite,client` (see `Makefile`, e.g. `client` target ~line 115).
- **`go_sqlite`** — selects the pure-Go SQLite driver (`server/db/sql-go.go`, guarded `//go:build go_sqlite`) instead of the cgo driver (`sql-cgo.go`, `//go:build cgo_sqlite`). This keeps the client CGO-free and cross-compilable (macOS/linux/windows, amd64/arm64/386 targets all in the Makefile).
- **`client`** — a marker/consistency tag applied to the whole `./client` build. There are no `//go:build client` gates inside `client/` source itself (the client tree simply doesn't import server-only packages); the tag exists to pair with `go_sqlite` and to exclude server-only build paths where relevant.

## 8. Key files to know

- `client/cli/cli.go` — assembles the entire cobra tree (`SliverCLI`); best single overview of wiring.
- `client/console/console.go` — defines `SliverClient` struct and `NewSliverClient`/`newClient`/`StartConsole`; the object every command receives.
- `client/console/teamclient.go` — `PreRunConnect`/`PreRunComplete`/`PostRunDisconnect` and `connect()`; the connection lifecycle.
- `client/command/server.go` — `ServerCommands` aggregator + `BindPreRun`/`BindPostRun`.
- `client/command/sliver.go` — `SliverCommands` aggregator; also where aliases/extensions get loaded.
- `client/command/command.go` — `makeBind`, `commandBinder`, `RestrictTargets`; the binding/grouping mechanism.
- `client/console/implant.go` — `ActiveTarget` type, target selection, menu switching, `Request()` (builds `commonpb.Request` with beacon/session + timeout), `Filters()`.
- `client/console/command.go` — `FilterCommands`, `isOffline`/`offlineCommands`, pre-connect hook registration.
- `client/cli/implant.go` — running implant commands from a system shell (`--use`), `preRunImplant`/`postRunImplant`.
- `client/command/console/console.go` — the `console` subcommand that starts the REPL.
- `client/transport/client.go` + `middleware.go` — the gRPC dialer and TLS/logging middleware.
- `client/command/completers/completers.go` — carapace completion helper entrypoints.
- `client/command/exec/commands.go` — canonical example of the per-group `commands.go` pattern (cobra + flags.Bind + carapace).
- `client/constants/constants.go` — menu names, help-group IDs, and command-filter tokens referenced everywhere.
- `client/console/log.go` — client log/asciicast streaming, `Printf`/`PrintInfof`/`PrintErrorf` and the logrus-init bridge.

## 9. Gotchas / where to look for X

- **"How does it decide to connect?"** — `PreRunConnect` (`console/teamclient.go`); connection is lazy and `sync.Once`-guarded inside the teamclient. Completion runs also connect (see `implant.go` carapace `PreRun` and `PreRunComplete`).
- **Offline commands** (help, update, licenses, settings, teamclient import) — hardcoded in `offlineCommands` in `console/command.go`, not annotation-driven.
- **Why a command is hidden for a target** — `ActiveTarget.Filters()` (`console/implant.go`) + `RestrictTargets` annotations + `isFiltered` (`console/command.go`). CLI mode also adds `ConsoleCmdsFilter` to hide console-only commands.
- **Server vs implant duplication** — many groups export both `Commands` and `SliverCommands`; check `server.go`/`sliver.go` to see which menu a command lands in.
- **Beacon vs session semantics** — `ActiveTarget.Request()` sets `Async=true`/`BeaconID` for beacons vs `Async=false`/`SessionID` for sessions; command-line is attached from `con.Args` (captured differently in CLI vs console — see `logCommand`/`PreCmdRunLineHooks`).
- **Logging is dual-stack** — slog (team core) + logrus (gRPC middleware) over one file; if adding transport logging, mind `initTeamclientLog` and `LogMiddlewareOptions`.
- **Aliases/extensions** are loaded at `SliverCommands` build time from `assets.GetInstalledAliasManifests`/`GetInstalledExtensionManifests`; a command "missing" may be an uninstalled extension, not code.
- **Tunnels/SOCKS/portfwd state** lives in `client/core` (client-side), distinct from server state; the tunnel loop starts in `connect()` via `core.TunnelLoop`.
- **"Cursed" browser features** — logic split between `client/command/cursed/`, `client/core/curses.go`, and `client/overlord/` (chromedp/CDP).
