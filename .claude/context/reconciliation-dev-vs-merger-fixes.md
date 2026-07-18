# Reconciliation: `dev` vs `merger-fixes` — dossier & proof

**Status:** COMPLETE. The reconciliation merge is done and proven total.
**Result branch:** `reconcile-dev-merger-fixes` @ merge commit (parents `merger-fixes` `dev`).
**Date of audit:** 2026-07-18.

---

## TL;DR

`dev` contributes **exactly one** original patch that `merger-fixes` did not already
have: the `bindServerConfig` refactor (`1ed02a134`). It has been grafted. Everything
else that looks like "dev has it and merger-fixes doesn't" is **stale code that upstream
Sliver deliberately deleted**, which `dev` still carries only because `dev` branched from
an **older** master. There is nothing else to preserve. The `git merge -s ours dev` +
graft strategy produced the correct, complete tree.

---

## Topology (the ground truth)

- `merge-base(dev, merger-fixes)` = `dcebd2dda` ("Merge branch 'master' …", 2025-02-13).
- Local `master` ref **is** `dcebd2dda` (same commit).
- `dev` = `2a026c976` — a **content merge** ("Merge branch 'master' into dev") with parents
  `1ed02a134` (bindServerConfig) and `dcebd2dda`.
- `merger-fixes` = `dcebd2dda` evolved forward by 4 commits, ending in
  `920b88d6f` ("Adapt Sliver to auth-only reeflective/team; restore typed operator RBAC").

Both branches are **independent reeflective/team integration attempts** off a shared
lineage. `dev` is the earlier attempt (Feb 2025) that then went dormant; `merger-fixes`
is the continuation that finished the job (full auth-only migration + later master merges).

> **Trap:** `git cherry` / patch-id is **unreliable here** because `2a026c976` is a
> criss-cross content merge. Do not conclude "only 1 unique commit" from `git cherry`
> alone — that was luck, not proof. Trust the **content diff**, which is what this dossier does.

## What `dev` actually adds (content diff, source only)

`git diff merger-fixes dev` (excluding vendor + generated `*.pb.go`/`*.pb.ts` + docs):
**363 files, +4228 / −66174**. The −66174 is `merger-fixes` being far ahead (auth work +
master merges). The +4228 is `dev` holding **older** versions of files. Broken down:

### Files present in `dev` but ABSENT in `merger-fixes` — the scary list, all resolved

| Path(s) in dev | Verdict | Evidence |
|---|---|---|
| `client/prelude/*`, `client/command/prelude-operator/*` | **STALE — do not restore** | Upstream removed it: `723eca2dd Remove prelude operator support`. Absent in `master`/base. |
| `client/command/generate/generate-stager.go` | **STALE — do not restore** | Upstream removed it: `0deaee625 Removing generate msf-stager command`. |
| `implant/sliver/screen/screenshot_darwin.go` | **Superseded, not lost** | `merger-fixes` has `screenshot_generic.go` with `//go:build !windows && !linux`, which **covers darwin**. Build-tag consolidation. |

### Files present in `merger-fixes` but ABSENT in `dev` — merger-fixes is richer

`merger-fixes` additionally has (dev lacks): `client/command/certificates/*`,
`client/command/clean/*`, `client/command/filesystem/mount.go`,
`client/command/processes/services.go`, `server/rpc/rpc-certificates.go`,
`implant/sliver/mount/*`, and this session's auth work
(`server/transport/authz_e2e_test.go`, `TEAM_AUTH_HANDOFF.md`). All expected: merger-fixes
is newer.

### dev's refactor commits — ALL already in merger-fixes

Every substantive `dev` refactor commit is an **ancestor of `merger-fixes`** (shared history),
verified with `git merge-base --is-ancestor`:

- `dc6be7cfe` Command tree refactoring — IN merger-fixes
- `7b1721bac` Return error on failed armory completion cache — IN merger-fixes
- `13f4ea3ee` Re-add persistent listeners — IN merger-fixes
- `cfaf517c3` Fix permissions for users and in middleware — IN merger-fixes **(then reversed by the auth work — this is the permissions "capitulation" the handoff told us to undo)**
- `14b0bfba8` Commented-out permissions middleware — IN merger-fixes
- `669524528` Update console/team deps + vendor — IN merger-fixes
- `a6a3e7875` Compiles — IN merger-fixes

## The one genuine graft: `bindServerConfig` (`1ed02a134`)

Extracts the root `--config/-c` flag binding out of `SliverCLI` into a helper.
Applied to `merger-fixes`'s tree as:

- `client/cli/cli.go` — inline flag block replaced with `bindServerConfig(con, root)`;
  dropped the now-unused `completers` import.
- `client/cli/version.go` — added the `bindServerConfig` helper + its imports.

**Two deliberate deviations from dev's literal patch:**
1. Dropped dev's duplicate `bindServerConfig` in `client/command/server.go` (package
   `command`, never referenced — dead code).
2. Used the current `github.com/carapace-sh/carapace` import path (dev predated the
   `rsteube/carapace` → `carapace-sh/carapace` rename).

## Verification performed

- `sliver-client` builds (`-tags "client go_sqlite"`).
- `sliver-server` builds (`-tags "server go_sqlite"`).
- `go vet ./client/cli/...` clean.
- Auth e2e suite passes (`server/transport/authz_e2e_test.go`): full-perm passes all,
  crackstation denied builder method, builder denied crackstation method, local-console
  bypass, operator-less user denied, SaveOperator/OperatorByName roundtrip+upsert.
- `-c/--config` present in built client `--help`.
- Zero conflict markers in the tree.

## Residual / optional follow-ups

- **Darwin implant screenshot:** confirm `implant/sliver/screen/screenshot_generic.go`
  actually compiles/works on darwin (it should — the build tag covers it). Only matters if
  you build darwin implants.
- **Branch disposition:** decide whether to fast-forward `merger-fixes` onto the
  reconciliation commit, or keep the reconciliation branch as a reviewed record.

## Method to re-verify (if ever doubted)

```bash
git merge-base dev merger-fixes                    # -> dcebd2dda (== master)
git diff --name-status merger-fixes dev -- . ':(exclude)vendor/*' ':(exclude)*.pb.go'
git log --oneline --all --diff-filter=D -- client/prelude/prelude.go   # -> 723eca2dd
git merge-base --is-ancestor <dev-refactor-commit> merger-fixes && echo shared
```
