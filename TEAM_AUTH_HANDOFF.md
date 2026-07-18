# Handoff: adapting Sliver to the auth-only `reeflective/team` library

**Audience:** an agent working in the Sliver repo (`/home/user/code/github.com/maxlandon/sliver`).
**Author:** an agent that just reworked the `github.com/reeflective/team` library at
`/home/user/code/github.com/reeflective/team` (local working tree, **uncommitted**).
**Status of that work:** library-side prototype complete, builds + vets + tests pass. **Sliver side not started — that's your job.**

> ⚠️ Line numbers below for *Sliver* files come from an exploration snapshot and may have drifted.
> Treat them as "look near here," and re-verify against the current tree before editing.
> The `reeflective/team` API facts, by contrast, are authoritative (I just wrote them).

---

## 1. What changed in the `team` library, in one sentence

The teamserver is now an **authentication + PKI authority only**. It proves *who* is calling and
**owns no authorization model whatsoever** — no permissions, no roles, nothing to interpret.
Authorization is 100% the embedding application's job (i.e. Sliver's).

### Why this happened (the original problem)

Sliver's per-user RBAC middleware (`permissionsUnaryServerInterceptor` /
`permissionsStreamServerInterceptor`) was originally written against Sliver's own typed
`models.Operator` (boolean fields `PermissionAll` / `PermissionBuilder` / `PermissionCrackstation`).
But the only authentication seam the library exposed — `Server.UserAuthenticate` — returned a
**fixed `*team.User` whose permissions were a flat `[]string`**. Sliver's interceptor could never
receive its own `*models.Operator` type, so historically the RBAC code was **commented out**
(Sliver commit `14b0bfba8`), and later **capitulated** to the library's model (Sliver commit
`cfaf517c3` rewrote the interceptors to read `team.User.Permissions []string` via
`slices.Contains`). That capitulation is exactly what the library owner wants to undo.

The new direction **reverses `cfaf517c3`**: go back to enforcing on Sliver's *own* typed operator
model — but resolve that model from Sliver's *own* store, keyed by the authenticated user name,
instead of from `team.User`.

---

## 2. The new `team` library API (authoritative)

Changes made in `/home/user/code/github.com/reeflective/team`:

| Symbol | Before | After |
|---|---|---|
| `team.User` (`teamclient.go`) | had `Permissions []string` | **field removed.** Now only `Name`, `Online`, `LastSeen`, `Clients` |
| `Server.UserAuthenticate` (`server/users.go`) | `UserAuthenticate(token) (*team.User, bool, error)` | **renamed + reshaped:** `Authenticate(token) (*team.User, error)` — pure verification primitive, returns identity, no bool |
| `Server.UserCreate` (`server/users.go`) | `UserCreate(name, host, port, perms ...string)` | **`UserCreate(name, host, port)`** — no perms |
| `db.User` (`internal/db/user.go`) | had `Permissions pq.StringArray` column + a dead `Permissions` struct | both removed |
| CLI (`server/commands/`) | `--permissions`/`-P` flag | **removed** |

Everything else (PKI, mTLS via `UsersTLSConfig()`, token issuance/storage, `Users()`,
the `Handler`/`Dialer` transport interfaces, `Self()`) is unchanged. Context injection was
**never** done by the core — it has always lived in the transport middleware. The only core
coupling to request identity was `UserAuthenticate`'s return type; that's what got cut.

**New usage pattern (what your interceptor should look like):**
```go
// authentication: ask the teamserver WHO is calling (identity only)
user, err := ts.Authenticate(rawToken)   // *team.User{Name,...}, no perms
if err != nil || user.Name == "" { /* reject: codes.Unauthenticated */ }

// authorization: YOUR job. Resolve the name against YOUR model, inject YOUR type.
op := yourStore.OperatorByName(user.Name)      // *models.Operator (typed perms)
ctx = context.WithValue(ctx, YourOperatorKey, op)
```

---

## 3. How to actually consume the changes (do this FIRST)

Sliver currently pins **`github.com/reeflective/team v0.2.1`** and **vendors** it
(`vendor/github.com/reeflective/team`), with **no `replace` directive**. That vendored copy is the
frozen v0.2.1 release and does **not** contain any of the changes above. So before touching Sliver
code, point Sliver at the local working tree:

```
# in Sliver's go.mod
replace github.com/reeflective/team => /home/user/code/github.com/reeflective/team
```
then `go mod tidy && go mod vendor` (or drop vendoring while iterating).

Until you do this, you'll be compiling against the *old* API and the guidance below won't match.
(Coordinate with the human: the library changes are uncommitted/untagged, so a real release will
eventually replace the `replace`.)

---

## 4. What to change in Sliver (the actual work)

All the auth/permission logic lives in **`server/transport/middleware.go`** (plus a couple of
touch points). Snapshot references — re-verify:

1. **`tokenAuthFunc`** (~`middleware.go:182-205`): calls `ts.UserAuthenticate(rawToken)` returning
   `(user, authorized, err)`. Change to `ts.Authenticate(rawToken)` returning `(user, err)` and drop
   the `authorized` bool. It currently stores the `*team.User` in context under keys `Transport` and
   `Operator` — instead, resolve Sliver's `*models.Operator` from `user.Name` and store *that* under
   the `Operator` key (keep `team.User` under `Transport` if you still want the raw identity).

2. **`permissionsUnaryServerInterceptor` / `permissionsStreamServerInterceptor`**
   (~`middleware.go:245-310`): after `cfaf517c3` these read `ctx.Value(Operator).(*team.User)` and do
   `slices.Contains(operator.Permissions, "all"/"builder"/"crackstation")` against the
   `builderMethods` / `crackstationMethods` allow-lists (~`middleware.go:215-243`) and the
   `Permission` string constants (~`middleware.go:207-213`). Rewrite to read
   `ctx.Value(Operator).(*models.Operator)` and enforce with its typed booleans
   (`PermissionAll` / `PermissionBuilder` / `PermissionCrackstation`). You can delete the
   `team`-based `Permission` string constants and the `slices` import if nothing else needs them.

3. **`serverAuthFunc`** (~`middleware.go:170-179`, the in-memory/local console path): currently
   injects a synthetic `team.User{Name:"server", Permissions:["all"]}`. Change it to inject a
   synthetic `*models.Operator` with all permissions set.

4. **`models.Operator`** (~`server/db/models/operator.go:37-39`): this is Sliver's typed permission
   model (`PermissionAll` / `PermissionBuilder` / `PermissionCrackstation`). It must become the
   source of truth again. Confirm the operator table still exists and is migrated. This is where the
   permissions the library no longer stores must now live, keyed by user name.

5. **User creation / permission assignment:** wherever Sliver calls `serv.UserCreate(name, host,
   port, perms...)`, drop the `perms...` (the library signature no longer accepts them) and instead
   persist the operator's permissions to Sliver's own operator table. If Sliver had a `--permissions`
   flow that leaned on the library's flag, re-add it as Sliver's own flag on Sliver's own user/operator
   command, writing to the operator table. (The library's `--permissions`/`-P` flag is gone.)

6. **Client side** (`client/transport/client.go`, `client/transport/middleware.go`): should need no
   change for this — it only sends the bearer token. Verify it still builds against the new API.

7. **CommonName / identity extraction** (`server/rpc/rpc.go:169-185` `getClientCommonName`, and
   `middleware.go:364-376` `getUser`): unaffected by the type change, but re-verify they still
   compile if you alter what's stored in context.

---

## 5. What NOT to do

- **Do not** edit anything under `/home/user/code/github.com/reeflective/team` — that side is done.
  Your job is entirely within the Sliver repo (plus the `replace`/vendor wiring).
- **Do not** reintroduce a `[]string` permission model or read `team.User.Permissions` — that field
  no longer exists and reintroducing that coupling is precisely what we're undoing.
- **Do not** try to make the library store Sliver's permissions. It won't. Sliver owns them.

---

## 6. Definition of done

- Sliver builds and vets against the local `reeflective/team` (via the `replace`).
- The permission interceptors are **live** (not commented out) and enforce on `*models.Operator`.
- Auth still works: a token minted by `UserCreate` authenticates via `Authenticate`, and the
  resolved operator's typed permissions gate the builder/crackstation method allow-lists.
- The in-memory local console path still bypasses auth with a full-permission synthetic operator.
- Verify end-to-end, not just compile: create a user, connect a client, confirm an allowed RPC
  passes and a disallowed one (e.g. a builder-only method for a non-builder operator) is rejected.

---

## 7. Background commits (Sliver history, for context)

- `14b0bfba8` "Add commented out permissions middleware builder/crack" — where the RBAC interceptors
  were first added but left commented out due to the type mismatch.
- `cfaf517c3` "Fix permissions for users and in middleware" — the capitulation to `team.User`'s
  `[]string` permissions. **Your task effectively supersedes this commit's approach.**
