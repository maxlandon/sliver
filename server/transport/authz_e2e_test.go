package transport

/*
   Sliver Implant Framework
   Copyright (C) 2019  Bishop Fox

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"
	"sync"
	"testing"

	"github.com/reeflective/team/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
)

const (
	crackstationMethod = "/rpcpb.SliverRPC/Crackstations"
	builderMethod      = "/rpcpb.SliverRPC/BuilderRegister"
)

// newTestTeamserver spins up a real reeflective/team core sharing Sliver's own
// (test-isolated) database, so authentication really verifies tokens and Sliver
// really resolves operators by name. Requires SLIVER_ROOT_DIR to point at a temp
// dir (set by the go test invocation) so we never touch a real ~/.sliver.
func newTestTeamserver(t *testing.T) *teamserver {
	t.Helper()

	core, err := server.New("sliver",
		server.WithDatabase(db.Client), // Share Sliver's (test-isolated) DB, incl. the Operator table.
		server.WithInMemory(),          // Keep the PKI/cert material in memory.
		server.WithNoLogs(true),
	)
	if err != nil {
		t.Fatalf("failed to create teamserver core: %s", err)
	}

	// ServeAddr runs the teamserver's one-time init (database + certificate
	// authority) before it looks up a listener; with no handler registered it
	// then returns ErrNoListener, which we ignore. This is the lightest way to
	// get the PKI initialized so UserCreate can mint user certificates.
	_, _ = core.ServeAddr("test-init", "localhost", 0)

	return &teamserver{Server: core, mutex: &sync.RWMutex{}}
}

// authenticate drives the real token-auth interceptor: it mints a user in the
// teamserver, persists its Sliver operator permissions, then feeds the raw token
// back through tokenAuthFunc exactly as an incoming gRPC request would.
func authenticate(t *testing.T, ts *teamserver, name string, operator *models.Operator) context.Context {
	t.Helper()

	cfg, err := ts.UserCreate(name, "localhost", 31337)
	if err != nil {
		t.Fatalf("UserCreate(%q) failed: %s", name, err)
	}

	if operator != nil {
		operator.Name = name
		if err := db.SaveOperator(operator); err != nil {
			t.Fatalf("SaveOperator(%q) failed: %s", name, err)
		}
	}

	// Present the token like a real client (Authorization: Bearer <token>).
	md := metadata.Pairs("authorization", "Bearer "+cfg.Token)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	newCtx, err := ts.tokenAuthFunc(ctx)
	if err != nil {
		t.Fatalf("tokenAuthFunc(%q) rejected a valid token: %s", name, err)
	}
	return newCtx
}

// assertMethod runs the unary permission interceptor for a given method and
// asserts whether it should be allowed (nil error, handler invoked) or denied.
func assertMethod(t *testing.T, ts *teamserver, ctx context.Context, method string, wantAllowed bool) {
	t.Helper()

	called := false
	handler := func(context.Context, interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}

	_, err := ts.permissionsUnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, handler)

	if wantAllowed {
		if err != nil {
			t.Errorf("method %s: expected ALLOWED, got error: %s", method, err)
		}
		if !called {
			t.Errorf("method %s: expected handler to run, it did not", method)
		}
		return
	}

	if err == nil {
		t.Errorf("method %s: expected DENIED, but it was allowed", method)
		return
	}
	if code := status.Code(err); code != codes.PermissionDenied {
		t.Errorf("method %s: expected PermissionDenied, got %s", method, code)
	}
	if called {
		t.Errorf("method %s: handler ran despite denial", method)
	}
}

// TestAuthorizationEndToEnd is the §6 definition-of-done check: it creates real
// users, connects them (token auth), and confirms that the typed operator model
// gates the builder/crackstation allow-lists correctly.
func TestAuthorizationEndToEnd(t *testing.T) {
	ts := newTestTeamserver(t)

	t.Run("full-permission operator passes everything", func(t *testing.T) {
		ctx := authenticate(t, ts, "admin", &models.Operator{PermissionAll: true})
		assertMethod(t, ts, ctx, crackstationMethod, true)
		assertMethod(t, ts, ctx, builderMethod, true)
		assertMethod(t, ts, ctx, "/rpcpb.SliverRPC/GetVersion", true)
	})

	t.Run("crackstation operator is denied builder-only method", func(t *testing.T) {
		ctx := authenticate(t, ts, "cracker", &models.Operator{PermissionCrackstation: true})
		// Allowed RPC (a crackstation method) passes...
		assertMethod(t, ts, ctx, crackstationMethod, true)
		// ...but a builder-only method for this non-builder operator is rejected.
		assertMethod(t, ts, ctx, builderMethod, false)
	})

	t.Run("builder operator is denied crackstation-only method", func(t *testing.T) {
		ctx := authenticate(t, ts, "builder", &models.Operator{PermissionBuilder: true})
		assertMethod(t, ts, ctx, builderMethod, true)
		assertMethod(t, ts, ctx, crackstationMethod, false)
	})

	t.Run("local console path bypasses auth with full permissions", func(t *testing.T) {
		ctx, err := serverAuthFunc(context.Background())
		if err != nil {
			t.Fatalf("serverAuthFunc failed: %s", err)
		}
		op, ok := ctx.Value(Operator).(*models.Operator)
		if !ok || op == nil || !op.PermissionAll {
			t.Fatalf("expected synthetic all-permission operator, got %#v", ctx.Value(Operator))
		}
		assertMethod(t, ts, ctx, builderMethod, true)
	})
}

// TestAuthenticatedUserWithoutOperatorIsDenied verifies that a validly
// authenticated user with no Sliver operator record is refused at token-auth
// time (authorization is Sliver's, and it has nothing on file for them).
func TestAuthenticatedUserWithoutOperatorIsDenied(t *testing.T) {
	ts := newTestTeamserver(t)

	cfg, err := ts.UserCreate("orphan", "localhost", 31337)
	if err != nil {
		t.Fatalf("UserCreate failed: %s", err)
	}

	md := metadata.Pairs("authorization", "Bearer "+cfg.Token)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	if _, err := ts.tokenAuthFunc(ctx); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for operator-less user, got %v", err)
	}
}

// TestOperatorPermissionRoundTrip is a focused DB check: SaveOperator persists
// typed permissions keyed by name and OperatorByName reads them back.
func TestOperatorPermissionRoundTrip(t *testing.T) {
	if err := db.SaveOperator(&models.Operator{Name: "roundtrip", PermissionBuilder: true}); err != nil {
		t.Fatalf("SaveOperator failed: %s", err)
	}

	got, err := db.OperatorByName("roundtrip")
	if err != nil {
		t.Fatalf("OperatorByName failed: %s", err)
	}
	if !got.PermissionBuilder || got.PermissionAll || got.PermissionCrackstation {
		t.Fatalf("unexpected permissions: %#v", got)
	}

	// Upsert: granting more permissions updates the same record.
	if err := db.SaveOperator(&models.Operator{Name: "roundtrip", PermissionAll: true}); err != nil {
		t.Fatalf("SaveOperator (update) failed: %s", err)
	}
	got, _ = db.OperatorByName("roundtrip")
	if !got.PermissionAll {
		t.Fatalf("expected upsert to set PermissionAll, got %#v", got)
	}
}
