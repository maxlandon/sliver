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

// This file covers the MULTIPLAYER path: a real TCP+mTLS gRPC listener and a
// remote teamclient authenticating with a per-user certificate and token — the
// path an operator actually uses to reach a remote sliver-server. It complements
// tests/teamserver (the in-memory single-player bufconn path).
//
// Like authz_e2e_test.go it lives in `package transport` so it can build the mtls
// handler WITHOUT the in-memory bufconn shim (NewTeamserver hard-wires that), and
// requires SLIVER_ROOT_DIR to point at a throwaway dir (set by the go test
// invocation) so it never touches a real ~/.sliver.
import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	teamclient "github.com/reeflective/team/client"
	"github.com/reeflective/team/server"

	clienttransport "github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/server/assets"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"
)

// newRealTeamserver builds a teamserver serving a real TCP+mTLS gRPC listener on
// an ephemeral loopback port. It mirrors NewTeamserver but deliberately omits the
// bufconn shim (clientOptionsFor), so the mtls handler binds an actual socket. It
// returns the core, the listener job id, and the port.
func newRealTeamserver(t *testing.T) (*server.Server, string, uint16) {
	t.Helper()

	// Only the TLS handler; no Tailscale (would need TS_AUTHKEY).
	tlsListener := newTeamserverTLS()

	core, err := server.New("sliver",
		server.WithHomeDirectory(assets.GetRootAppDir()),
		server.WithLogger(log.RootSlogHandler()),
		server.WithDatabase(db.Client),
		server.WithHandler(tlsListener), // localListener stays nil -> real net.Listen
	)
	if err != nil {
		t.Fatalf("server.New: %s", err)
	}

	port := freePort(t)

	// ServeAddr runs one-time init (DB + certificate authority) and then binds
	// the real mTLS listener. It is non-blocking (returns a job id).
	var id string
	withDeadline(t, 15*time.Second, "ServeAddr(real mTLS)", func() {
		id, err = core.ServeAddr(tlsListener.Name(), "127.0.0.1", port)
	})
	if err != nil {
		t.Fatalf("ServeAddr(127.0.0.1:%d): %s", port, err)
	}

	return core, id, port
}

// connectRemote creates a real user on the server (minting a client cert + token),
// grants it a Sliver operator record, then dials the listener over mTLS as that
// user and returns a live SliverRPC client. The dialer is the very same
// client/transport.TeamClient the sliver-client binary uses.
// connectRemoteE is the goroutine-safe core of connectRemote: it returns errors
// instead of calling t.Fatalf, so it can be used from concurrent goroutines (where
// t.Fatalf is forbidden). It creates the user + operator record and dials over mTLS.
func connectRemoteE(core *server.Server, port uint16, name string, op *models.Operator) (rpcpb.SliverRPCClient, *teamclient.Client, error) {
	cfg, err := core.UserCreate(name, "127.0.0.1", port)
	if err != nil {
		return nil, nil, fmt.Errorf("UserCreate(%s): %w", name, err)
	}
	if cfg.PrivateKey == "" || cfg.Token == "" {
		return nil, nil, fmt.Errorf("UserCreate(%s) returned an incomplete config (key/token empty)", name)
	}

	// Authorization is Sliver's: the authenticated user needs a matching operator
	// record or token-auth rejects it (see TestAuthenticatedUserWithoutOperatorIsDenied).
	op.Name = cfg.User
	if err := db.SaveOperator(op); err != nil {
		return nil, nil, fmt.Errorf("SaveOperator(%s): %w", name, err)
	}

	dialer := clienttransport.NewClient()
	tc, err := teamclient.New("sliver",
		teamclient.WithDialer(dialer),
		teamclient.WithConfig(cfg),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("teamclient.New(%s): %w", name, err)
	}

	if err := tc.Connect(); err != nil {
		return nil, nil, fmt.Errorf("teamclient.Connect(%s): %w", name, err)
	}
	if dialer.Conn == nil {
		return nil, nil, fmt.Errorf("dialer produced a nil gRPC connection after Connect(%s)", name)
	}

	return rpcpb.NewSliverRPCClient(dialer.Conn), tc, nil
}

// connectRemote is the watchdog'd, t.Fatalf-on-error wrapper for single-goroutine
// use (the test goroutine).
func connectRemote(t *testing.T, core *server.Server, port uint16, name string, op *models.Operator) (rpcpb.SliverRPCClient, *teamclient.Client) {
	t.Helper()

	var (
		rpc rpcpb.SliverRPCClient
		tc  *teamclient.Client
		err error
	)
	withDeadline(t, 20*time.Second, "connectRemote(mTLS)", func() {
		rpc, tc, err = connectRemoteE(core, port, name, op)
	})
	if err != nil {
		t.Fatalf("connect remote: %s", err)
	}
	return rpc, tc
}

// TestMultiplayerConnectAndRPC drives the full remote handshake: real mTLS
// listener, per-user cert + token auth, and an authorized RPC round-trip.
func TestMultiplayerConnectAndRPC(t *testing.T) {
	core, listenerID, port := newRealTeamserver(t)

	rpc, tc := connectRemote(t, core, port, "operator", &models.Operator{PermissionAll: true})
	t.Cleanup(func() {
		withDeadline(t, 10*time.Second, "teamclient.Disconnect", func() { _ = tc.Disconnect() })
	})

	withDeadline(t, 10*time.Second, "GetVersion over mTLS", func() {
		v, err := rpc.GetVersion(ctxWithTimeout(t, 5*time.Second), &commonpb.Empty{})
		if err != nil {
			t.Fatalf("GetVersion over mTLS failed: %s", err)
		}
		t.Logf("multiplayer server version: %d.%d.%d", v.Major, v.Minor, v.Patch)
	})

	// Closing the listener is the teardown path flagged as a deadlock suspect
	// (unbuffered kill channel in the team core). Time-box it.
	withDeadline(t, 10*time.Second, "ListenerClose", func() {
		if err := core.ListenerClose(listenerID); err != nil {
			t.Errorf("ListenerClose(%s): %s", listenerID, err)
		}
	})
}

// TestMultiplayerUnauthorizedUserDenied verifies the remote path enforces
// authorization: a user with a valid cert+token but NO operator record is
// rejected (authentication succeeds, authorization does not).
func TestMultiplayerUnauthorizedUserDenied(t *testing.T) {
	core, listenerID, port := newRealTeamserver(t)
	t.Cleanup(func() {
		withDeadline(t, 10*time.Second, "ListenerClose", func() { _ = core.ListenerClose(listenerID) })
	})

	cfg, err := core.UserCreate("ghost", "127.0.0.1", port)
	if err != nil {
		t.Fatalf("UserCreate: %s", err)
	}
	// Intentionally do NOT SaveOperator for this user.

	dialer := clienttransport.NewClient()
	tc, err := teamclient.New("sliver", teamclient.WithDialer(dialer), teamclient.WithConfig(cfg))
	if err != nil {
		t.Fatalf("teamclient.New: %s", err)
	}
	withDeadline(t, 15*time.Second, "teamclient.Connect", func() { _ = tc.Connect() })
	t.Cleanup(func() { _ = tc.Disconnect() })

	rpc := rpcpb.NewSliverRPCClient(dialer.Conn)
	withDeadline(t, 10*time.Second, "GetVersion (should be denied)", func() {
		if _, err := rpc.GetVersion(ctxWithTimeout(t, 5*time.Second), &commonpb.Empty{}); err == nil {
			t.Fatal("expected an operator-less user to be denied, but the RPC succeeded")
		}
	})
}

// TestMultiplayerConcurrentOperators connects many operators at once, each firing
// several concurrent RPCs, all under -race and a hard watchdog. It shakes out
// server-side data races and connection/serve deadlocks a single-client test can't:
// concurrent mTLS handshakes, concurrent token-auth cache access, and concurrent RPC
// handling against the shared teamserver core.
func TestMultiplayerConcurrentOperators(t *testing.T) {
	core, listenerID, port := newRealTeamserver(t)
	t.Cleanup(func() {
		withDeadline(t, 10*time.Second, "ListenerClose", func() { _ = core.ListenerClose(listenerID) })
	})

	const operators = 8
	const rpcsPerOperator = 5

	var wg sync.WaitGroup
	errCh := make(chan error, operators*rpcsPerOperator*2+operators)

	withDeadline(t, 45*time.Second, "concurrent operators connect+RPC", func() {
		for i := 0; i < operators; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				name := fmt.Sprintf("op-%d", n)

				rpc, tc, err := connectRemoteE(core, port, name, &models.Operator{PermissionAll: true})
				if err != nil {
					errCh <- err
					return
				}
				defer func() { _ = tc.Disconnect() }()

				var rwg sync.WaitGroup
				for j := 0; j < rpcsPerOperator; j++ {
					rwg.Add(1)
					go func() {
						defer rwg.Done()
						if _, err := rpc.GetVersion(ctxWithTimeout(t, 5*time.Second), &commonpb.Empty{}); err != nil {
							errCh <- fmt.Errorf("%s GetVersion: %w", name, err)
						}
						if _, err := rpc.GetUsers(ctxWithTimeout(t, 5*time.Second), &commonpb.Empty{}); err != nil {
							errCh <- fmt.Errorf("%s GetUsers: %w", name, err)
						}
					}()
				}
				rwg.Wait()
			}(i)
		}
		wg.Wait()
	})

	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent operator error: %s", err)
	}
}

// TestListenerCloseInvalidID confirms ListenerClose on an unknown id returns a
// not-found error rather than blocking on the unbuffered kill channel. (Closing an
// already-removed listener is the documented double-close deadlock hot-spot; this
// deterministic sibling at least pins the not-found path.)
func TestListenerCloseInvalidID(t *testing.T) {
	core, listenerID, _ := newRealTeamserver(t)
	t.Cleanup(func() {
		withDeadline(t, 10*time.Second, "ListenerClose(real)", func() { _ = core.ListenerClose(listenerID) })
	})

	withDeadline(t, 5*time.Second, "ListenerClose(bogus id)", func() {
		if err := core.ListenerClose("does-not-exist"); err == nil {
			t.Error("expected an error closing a non-existent listener, got nil")
		}
	})
}

// freePort grabs an ephemeral loopback port and immediately frees it. The small
// race window before ServeAddr re-binds is acceptable for a local test.
func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve free port: %s", err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// withDeadline runs fn on its own goroutine and fails with a full goroutine dump
// if it does not return within d — so a connection/close deadlock surfaces as a
// precise failure instead of a hung test.
func withDeadline(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("DEADLOCK: %q did not finish within %s\n--- all goroutines ---\n%s", what, d, buf[:n])
	}
}

func ctxWithTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}
