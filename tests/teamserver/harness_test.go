package teamserver

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

// Package teamserver holds a sandbox-based integration suite for the Sliver
// teamserver/teamclient boundary. Each test spins up a REAL teamserver and a
// REAL teamclient, both in this process, wired over the same in-memory gRPC
// bufconn transport that Sliver's single-player console uses (see
// server/transport.clientOptionsFor). There is no socket, no TLS and no token
// on this path — it is exactly the local `sliver-server console` flow.
//
// Everything runs against an isolated SLIVER_ROOT_DIR (a throwaway temp dir the
// runner exports before `go test` starts — see run.sh). Because server/db
// initialises db.Client eagerly at package-init time, that variable MUST be set
// in the test process environment, not from inside a test; the runner guarantees
// it and TestMain fails loudly if it was forgotten.
//
// Every potentially-blocking operation is wrapped in a hard watchdog (within),
// so a deadlock surfaces as a failed test carrying a full goroutine dump rather
// than a silently hung `go test`.
import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc"

	teamserver "github.com/reeflective/team/server"

	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/server/transport"
)

// TestMain guards the one environmental precondition the whole suite depends on:
// an isolated SLIVER_ROOT_DIR. It must already point somewhere writable and
// throwaway BEFORE this binary started, because server/db opens the database at
// package-init (before TestMain runs), so setting it here would be too late.
func TestMain(m *testing.M) {
	if os.Getenv("SLIVER_ROOT_DIR") == "" {
		println("SLIVER_ROOT_DIR is not set; refusing to run against a real ~/.sliver.")
		println("Use ./tests/teamserver/run.sh (it exports a throwaway temp dir).")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// sandbox is an in-process teamserver+teamclient pair sharing one bufconn.
type sandbox struct {
	t    *testing.T
	Team *teamserver.Server    // the reeflective/team core, serving Sliver's RPC
	Con  *console.SliverClient // the real Sliver console client (its teamclient is connected)
	RPC  rpcpb.SliverRPCClient // an RPC client the test drives directly, over the same bufconn
	conn *grpc.ClientConn
}

// newSandbox builds a fresh teamserver, serves it on an in-memory bufconn, and
// connects a teamclient — the same sequence server/cli.preRunServerS performs
// for single-player mode, minus the cobra plumbing. The console's own con.Rpc is
// populated by an unexported, cobra-driven step we cannot reach from here, so we
// dial our own SliverRPC client over the identical bufconn options: same wire,
// same server, independently reachable.
func newSandbox(t *testing.T) *sandbox {
	t.Helper()

	sb := &sandbox{t: t}

	within(t, 15*time.Second, "newSandbox: build+serve+connect", func() {
		team, clientOpts, err := transport.NewTeamserver()
		if err != nil {
			t.Fatalf("NewTeamserver: %s", err)
		}
		sb.Team = team

		con, err := console.NewSliverClient(clientOpts...)
		if err != nil {
			t.Fatalf("NewSliverClient: %s", err)
		}
		sb.Con = con

		// Serve the in-memory transport and connect the console's teamclient.
		// Serve is non-blocking: it does `go grpcServer.Serve(bufconn)` then
		// cli.Connect(...).
		if err := team.Serve(con.Teamclient); err != nil {
			t.Fatalf("teamserver.Serve: %s", err)
		}

		// Our own RPC client over the same bufconn. The target host:port is
		// ignored because clientOpts carries a grpc.WithContextDialer bound to
		// the bufconn; creds are insecure on this local path.
		conn, err := grpc.DialContext(context.Background(), "bufnet", clientOpts...)
		if err != nil {
			t.Fatalf("grpc.DialContext(bufconn): %s", err)
		}
		sb.conn = conn
		sb.RPC = rpcpb.NewSliverRPCClient(conn)
	})

	t.Cleanup(sb.close)
	return sb
}

// close tears the sandbox down under a watchdog. The teardown path is itself a
// prime deadlock suspect: Sliver's mtls handler Close() is a no-op, the bufconn
// server goroutine is never joined, and team.Client.Disconnect juggles a
// sync.Once — so we time-box it and dump goroutines if it hangs.
func (sb *sandbox) close() {
	within(sb.t, 10*time.Second, "sandbox.close", func() {
		if sb.conn != nil {
			_ = sb.conn.Close()
		}
		if sb.Con != nil {
			// Disconnect the console's teamclient (grpc.ClientConn.Close +
			// resets the connect sync.Once).
			_ = sb.Con.Teamclient.Disconnect()
		}
	})
}

// within runs fn on its own goroutine and fails the test with a full goroutine
// dump if it does not finish within d. A genuinely deadlocked fn leaks its
// goroutine (unavoidable — it cannot be interrupted), but the dump pinpoints
// exactly where, and the test fails immediately instead of blocking until the
// global `go test -timeout` kills everything.
func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()

	select {
	case <-done:
	case <-time.After(d):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("DEADLOCK: %q did not finish within %s\n--- all goroutines ---\n%s", what, d, buf[:n])
	}
}

// ctx returns a context that is cancelled after d, registered for cleanup. Use
// it for individual RPC calls so a hung call fails fast rather than blocking.
func ctx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}

// goroutineCount is a coarse leak gauge for teardown stress tests.
func goroutineCount() int {
	return runtime.NumGoroutine()
}
