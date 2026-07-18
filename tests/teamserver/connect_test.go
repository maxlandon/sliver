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

import (
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// TestConnectAndVersion is the smoke test: stand up the full in-process
// teamserver/teamclient stack, then make a real RPC round-trip (GetVersion).
// If the local single-player connect path is broken or deadlocks, this fails
// here — the cheapest possible signal.
func TestConnectAndVersion(t *testing.T) {
	sb := newSandbox(t)

	var major, minor, patch int32
	within(t, 5*time.Second, "GetVersion round-trip", func() {
		ver, err := sb.RPC.GetVersion(ctx(t, 3*time.Second), &commonpb.Empty{})
		if err != nil {
			t.Fatalf("GetVersion RPC failed: %s", err)
		}
		major, minor, patch = ver.Major, ver.Minor, ver.Patch
	})

	// A well-formed version response is enough to prove the whole chain
	// (dialer -> bufconn -> gRPC server -> RPC handler -> DB-backed core) is live.
	t.Logf("server version: %d.%d.%d", major, minor, patch)
}

// TestRepeatedConnectDisconnect stresses the teardown path the connection-map
// flagged as a deadlock/leak suspect: mtls Close() is a no-op, the bufconn
// server goroutine is never joined, and Disconnect resets a sync.Once. If any
// cycle wedges, the per-iteration watchdog in newSandbox/close fails with a
// goroutine dump instead of hanging the suite.
func TestRepeatedConnectDisconnect(t *testing.T) {
	const cycles = 5

	before := goroutineCount()
	for i := 0; i < cycles; i++ {
		func() {
			sb := newSandbox(t)
			// Exercise the connection each cycle, not just open/close.
			within(t, 5*time.Second, "cycle GetVersion", func() {
				if _, err := sb.RPC.GetVersion(ctx(t, 3*time.Second), &commonpb.Empty{}); err != nil {
					t.Fatalf("cycle %d: GetVersion failed: %s", i, err)
				}
			})
			sb.close()
		}()
	}

	// Give any post-close goroutines a beat to unwind, then report growth. We
	// don't fail on leak here (the bufconn server goroutine is known-unjoined
	// upstream) — we surface the delta so a regression is visible and we can
	// decide whether a Sliver-side GracefulStop wrapper is warranted.
	time.Sleep(500 * time.Millisecond)
	after := goroutineCount()
	t.Logf("goroutines: before=%d after=%d delta=%+d over %d cycles", before, after, after-before, cycles)
}
