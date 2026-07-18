package rpc

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
)

// TestIsOperatorOnline pins the rough LastSeen-recency liveness heuristic used by
// GetUsers: a user seen within operatorOnlineWindow is online, an older or
// never-seen (zero) LastSeen is offline. This replaced the core.Clients live-stream
// registry, which never dropped operators whose console closed without cleanly
// cancelling the Events stream (pinning them "online" forever).
func TestIsOperatorOnline(t *testing.T) {
	cases := []struct {
		name     string
		lastSeen time.Time
		want     bool
	}{
		{"never seen (zero time)", time.Time{}, false},
		{"seen just now", time.Now(), true},
		{"seen mid-window", time.Now().Add(-operatorOnlineWindow / 2), true},
		{"seen just inside window", time.Now().Add(-operatorOnlineWindow + 2*time.Second), true},
		{"seen just outside window", time.Now().Add(-operatorOnlineWindow - 2*time.Second), false},
		{"seen long ago", time.Now().Add(-1 * time.Hour), false},
		{"future timestamp (clock skew)", time.Now().Add(1 * time.Minute), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isOperatorOnline(tc.lastSeen); got != tc.want {
				t.Fatalf("isOperatorOnline(%v) = %v, want %v (window=%s)",
					tc.lastSeen, got, tc.want, operatorOnlineWindow)
			}
		})
	}
}
