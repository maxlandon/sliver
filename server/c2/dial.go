package c2

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
	"net"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db/models"
)

// Dial - Root function where all dialers for all C2 channels are called.
// Please add a branch case for your C2 profile, where you should normally
// just have to imitate the above lines.
func Dial(profile *models.C2Profile, network comm.Net, session *core.Session) (err error) {

	// conn - If your C2 channel yields a net.Conn compliant connection, use this
	// conn so that the server can transparently handle session handling, RPC setup
	// around it and various other synchronization stuff that are useful to the client
	// console having requested a dial.
	var conn net.Conn

	switch profile.Channel {

	case sliverpb.C2Channel_MTLS:
		// Dial and yield a MutualTLS authenticated/encrypted connection,
		// either pivoted through an implant comm or on the server interfaces.
		conn, err = DialMutualTLS(profile, network)
		if err != nil {
			return
		}

	case sliverpb.C2Channel_HTTPS:

	case sliverpb.C2Channel_DNS:
	}

	// Automatically and transparently serve the connection, if the latter has been used.
	// This function will return if this connection is not used (thus nil), without hampering
	// on the session setup,registration and usage process.
	go handleSliverConnection(conn)

	return
}
