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
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/cryptography"
	"github.com/bishopfox/sliver/server/db/models"
)

// Dial - Root function where all dialers for all C2 channels are called.
// Please add a branch case for your C2 profile, where you should normally
// just have to imitate the above lines.
func Dial(profile *models.C2Profile, net comm.Net, session *core.Session) (err error) {

	switch profile.Channel {
	case sliverpb.C2Channel_MTLS:

		// Fetch a TLS configuration from the values in the profile
		tlsConfig := cryptography.TLSConfigFromProfile(profile)

		hostport := fmt.Sprintf("%s:%d", profile.Hostname, profile.Port)
		conn, err := net.Dial("tcp", hostport)
		if err != nil {
			return err
		}

		// Upgrade to TLS, with certs loaded for mutual authentication
		tlsConn := tls.Client(conn, tlsConfig)
		if tlsConn == nil {
			return errors.New("Failed to wrap TCP connection into Mutual TLS")
		}

		// Start reading the connection for C2 messages
		go handleSliverConnection(tlsConn)

	case sliverpb.C2Channel_HTTPS:

	case sliverpb.C2Channel_DNS:
	case sliverpb.C2Channel_WG:
	}

	return
}
