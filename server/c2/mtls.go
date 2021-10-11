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
	"net"

	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/cryptography"
	"github.com/bishopfox/sliver/server/db/models"
)

// DialMutualTLS - Dial an implant listening for incoming MutualTLS connections
func DialMutualTLS(profile *models.Malleable, network comm.Net) (tlsConn net.Conn, err error) {

	// Fetch a TLS configuration from the values in the profile
	tlsConfig := cryptography.TLSConfigFromProfile(profile)

	hostport := fmt.Sprintf("%s:%d", profile.Hostname, profile.Port)
	conn, err := network.Dial("tcp", hostport)
	if err != nil {
		return nil, err
	}

	// Upgrade to TLS, with certs loaded for mutual authentication
	tlsConn = tls.Client(conn, tlsConfig)
	if tlsConn == nil {
		return nil, errors.New("Failed to wrap TCP connection into Mutual TLS")
	}

	return tlsConn, nil
}

// ListenMutualTLS - Start a MutualTLS listener on the server or the active session
func ListenMutualTLS(profile *models.Malleable, network comm.Net) (ln net.Listener, err error) {

	// Fetch a TLS configuration from the values in the profile
	tlsConfig := cryptography.TLSConfigFromProfile(profile)

	// Use the Comm system network to automatically dispatch dial/listen
	// to the right interface (either the server's, or the active session)
	hostport := fmt.Sprintf("%s:%d", profile.Hostname, profile.Port)
	clear, err := network.Listen("tcp", hostport)
	if err != nil {
		return nil, err
	}

	// Upgrade to TLS, with certs loaded for mutual authentication
	ln = tls.NewListener(clear, tlsConfig)
	if ln == nil {
		return nil, fmt.Errorf("Failed to upgrade TCP listener into an mTLS one")
	}

	return
}
