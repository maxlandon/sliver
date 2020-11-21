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
	"fmt"
	"net"
	"net/url"
	"sync"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/log"
	"github.com/hashicorp/yamux"
)

var (
	tpLog = log.NamedLogger("c2", "transport")
)

// Transport - The server-side equivalent of an implant Transport.
// There is only one Transport per physical connection ESTABLISHED,
// which means the same listener, for instance, might pop several
// Transports, for several implants.
// However, traffic going through different implants (C2 or not) might
// flow into/out of a single Transport object.
type Transport struct {
	ID uint64 // A unique ID for this transport.

	// Depending on the underlying protocol stack used by this transport,
	// we might or might not be able to do stream multiplexing. Generally,
	// if IsMux is set to false, it is because the underlying protocol used
	// is not able to yield us a net.Conn object, and therefore the conn below
	// will also be empty.
	IsMux bool

	// conn - Physical connection initiated by/on behalf of this Transport.
	conn net.Conn

	// multiplexer - Able to derive streams from physical conn above. Since the
	// server-side Transport (here) asks the implant Transport to mux its connection,
	// this session is a yamux.Client.
	multiplexer *yamux.Session

	// C2 - This Transport's other end must be an implant, and we are the
	// Server so instead of a *Connection we have a *Session reference.
	// Whether mux-able or not, this must be working.
	C2 *core.Session
	// URL is populated with the implant's registration information.
	URL *url.URL

	// Inbound - Streams that have been created upon request of the Transport's
	// other end: here, an implant pivot.
	// IMPORTANT: ANY inbound stream is considered PURE REVERSE connections:
	// that is, implants having contacted a pivot for a registration, and the pivot
	// having forwarded the conn. Therefore, all streams are "RPC handled" as such.
	// Also, the conn at the transport layer has already been TLS-authenticated.
	Inbound chan net.Conn
	// Outbound - Streams directed at the Transport's other end. We usually
	// fill this channel with conns handled by C2 server/console proxies.
	Outbound chan net.Conn
}

// New - Instantiate a new transport and do basic setup
func New(url *url.URL) (t *Transport) {
	t = &Transport{
		ID:  1, // Test, need to coordinate with remote end for this.
		URL: url,
	}
	return
}

// StartFromConn - A net.Conn has been created out of a listener, and we pass this
// conn to create a new active transport, with all needed infrastructure. If the conn
// is nil, it means we have a non-muxable protocol stack, but still register a transport.
// The conn passed as argument is generally a physical conn, BUT IN ANY CASE, it cannot be
// a muxed conn. Otherwise we cannot put a multiplexer around it again.
func (t *Transport) StartFromConn(conn net.Conn) (err error) {

	tpLog.Printf("New transport from incoming connection (<- %s)", conn.RemoteAddr())

	// We fill details on this Transport
	t.IsMux = true

	// Inbound/outbound streams are initialized
	t.Inbound = make(chan net.Conn, 100)
	t.Outbound = make(chan net.Conn, 100)

	t.multiplexer, err = yamux.Client(conn, nil)
	if err != nil {
		tpLog.Printf("[mux] Error setting up multiplexer client: %s", err)
	}

	// Finally, mux a first stream and register the session over it.
	err = t.NewStreamC2()

	return
}

// NewStreamC2 - The transport has received a new muxed stream (REVERSE).
// It is for now only an mTLS pivoted implant connection, which needs registration.
// We therefore add a C2 RPC layer on top of this connection, and register the session.
func (t *Transport) NewStreamC2() (err error) {

	// Initiate first stream, used by remote end as C2 RPC stream.
	// The remote is already listening for incoming mux requests.
	stream, err := t.multiplexer.Open()
	if err != nil {
		tpLog.Printf("[mux] Error opening C2 stream: %s", err)
		return
	}

	// Create and register session
	session := core.Sessions.Add(&core.Session{
		Transport:     "mtls",
		RemoteAddress: fmt.Sprintf("%s", stream.RemoteAddr()),
		Send:          make(chan *sliverpb.Envelope),
		RespMutex:     &sync.RWMutex{},
		Resp:          map[uint64]chan *sliverpb.Envelope{},
	})
	session.UpdateCheckin()

	// Concurrently start RPC request/response handling.
	go handleSessionRPC(session, stream)

	tpLog.Infof("Done creating RPC C2 stream.")

	return
}
