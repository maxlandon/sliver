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
	"io"
	"net"
	"net/url"
	"sync"

	"github.com/hashicorp/yamux"
	"github.com/ilgooz/bon"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
	serverHandlers "github.com/bishopfox/sliver/server/handlers"
	"github.com/bishopfox/sliver/server/log"
)

var (
	tpLog = log.NamedLogger("c2", "transport")
)

// Transport - The server-side equivalent of an implant Transport. There is only one Transport per
// physical connection ESTABLISHED, which means the same listener, for instance, might pop several
// Transports, for several implants. However, traffic going through different implants (C2 or not)
// might flow into/out of a single Transport object.
type Transport struct {
	ID uint32

	// URL is populated with the implant's registration information.
	URL *url.URL

	// If the underlying connection is not a net.Conn, we cannot multiplex it.
	// If IsMux is set to false, it is because the underlying protocol used
	// is not able to yield us a net.Conn object, and therefore the conn below
	// will also be empty.
	IsMux bool

	// conn - Physical connection initiated by/on behalf of this Transport.
	conn net.Conn

	// Multiplexer - Able to derive stream from the physical conn above.
	multiplexer *yamux.Session

	// Session - This Transport's other end must be an implant, and we are the
	// Server so instead of a *Connection we have a *Session reference.
	// Whether mux-able or not, this object is never nil.
	Session *core.Session

	// Router - For each connection that needs to be forwarded to the other end we use the
	// Router to connect, specify the wished route of the connection, and pipe.
	// Automatically handles reverse connections when it has route IDs and handlers for doing so.
	Router *bon.Bon
}

// NewTransport - Instantiate a new transport and do basic setup
func NewTransport(url *url.URL) (t *Transport) {
	t = &Transport{
		ID:  nextTransportID(),
		URL: url,
	}
	tpLog.Printf("New transport from incoming connection (<- %s)", t.URL.String())

	return
}

// Start - A net.Conn has been created out of a listener, and we pass this conn to create a new active
// transport, with all needed infrastructure. If the conn is nil, it means we have a non-muxable protocol
// stack, but still register a transport.
// The conn passed as argument is generally a physical conn, BUT IN ANY CASE, it cannot be a muxed conn:
// otherwise we cannot put a multiplexer around it again.
func (t *Transport) Start(conn net.Conn) (err error) {

	if conn != nil {

		// Assuming the conn has not been drawned from a multiplexer !!
		t.multiplexer, err = yamux.Client(conn, nil)
		if err != nil {
			tpLog.Printf("[mux] Error setting up multiplexer client: %s", err)
			t.phyConnFallBack()
		}
		t.IsMux = true

		err = t.setupMuxC2()
		if err != nil {
			t.phyConnFallBack()
		}
	}

	// Add to active transports
	Transports.Add(t)

	tpLog.Infof("Transport %d set up and running (%s <- %s)", t.ID, t.conn.LocalAddr(), t.conn.RemoteAddr())
	return
}

func (t *Transport) setupMuxC2() (err error) {

	// Initiate first stream, used by remote end as C2 RPC stream.
	// The remote is already listening for incoming mux requests.
	stream, err := t.multiplexer.Open()
	if err != nil {
		tpLog.Printf("[mux] Error opening C2 stream: %s", err)
		return
	}
	go t.handleSessionRPC(t.Session, stream)

	// Create and register session
	t.Session = core.Sessions.Add(&core.Session{
		Transport:     "mtls",
		RemoteAddress: fmt.Sprintf("%s", t.multiplexer.Addr()),
		Send:          make(chan *sliverpb.Envelope),
		RespMutex:     &sync.RWMutex{},
		Resp:          map[uint64]chan *sliverpb.Envelope{},
	})
	t.Session.UpdateCheckin()

	tpLog.Infof("Done creating RPC C2 stream.")
	return
}

// handleSessionRPC - Small refactor used by new Transport model.
func (t *Transport) handleSessionRPC(session *core.Session, conn net.Conn) {

	// We will automatically cleanup the session once this function exits.
	defer func() {
		mtlsLog.Debugf("Cleaning up for %s", session.Name)
		core.Sessions.Remove(session.ID)
		conn.Close()
	}()

	// Receive messages
	done := make(chan bool)
	go func() {
		defer func() {
			done <- true
		}()
		handlers := serverHandlers.GetSessionHandlers()
		for {
			envelope, err := socketReadEnvelope(conn)
			if err != nil {
				mtlsLog.Errorf("Socket read error %v", err)
				return
			}
			session.UpdateCheckin()
			if envelope.ID != 0 {
				session.RespMutex.RLock()
				if resp, ok := session.Resp[envelope.ID]; ok {
					resp <- envelope // Could deadlock, maybe want to investigate better solutions
				}
				session.RespMutex.RUnlock()
			} else if handler, ok := handlers[envelope.Type]; ok {
				go handler.(func(*core.Session, []byte))(session, envelope.Data)
			}
		}
	}()

Loop:
	for {
		select {
		case envelope := <-session.Send:
			err := socketWriteEnvelope(conn, envelope)
			if err != nil {
				mtlsLog.Errorf("Socket write failed %v", err)
				break Loop
			}
		case <-done:
			break Loop
		}
	}
	mtlsLog.Infof("Closing connection to session %s", session.Name)
}

// In case we failed to use multiplexing, we downgrade to RPC over the transport's physical connection.
func (t *Transport) phyConnFallBack() (err error) {

	tpLog.Infof("falling back on RPC around physical conn")

	// First make sure all mux code is cleanup correctly.
	tpLog.Infof("[mux] Cleaning multiplexing code")
	if t.multiplexer != nil {
		err = t.multiplexer.GoAway()
		if err != nil {
			tpLog.Errorf("[mux] Error sending GoAway: %s", err)
		}

		err = t.multiplexer.Close()
		tpLog.Errorf("[mux] Error closing session: %s", err)

		t.IsMux = false
	}

	// Create and register session
	t.Session = core.Sessions.Add(&core.Session{
		Transport:     "mtls",
		RemoteAddress: fmt.Sprintf("%s", t.conn.RemoteAddr()),
		Send:          make(chan *sliverpb.Envelope),
		RespMutex:     &sync.RWMutex{},
		Resp:          map[uint64]chan *sliverpb.Envelope{},
	})
	t.Session.UpdateCheckin()

	// Concurrently start RPC request/response handling.
	go t.handleSessionRPC(t.Session, t.conn)

	tpLog.Infof("Done downgrading RPC C2 over physical conn.")

	return
}

// Stop - Gracefully shutdowns all components of this transport.
// The force parameter is used in case we have a mux transport, and
// that we want to kill it even if there are pending streams in it.
func (t *Transport) Stop(force bool) (err error) {

	if t.IsMux {
		activeStreams := t.multiplexer.NumStreams()

		// If there is an active Session, there is at least one open stream,
		// that we do not count as "important" when stopping the Transport.
		if (t.Session != nil && activeStreams > 1) || (t.Session == nil && activeStreams > 0) && !force {
			return fmt.Errorf("Cannot stop transport: %d streams still opened", activeStreams)
		}

		tpLog.Infof("[mux] closing all muxed streams")
		err = t.multiplexer.GoAway()
		if err != nil {
			tpLog.Errorf("[mux] Error sending GoAway: %s", err)
		}
		err = t.multiplexer.Close()
		tpLog.Errorf("[mux] Error closing session: %s", err)
	}

	// Just check the physical connection is not nil and kill it if necessary.
	if t.conn != nil {
		tpLog.Infof("killing physical connection (%s  ->  %s", t.conn.LocalAddr(), t.conn.RemoteAddr())
		return t.conn.Close()
	}

	// Remove from active transports
	Transports.Remove(t.ID)

	tpLog.Infof("Transport closed (%s)", t.conn.RemoteAddr())

	return
}

// HandleRouteStream - The transport is asked to route a stream given a route ID.
// This function is called by Bon' routing handlers, once they have the routeID and the conn.
func (t *Transport) HandleRouteStream(routeID uint32, src net.Conn) (err error) {

	tpLog.Infof("[route] routing connection (ID: %d, Dest: %s)", routeID, src.RemoteAddr())

	var route bon.Route = bon.Route(routeID)
	dst, err := t.Router.Connect(route)

	tpLog.Infof("[mux] Outbound stream: muxing conn and piping")

	transport(src, dst)
	return
}

// IsRouting - The transport checks if it is routing traffic that does not originate from this implant.
func (t *Transport) IsRouting() bool {

	if t.IsMux {
		activeStreams := t.multiplexer.NumStreams()
		// If there is an active C2, there is at least one open stream,
		// that we do not count as "important" when stopping the Transport.
		if (t.Session != nil && activeStreams > 1) || (t.Session == nil && activeStreams > 0) {
			return true
		}
		// Else we don't have any non-implant streams.
		return false
	}
	// If no mux, no routing.
	return false
}

func transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	go func() {
		errc <- copyBuffer(rw1, rw2)
	}()

	go func() {
		errc <- copyBuffer(rw2, rw1)
	}()

	err := <-errc
	if err != nil && err == io.EOF {
		err = nil
	}
	return err
}

func copyBuffer(dst io.Writer, src io.Reader) error {
	buf := lPool.Get().([]byte)
	defer lPool.Put(buf)

	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

var (
	sPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, smallBufferSize)
		},
	}
	mPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, mediumBufferSize)
		},
	}
	lPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, largeBufferSize)
		},
	}
)

var (
	tinyBufferSize   = 512
	smallBufferSize  = 2 * 1024  // 2KB small buffer
	mediumBufferSize = 8 * 1024  // 8KB medium buffer
	largeBufferSize  = 32 * 1024 // 32KB large buffer
)
