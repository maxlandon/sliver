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
	"github.com/bishopfox/sliver/server/log"
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

	// Router - For each connection that needs to be forwarded to the other end
	// we use the Router to connect, specify the wished route of the connection, and pipe.
	// Therefore, here the Router is in a client position most of the time.
	Router *bon.Bon
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

	t.multiplexer, err = yamux.Client(conn, nil)
	if err != nil {
		tpLog.Printf("[mux] Error setting up multiplexer client: %s", err)
	}

	// We start handling inbound/outbound streams in the background
	go t.handleInboundStreams()

	// Initiate first stream, used by remote end as C2 RPC stream.
	// The remote is already listening for incoming mux requests.
	stream, err := t.multiplexer.Open()
	if err != nil {
		tpLog.Printf("[mux] Error opening C2 stream: %s", err)
		return
	}
	t.C2, err = t.NewStreamC2(stream)
	if err != nil {
		return t.phyConnFallBack()
	}

	return
}

// NewStreamC2 - The transport has received a new muxed stream (REVERSE).
// It is for now only an mTLS pivoted implant connection, which needs registration.
// We therefore add a C2 RPC layer on top of this connection, and register the session.
func (t *Transport) NewStreamC2(stream net.Conn) (sess *core.Session, err error) {

	// Create and register session
	sess = core.Sessions.Add(&core.Session{
		Transport:     "mtls",
		RemoteAddress: fmt.Sprintf("%s", stream.RemoteAddr()),
		Send:          make(chan *sliverpb.Envelope),
		RespMutex:     &sync.RWMutex{},
		Resp:          map[uint64]chan *sliverpb.Envelope{},
	})
	sess.UpdateCheckin()

	// Concurrently start RPC request/response handling.
	go handleSessionRPC(sess, stream)

	tpLog.Infof("Done creating RPC C2 stream.")

	return
}

// Stop - Gracefully shutdowns all components of this transport.
// The force parameter is used in case we have a mux transport, and
// that we want to kill it even if there are pending streams in it.
func (t *Transport) Stop(force bool) (err error) {

	if t.IsMux {
		activeStreams := t.multiplexer.NumStreams()

		// If there is an active C2, there is at least one open stream,
		// that we do not count as "important" when stopping the Transport.
		if (t.C2 != nil && activeStreams > 1) || (t.C2 == nil && activeStreams > 0) && !force {
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

	tpLog.Infof("Transport closed (%s)", t.conn.RemoteAddr())

	return
}

// handleInboundStreams - Each time the other end of the transport asks us to handle
// a connection, we handle it. However, as opposed to implant's handleInboundStreams()
// functions, we always assume these streams are REVERSE connections initiated by some
// implants, and therefore we automatically register a new session. Authentication should
// have been already performed on the pivot implant's listener.
func (t *Transport) handleInboundStreams() {

	defer func() {
		close(t.Inbound)
		tpLog.Infof("[mux] Stopped processing inbound streams: ")
	}()

	tpLog.Infof("[mux] Starting inbound stream handling in background...")
	for {
		select {
		default:
			stream, err := t.multiplexer.Accept()
			if err != nil {
				tpLog.Errorf("[mux] Error accepting C2 stream: %s", err)
				return
			}
			tpLog.Infof("[mux] Inbound stream: muxing conn")

			// Register session over this new stream, by default.
			_, err = t.NewStreamC2(stream)
			if err != nil {
				tpLog.Errorf("Failed to register session: %s", err)
			}

		case <-t.multiplexer.CloseChan():
			return
		}
	}
}

// HandleRouteStream - The transport is asked to route a stream given a route ID.
// This function is called by Bon' routing handlers, once they have the routeID and the conn.
func (t *Transport) HandleRouteStream(routeID uint32, src net.Conn) (err error) {

	tpLog.Infof("[route] routing connection (ID: %d, Dest: %s)", routeID, src.RemoteAddr())

	var route bon.Route = bon.Route(routeID)
	dst, err := t.Router.Connect(route)

	tpLog.Infof("[mux] Outbound stream: muxing conn and piping")

	transport(src, dst)
	// go transport(src, dst)
	return
}

// In case we failed to use multiplexing infrastructure, we call here
// to downgrade to RPC over the transport's physical connection.
func (t *Transport) phyConnFallBack() (err error) {

	tpLog.Infof("falling back on RPC around physical conn")

	// First make sure all mux code is cleanup correctly.
	tpLog.Infof("[mux] Cleaning multiplexing code")

	// Create and register session
	t.C2 = core.Sessions.Add(&core.Session{
		Transport:     "mtls",
		RemoteAddress: fmt.Sprintf("%s", t.conn.RemoteAddr()),
		Send:          make(chan *sliverpb.Envelope),
		RespMutex:     &sync.RWMutex{},
		Resp:          map[uint64]chan *sliverpb.Envelope{},
	})
	t.C2.UpdateCheckin()

	// Concurrently start RPC request/response handling, but
	// this time around the transport physical conn
	go handleSessionRPC(t.C2, t.conn)

	tpLog.Infof("Done downgrading RPC C2 over physical conn.")

	return
}

// IsRouting - The transport checks if it is routing traffic that does not originate from this implant.
func (t *Transport) IsRouting() bool {

	if t.IsMux {
		activeStreams := t.multiplexer.NumStreams()
		// If there is an active C2, there is at least one open stream,
		// that we do not count as "important" when stopping the Transport.
		if (t.C2 != nil && activeStreams > 1) || (t.C2 == nil && activeStreams > 0) {
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
