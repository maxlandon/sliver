package route

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
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ilgooz/bon"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/core"
)

var (
	// Routes - All active network routes.
	Routes = &routes{
		Active: map[uint32]*sliverpb.Route{},
		mutex:  &sync.Mutex{},
	}
	routeID = uint32(0)

	defaultNetTimeout = 10 * time.Second
)

// routes - Holds all available routes to the server and its implants.
type routes struct {
	Active map[uint32]*sliverpb.Route
	mutex  *sync.Mutex
	// Router - There is only one router as entrypoint to all network routes,
	// and all server internal 'requests' are sent through here, as well as
	// proxied communications from all user consoles.
	Server *bon.Bon
}

// Add - A user has requested to open a route. Send requests to all nodes in the route chain,
// so they know how to handle traffic directed at a certain address, and register the route.
// For each implant node, we cut the sliverpb.Route it directly send it through its C2 RPC channel.
func (r *routes) Add(new *sliverpb.Route) (route *sliverpb.Route, err error) {

	// Check address / netmask / etc provided in new. Process values if needed

	var sess *core.Session // The session that will be the last node in the route.

	// If an implant ID is given in the request, we directly check its interfaces.
	// The new.ID is normally (and later) used for the route, but we use it as a filter for now.
	if new.ID != 0 {
		sess = core.Sessions.Get(new.ID)
	}

	// If no, get interfaces for all implants and verify no doublons.
	if new.ID == 0 {

	}

	// If yes, get route to implant.
	route, err = r.BuildRouteToSession(sess)
	if err != nil {
		return nil, err
	}

	// Generate a unique ID for this route. This ID will be used by
	// all nodes for routing all traffic tagged with this route ID.
	route.ID = NextRouteID()

	// Add handle func to Router (technically the fist node in the chain)
	var handle = func(conn net.Conn) {
		for _, t := range c2.Transports.Active {
			next := route.Nodes[0]
			if t.C2.ID == next.ID {
				go t.HandleRouteStream(route.ID, conn)
			}
		}
	}
	// Add handle func to Router.
	r.Server.Handle(bon.Route(route.ID), handle)

	// A copy of the route that we cutoff at each successful node request.
	// The final subnet we want to route traffic to is always preserved despite cutoffs
	next := *new

	// Send C2 request to each implant node in the chain.
	for _, node := range next.Nodes {
		nodeSession := core.Sessions.Get(node.ID)

		addRouteReq := &sliverpb.AddRouteReq{
			Route: &next,
		}
		data, _ := proto.Marshal(addRouteReq)

		resp, err := nodeSession.Request(sliverpb.MsgAddRouteReq, defaultNetTimeout, data)
		if err != nil {
			return nil, err
		}

		addRoute := &sliverpb.AddRoute{}
		proto.Unmarshal(resp, addRoute)

		if addRoute.Success == false {
			return nil, errors.New(addRoute.Response.Err)
		}

		// Cutoff the implant node and roll to next implant.
		next.Nodes = next.Nodes[1:]
	}

	// Add chain split to Active
	r.mutex.Lock()
	r.Active[new.ID] = new
	r.mutex.Unlock()

	return
}

// Remove - We notify all implant nodes on the route to stop routing traffic, and deregister the route.
func (r *routes) Remove(routeID uint32) (err error) {

	route, found := r.Active[routeID]
	if !found {
		return fmt.Errorf("provided route ID (%d) does not exist", routeID)
	}

	// Send request to remove route to all implant nodes.
	for _, node := range route.Nodes {

		nodeSession := core.Sessions.Get(node.ID)

		rmRouteReq := &sliverpb.RmRouteReq{}
		data, _ := proto.Marshal(rmRouteReq)

		resp, err := nodeSession.Request(sliverpb.MsgRmRouteReq, defaultNetTimeout, data)
		if err != nil {
			return err
		}

		rmRoute := &sliverpb.RmRoute{}
		proto.Unmarshal(resp, rmRoute)

		if rmRoute.Success == false {
			return errors.New(rmRoute.Response.Err)
		}

	}

	// Call off to Router
	r.Server.Off(bon.Route(routeID))

	// Remove route from Active
	r.mutex.Lock()
	delete(r.Active, route.ID)
	r.mutex.Unlock()

	return
}

// GetRouteFor - Given a network address/subnet, we find the correct chain of nodes to route traffic.
// The addr should normally be part of the last node's subnets. If the chain is empty, we pass the
// conn to be handled directory by net.DialTCP/ net.DialUDP / other.
func (r *routes) GetRouteFor(addr string) (route *sliverpb.Route) {

	// Get net interfaces for all implants and verify no doublons.

	// Once interface is found, get route to implant and return it.

	return
}

// BuildRouteToSession - Given a session, we build the full route (all nodes) to this session.
// Each node will have the implan's active transport address and the Session ID.
func (r *routes) BuildRouteToSession(sess *core.Session) (route *sliverpb.Route, err error) {

	// Check the session remote address, and check active routes for the corresponding subnet.

	// Add a node to this route, (with the session argument info)

	// Return the new route.

	return
}

// GetSessionRoute - Sometimes we need to have quick access to sessions, based on an address (not subnets).
// This returns an implant session if the provided address corresponds to a route address, or nil if the address is
// accessible from the C2 Server. Error is returned if provided address is invalid, if not technical errors.
func (r *routes) GetSessionRoute(addr string) (sess *core.Session, err error) {

	// Get net interfaces for all implants and verify no doublons.

	// If no doublons, send back implant session

	// If yes, returns the first one in list.

	return
}

// handleRouteConns - A goroutine used to process all streams/conns given by
// transports/clients/servers to the routing system. Subroutines are started
// for each active transport on the server. This function should normally only
// handle traffic to be forwarded to implants, not reverse connections.
func (r *routes) handleRouteConns() {

	// For each of the transports, watch their inbound channel.

}

// NextRouteID - Returns an incremental nonce as an id
func NextRouteID() uint32 {
	newID := routeID + 1
	routeID++
	return newID
}
