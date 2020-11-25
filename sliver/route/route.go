package route

import (
	"sync"

	"github.com/hashicorp/yamux"
	"github.com/ilgooz/bon"
)

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

// The route package is used to route all traffic going either:
// - From the server to a pivoted implant (through this pivot)
// - From a pivoted implant back to the server
// - From the server to an endpoint that is not an implant.

// In the case of implant-to-server communications, the
// traffic should never leave the physical connections:
// Server -> pivot      and     pivot -> pivoted implant.

// In any case, this pivot should NEVER open any listener on the host.
// The listener is always a multiplexer, which satisfies the net.Listener interface.

// Also, as opposed to gost where it doesn't matter opening physical conns,
// and therefore where it does not matter to share the route chain between all
// proxy nodes, we need to divide the Route between all nodes, where each node
// only knows about the next one, and is therefore able to use mux conns to route traffic.

var (
	// Routes - All active network routes.
	Routes = &routes{
		Active: []Chain{},
		mutex:  &sync.Mutex{},
	}
)

// routes - Holds all routes in which this implant is a node.
type routes struct {
	Active []Chain
	mutex  *sync.Mutex
	Router *bon.Bon
}

// start - When the first route is registered, we register a mux router.
// After this call, the implant is able to route traffic that is being forwarded
// by the previous node in the chain (server -> pivot -> this implant).
func start(transporter *yamux.Session) (err error) {
	tpLog.Infof("Starting mux stream router")
	Routes.Router = bon.New(transporter)
	return
}

// Add - The implant has received a route request from the server.
// The route is always ready to be used, as the server only sent us
// what we need to route traffic, and only this.
func (r *routes) Add(new *Chain) (*Chain, error) {

	// If no routes yet, we need to register the mux router
	// to the active transport's multiplexer session.
	if len(r.Active) == 0 {
		start(transports.ServerComms.Multiplexer)
	}

	// Add chain split to Active

	// Add handle func to Router.

	return &Chain{}, nil
}

// Remove - The implant has been ordered to stop routing traffic to a certain route.
// We do not accept further streams for this one, and deregister it.
func (r *routes) Remove(routeID uint64) (err error) {
	return
}

// The routing system is currently handling a stream. It checks the destination address,
// and finds the correct node to forward the conn to. If the chain is empty, we pass the
// conn to be handled directory by net.DialTCP/ net.DialUDP / other.
func (r *routes) GetRouteFor(addr string) (route *Chain) {
	return
}

// Chain - A chain holds all nodes of a proxy chain, and builds routes from it.
type Chain struct {
	ID      bon.Route // Used by bon stream router over yamux.
	Retries int
	route   []Node
}

// Node - A proxy node, mainly used to construct a proxy chain.
// Each node in a chain is an implant process.
type Node struct {
	ID   int
	Addr string
	Host string
}
