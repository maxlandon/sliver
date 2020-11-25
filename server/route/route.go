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
	"sync"

	"github.com/ilgooz/bon"
)

// The server-side route package works similarly to the implant's route package with respect to:
//
// 1) Proxies used by C2 users are defined and used in the client/ (so that it does not make any
//    difference whether we are the admin -local- or a client -remote-).

// It also works differntly, because the server holds all routes for all implants, while implants
// only have a subset of each route (the next node).

var (
	// Routes - All active network routes.
	Routes = &routes{
		Active: []Chain{},
		mutex:  &sync.Mutex{},
	}
)

// routes - Holds all available routes to the server and its implants.
type routes struct {
	Active []Chain
	mutex  *sync.Mutex
	Router *bon.Bon
}

// Add - A user has requested to open a route. Send requests to all nodes in the route chain,
// so they know how to handle traffic directed at a certain address, and register the route.
// For each implant node, we cut the Chain it directly send it through its C2 RPC channel.
func (r *routes) Add(new *Chain) (*Chain, error) {

	// If no routes yet, we need to register the mux router

	// Add chain split to Active

	// Add handle func to Router.

	return &Chain{}, nil
}

// Remove - We notify all implant nodes on the route to stop routing traffic, and deregister the route.
func (r *routes) Remove(routeID uint64) (err error) {

	// Remove route from Active

	// Call off to Router.

	return
}

// GetRouteFor - Given a network address/subnet, we find the correct chain of nodes to route traffic.
// The addr should normally be part of the last node's subnets. If the chain is empty, we pass the
// conn to be handled directory by net.DialTCP/ net.DialUDP / other.
func (r *routes) GetRouteFor(addr string) (route *Chain) {
	return
}

// handleRouteConns - A goroutine used to process all streams/conns given by transports/clients/servers to the routing system.
// Subroutines are started for each active transport on the server. This function should normally only handle traffic to be forwarded
// to implants, not reverse connections.
func (r *routes) handleRouteConns() {

	// For each of the transports, watch their inbound channel.

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
