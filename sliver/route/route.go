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

	"github.com/bishopfox/sliver/protobuf/sliverpb"
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
