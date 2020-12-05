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
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/ilgooz/bon"

	"github.com/bishopfox/sliver/protobuf/commonpb"
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

// routes - Holds and manages all available routes to the server and its implants.
type routes struct {
	Active map[uint32]*sliverpb.Route
	Server *bon.Bon // Default server used when no personal proxies or other scheme.
	mutex  *sync.Mutex
}

// Add - A user has requested to open a route. Send requests to all nodes in the route chain,
// so they know how to handle traffic directed at a certain address, and register the route.
// For each implant node, we cut the sliverpb.Route it directly send it through its C2 RPC channel.
func (r *routes) Add(newRoute *sliverpb.Route) (route *sliverpb.Route, err error) {

	// This session is the last one of the route, which will dial endpoint on its host subnet.
	var lastNodeSession *core.Session

	// Check address / netmask / etc provided in new. Process values if needed
	ip, subnet, err := net.ParseCIDR(newRoute.Subnet)
	if err != nil {
		ip = net.ParseIP(newRoute.Subnet)
		if ip == nil {
			return nil, fmt.Errorf("Error parsing route subnet: %s", err)
		}
	}
	m := subnet.Mask
	mask := fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])

	// If an implant ID is given in the request, we directly check its interfaces.
	// The new.ID is normally (and later) used for the route, but we use it as a filter for now.
	if newRoute.ID != 0 {
		lastNodeSession = core.Sessions.Get(newRoute.ID)
		err = checkSessionNetIfaces(ip, lastNodeSession)
		if err != nil {
			return nil, err
		}
	}

	// If no, get interfaces for all implants and verify no doublons.
	// For each implant, check network interfaces. Stop at the first one valid.
	if newRoute.ID == 0 {
		lastNodeSession, err = checkAllNetIfaces(subnet)
		if err != nil {
			return nil, fmt.Errorf("Error adding route: %s", err.Error())
		}
	}

	// We should not have an empty last node session.
	if lastNodeSession == nil {
		return nil, errors.New("Error adding route: last node' session is nil, after checking all interfaces")
	}

	// Check existing routes: for each of them, make sure the ip is not contained in the destination subnet.
	for _, rt := range r.Active {
		_, rtNet, _ := net.ParseCIDR(rt.Subnet)
		if rtNet.Contains(ip) && rtNet.Mask.String() == subnet.Mask.String() {
			return nil, fmt.Errorf("Active route %s (Mask: %s, ID:%d)", rt.Subnet, mask, rt.ID)
		}
	}

	// We build the full route to this last node session.
	route, err = BuildRouteToSession(lastNodeSession)
	if err != nil {
		return nil, err
	}
	if route == nil {
		return nil, errors.New("Route is empty after building it")
	}

	// Populate remaining fields for this route.
	route.Subnet = subnet.String()
	route.Netmask = mask

	// Send C2 request to each implant node in the chain. If any error arises
	// from this function, we ask back all concerned nodes to delete this route.
	err = r.initRoute(route)
	if err != nil {
		// HERE TODO: ADD SPECIAL ROUTE CUTOFF AND PASS IT TO removeRoute() !!!!!
	}

	// Add chain split to Active
	r.mutex.Lock()
	r.Active[route.ID] = route
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
	err = r.removeRoute(route)
	if err != nil {
		return fmt.Errorf("Error removing route: %s", err.Error())
	}

	// Call off to the server's Router
	r.Server.Off(bon.Route(routeID))

	// Remove route from Active
	r.mutex.Lock()
	delete(r.Active, route.ID)
	r.mutex.Unlock()

	return
}

func (r *routes) AddRouteForwardHandler(route *sliverpb.Route) (err error) {

	// If the routes server is nil, activate it with all client proxies
	// available, or setup a default one.
	if r.Server == nil {

	}

	// We always have the implant IDs for each node, and we match it with a transport.
	var handle = func(conn net.Conn) {
		for _, t := range c2.Transports.Active {
			next := route.Nodes[0]
			if t.Session.ID == next.ID {
				go t.HandleRouteConn(route.ID, conn)
			}
		}
	}
	r.Server.Handle(bon.Route(route.ID), handle) // Add add this default server.

	return
}

// BuildRouteToSession - Given a session, we build the full route (all nodes) to this session.
// Each node will have the implan's active transport address and the Session ID.
func BuildRouteToSession(sess *core.Session) (route *sliverpb.Route, err error) {

	route = &sliverpb.Route{
		ID: NextRouteID(), // A unique ID for this route, wether used or not.
	}

	// The session remote address belongs to one of the routes' IP destinations.
	addr := strings.Split(sess.RemoteAddress, ":")[0]
	ip := net.ParseIP(addr)

	// Check all active routes: if any of them has a final destination network
	// that encompasses the address of the Session, we return this route.
	for _, rt := range Routes.Active {
		_, subnet, _ := net.ParseCIDR(rt.Subnet)
		if subnet.Contains(ip) && rt.Nodes[len(rt.Nodes)-1].ID == sess.ID {
			route.Nodes = rt.Nodes
		}
	}

	// Add a node to this route, (with the session argument info)
	node := &sliverpb.Node{
		ID:   sess.ID,
		Name: sess.Name,
		Host: sess.Hostname,
		Addr: ip.String(),
	}
	route.Nodes = append(route.Nodes, node)

	return
}

// GetSession - Sometimes we need to have quick access to sessions, based on an address (not subnets).
// This returns an implant session if the provided address corresponds to a route address, or nil if the address is
// accessible from the C2 Server. Error is returned if provided address is invalid, if not technical errors.
func (r *routes) GetSession(addr string) (session *core.Session, err error) {

	// Check address / netmask / etc provided in new. Process values if needed
	ip, subnet, err := net.ParseCIDR(addr)
	if err != nil {
		ip = net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("Error parsing route subnet: %s", err)
		}
		subnet = &net.IPNet{IP: ip, Mask: ip.DefaultMask()}
	}

	// If we don't have route, the caller will know its the server.
	if len(r.Active) == 0 {
		return nil, nil
	}

	// Get net interfaces for all implants and verify no doublons.
	// TODO: Change this so that session can be nil after call.
	session, err = checkAllNetIfaces(subnet)
	if err != nil {
		return nil, fmt.Errorf("Error getting route: %s", err.Error())
	}

	return
}

// initRoute - This function sends to each implant node a request to open a route handler.
// If any error arises with one of the nodes, we go back to beginning of the route and
// ask each node again to delete the route, if any are already up.
func (r *routes) initRoute(route *sliverpb.Route) (err error) {

	// A copy of the route that we cutoff at each successful node request.
	// The final subnet we want to route traffic to is always preserved despite cutoffs
	next := *route

	for _, node := range next.Nodes {
		nodeSession := core.Sessions.Get(node.ID)

		// Send request to implant
		addRouteReq := &sliverpb.AddRouteReq{
			Request: &commonpb.Request{SessionID: nodeSession.ID},
			Route:   &next,
		}
		data, _ := proto.Marshal(addRouteReq)

		// Process response
		addRoute := &sliverpb.AddRoute{}
		resp, err := nodeSession.Request(sliverpb.MsgNumber(addRouteReq), defaultNetTimeout, data)
		if err != nil {
			return err
		}
		proto.Unmarshal(resp, addRoute)

		// If there is an error with a node, we return it and the caller will be in
		// charge of asking previously ordered nodes to delete this orphaned route.
		if addRoute.Success == false {
			return errors.New(addRoute.Response.Err)
		}

		// Cutoff the implant node and roll to next implant.
		next.Nodes = next.Nodes[1:]
	}
	return
}

// removeRoute - This function is the equivalent of initRoute(): it sends a request
// to all implant nodes to delete a given route.
func (r *routes) removeRoute(route *sliverpb.Route) (err error) {

	for _, node := range route.Nodes {

		nodeSession := core.Sessions.Get(node.ID)
		rmRouteReq := &sliverpb.RmRouteReq{
			Request: &commonpb.Request{SessionID: nodeSession.ID},
		}
		data, _ := proto.Marshal(rmRouteReq)

		resp, err := nodeSession.Request(sliverpb.MsgNumber(rmRouteReq), defaultNetTimeout, data)
		if err != nil {
			return err
		}

		rmRoute := &sliverpb.RmRoute{}
		proto.Unmarshal(resp, rmRoute)

		// TODO: If, for any reason, an error arises from one of the nodes
		// we currently don't instruct previous ones to "reopen" the route.
		// If should not mattter as far as route IDs are concerned, because
		// they are determined by the server and identical across nodes.
		// Still, we should find a way to deal with this.
		if rmRoute.Success == false {
			return errors.New(rmRoute.Response.Err)
		}
	}

	return
}

func checkSessionNetIfaces(ip net.IP, sess *core.Session) (err error) {

	ifacesReq := &sliverpb.IfconfigReq{
		Request: &commonpb.Request{SessionID: sess.ID},
	}
	data, _ := proto.Marshal(ifacesReq)

	resp, err := sess.Request(sliverpb.MsgNumber(ifacesReq), defaultNetTimeout, data)
	if err != nil {
		return fmt.Errorf("Error getting session interfaces: %s", err.Error())
	}
	ifaces := &sliverpb.Ifconfig{}
	proto.Unmarshal(resp, ifaces)

	// For all net interfaces, check there is one that the new route subnet contains.
	var found = false
	for _, iface := range ifaces.NetInterfaces {

		// Normally the first field is the host's interface IP in CIDR notation.
		ipv4CIDR := iface.IPAddresses[0]

		// Always check if we can have both Network CIDR and IP address
		ipAddr, subnet, err := net.ParseCIDR(ipv4CIDR)
		if err != nil {
			ip = net.ParseIP(iface.IPAddresses[0])
		}
		// Loopback are not allowed when routing, only with port forward.
		if ipAddr.IsLoopback() {
			continue
		}
		if subnet.Contains(ip) {
			found = true
		}
	}
	// If yes, we can go on, else we return.
	if !found {
		return fmt.Errorf("Error adding route: implant host has no network for IP %s",
			ip.String())
	}
	return
}

func checkAllNetIfaces(subnet *net.IPNet) (session *core.Session, err error) {

	var found, doublon = false, false
	var sessionIDs []uint32
	var sessDesc []string

	for _, sess := range core.Sessions.All() {

		err = checkSessionNetIfaces(subnet.IP, sess)
		if err != nil {
			continue
		}

		if found {
			doublon = true
		} else if doublon {
			return nil, fmt.Errorf("Sessions %s and %s have colliding interfaces for subnet %s",
				sessDesc[0], sessDesc[1], subnet.IP.String())
		} else {
			sessionIDs = append(sessionIDs, sess.ID)
			sessDesc = append(sessDesc, fmt.Sprintf("%s (ID:%d)", sess.Name, sess.ID))
			found = true
		}

		// If we found one, we have the last node's session.
		if found && !doublon {
			session = sess
		}
	}

	if !found {
		return nil, fmt.Errorf("Error adding route: no implant hosts have access to subnet %s", subnet.IP.String())
	}

	return
}

// NextRouteID - Returns an incremental nonce as an id
func NextRouteID() uint32 {
	newID := routeID + 1
	routeID++
	return newID
}

// GetRouteFor - Given a network address/subnet, we find the correct chain of nodes to route traffic.
// The addr should normally be part of the last node's subnets. If the chain is empty, we pass the
// conn to be handled directory by net.DialTCP/ net.DialUDP / other.
// func (r *routes) GetRouteFor(addr string) (route *sliverpb.Route, err error) {
//
//         // Check address / netmask / etc provided in new. Process values if needed
//         ip, subnet, err := net.ParseCIDR(addr)
//         if err != nil {
//                 ip = net.ParseIP(addr)
//                 if ip == nil {
//                         return nil, fmt.Errorf("Error parsing route subnet: %s", err)
//                 }
//         }
//
//         // Last node in the route we will build, if we find a corresponding network on host.
//         var session *core.Session
//
//         // Active routes and their associated sessions have priority: a route is directly
//         // returned, as it does not need any additional node or processing.
//         for _, rt := range r.Active {
//                 if rt.Subnet == ip.String() && rt.Netmask == subnet.Mask.String() {
//                         return rt, nil
//                 }
//         }
//
//         // If we did not find an active route, get net interfaces for all implants and verify no doublons.
//         if session == nil {
//                 session, err = checkAllNetIfaces(subnet)
//                 if err != nil {
//                         return nil, fmt.Errorf("Error getting route: %s", err.Error())
//                 }
//         }
//
//         // If session is still nil, it means we contact the server.
//         if session == nil {
//                 return nil, nil
//         }
//
//         // TODO:
//         // The session found might be in the same network as the host,
//         // in which case we use the server and return nil (check transport connections)
//
//         return
// }
