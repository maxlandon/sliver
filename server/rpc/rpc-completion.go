package rpc

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
	"context"
	"net"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
)

// CompleteServerInterfaces - Get the server interfaces for C2 listeners
func (rpc *Server) CompleteServerInterfaces(ctx context.Context, req *sliverpb.IfconfigReq) (*sliverpb.Ifconfig, error) {

	resp := &sliverpb.Ifconfig{}

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			iface := &sliverpb.NetInterface{}
			iface.IPAddresses = append(iface.IPAddresses, ip.String())
			resp.NetInterfaces = append(resp.NetInterfaces, iface)
		}
	}

	return resp, nil
}

// CompleteSessionPath - Get the contents of a path if directory
func (rpc *Server) CompleteSessionPath(ctx context.Context, req *sliverpb.LsReq) (res *sliverpb.Ls, err error) {
	hostUUID := getContextHost(req)

	cache := Cache.GetSessionCache(hostUUID, rpc.GenericHandler)

	return cache.GetDirectoryContents(req.Path, req.Request.SessionID), nil
}

// CompleteSessionProcesses - Get the list of running processes
func (rpc *Server) CompleteSessionProcesses(ctx context.Context, req *sliverpb.PsReq) (res *sliverpb.Ps, err error) {
	hostUUID := getContextHost(req)

	cache := Cache.GetSessionCache(hostUUID, rpc.GenericHandler)

	return cache.GetProcesses(req.Request.SessionID), nil
}

// CompleteSessionInterfaces - Get the session's host current network interfaces
func (rpc *Server) CompleteSessionInterfaces(ctx context.Context, req *sliverpb.IfconfigReq) (res *sliverpb.Ifconfig, err error) {
	hostUUID := getContextHost(req)

	cache := Cache.GetSessionCache(hostUUID, rpc.GenericHandler)

	return cache.GetNetInterfaces(req.Request.SessionID), nil
}

// CompleteSessionEnv - Get the list of the host environment variables
func (rpc *Server) CompleteSessionEnv(ctx context.Context, req *sliverpb.EnvReq) (res *sliverpb.EnvInfo, err error) {
	hostUUID := getContextHost(req)

	cache := Cache.GetSessionCache(hostUUID, rpc.GenericHandler)

	return cache.GetEnvironmentVariables(req.Request.SessionID), nil
}

func getContextHost(req GenericRequest) (hostUUID string) {

	session := core.Sessions.GetByUUID(req.GetRequest().SessionUUID)
	if session == nil {
		beacon, _ := db.BeaconByID(req.GetRequest().BeaconID)
		return beacon.HostUUID.String()
	}
	return session.HostUUID
}
