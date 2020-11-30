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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Routes - Get active network routes
func (rpc *Server) Routes(ctx context.Context, req *sliverpb.RoutesReq) (*sliverpb.Routes, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Routes not implemented")
}

// AddRoute - Add a nework route through
func (rpc *Server) AddRoute(ctx context.Context, req *sliverpb.AddRouteReq) (*sliverpb.AddRoute, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddRoute not implemented")
}

// RemoveRoute - Delete an active network route.
func (rpc *Server) RemoveRoute(ctx context.Context, req *sliverpb.RmRouteReq) (*sliverpb.RmRoute, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveRoute not implemented")
}
