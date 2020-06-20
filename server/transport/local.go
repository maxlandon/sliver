package transport

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
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/server/log"
	"github.com/bishopfox/sliver/server/rpc"
	"github.com/bishopfox/sliver/server/rpc/buildserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 2 * mb

var (
	localLog = log.NamedLogger("transport", "local")
)

// LocalRPCServerListener - Bind gRPC server to an in-memory listener, which is
//                 typically used for unit testing, but ... it should be fine
func LocalRPCServerListener() (*grpc.Server, *bufconn.Listener, error) {
	localLog.Infof("Binding RPC server to listener ...")
	ln := bufconn.Listen(bufSize)
	options := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(ServerMaxMessageSize),
		grpc.MaxSendMsgSize(ServerMaxMessageSize),
	}
	options = append(options, initLoggerMiddleware()...)
	grpcServer := grpc.NewServer(options...)
	rpcpb.RegisterSliverRPCServer(grpcServer, rpc.NewSliverServer())
	go func() {
		if err := grpcServer.Serve(ln); err != nil {
			localLog.Fatalf("gRPC local rpc server listener error: %v", err)
		}
	}()
	return grpcServer, ln, nil
}

// LocalBuildServerListener - In-memory build server transport
func LocalBuildServerListener() (*grpc.Server, *bufconn.Listener, error) {
	localLog.Infof("Binding build server to listener ...")
	ln := bufconn.Listen(bufSize)
	options := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(ServerMaxMessageSize),
		grpc.MaxSendMsgSize(ServerMaxMessageSize),
	}
	options = append(options, initLoggerMiddleware()...)
	grpcServer := grpc.NewServer(options...)
	rpcpb.RegisterBuilderRPCServer(grpcServer, buildserver.NewBuildServer())
	go func() {
		if err := grpcServer.Serve(ln); err != nil {
			localLog.Fatalf("gRPC local build server listener error: %v", err)
		}
	}()
	return grpcServer, ln, nil
}
