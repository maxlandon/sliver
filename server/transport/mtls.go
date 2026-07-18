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
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/reeflective/team/server"
)

// teamserver is a vanilla TCP+MTLS gRPC server offering all Sliver services through it.
// This listener backend embeds a team/server.Server core driver and uses it for fetching
// server-side TLS configurations, use its loggers and access its database/users/list.
type teamserver struct {
	*server.Server

	options       []grpc.ServerOption
	localListener *bufconn.Listener
	mutex         *sync.RWMutex
}

// newTeamserverTLS returns a vanilla tcp+mtls gRPC teamserver listener backend.
// Developers: note that the teamserver type is already set with logging/
// auth/middleware/buffering gRPC options. You can still override them.
func newTeamserverTLS(opts ...grpc.ServerOption) *teamserver {
	listener := &teamserver{
		mutex:   &sync.RWMutex{},
		options: bufferingOptions(),
	}

	listener.options = append(listener.options, opts...)

	return listener
}

// Name immplements team/server.Handler.Name().
// It indicates the transport/rpc stack.
func (h *teamserver) Name() string {
	return "gRPC/mTLS"
}

// Init implements team/server.Handler.Init().
// It is used to initialize the listener with the correct TLS credentials
// middleware (or absence of if about to serve an in-memory connection).
func (h *teamserver) Init(team *server.Server) (err error) {
	h.Server = team

	// Panic recovery — installed FIRST so it is the outermost interceptor and
	// wraps every downstream interceptor and RPC handler. A panic in any handler
	// (e.g. an unchecked slice index) becomes a codes.Internal error with a logged
	// stack instead of tearing down the entire teamserver process.
	h.options = append(h.options,
		grpc.ChainUnaryInterceptor(recoveryUnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(recoveryStreamServerInterceptor()),
	)

	// Logging
	logOptions, err := logMiddlewareOptions(h.Server)
	if err != nil {
		return err
	}

	h.options = append(h.options, logOptions...)

	// NOTE: operator authentication middleware is installed in Listen(), not here.
	// Whether a connection needs real authentication depends on the listener kind
	// (a TCP daemon/remote listener does; the in-memory bufconn does not), and that
	// is only known once Listen() is given a concrete address.

	return nil
}

// Listen implements team/server.Handler.Listen().
// this teamserver uses a tcp+TLS (mutual) listener to serve remote clients.
func (h *teamserver) Listen(addr string) (ln net.Listener, err error) {
	// Only the in-memory (single-player) serve uses the bufconn shim: the team
	// core drives it with an empty host and port 0, i.e. addr ":0". Every other
	// address is a real daemon/remote listener that MUST bind an actual TCP
	// socket -- otherwise the server has no network presence and remote clients
	// time out. (This used to key off localListener != nil, but that field is set
	// at construction for the in-memory client and is never cleared in daemon
	// mode, so the daemon wrongly served the bufconn and never bound TCP.)
	h.mutex.Lock()
	inMemory := h.localListener != nil && addr == ":0"
	if inMemory {
		ln = h.localListener
	}
	// Consume the reference either way: past this point the handler is committed
	// to a listener kind, and a nil localListener makes the auth middleware treat
	// connections as remote users requiring authentication.
	h.localListener = nil
	h.mutex.Unlock()

	if inMemory {
		// In-memory conn: no TLS, no authentication.
		h.serve(ln)
		return ln, nil
	}

	// Real TCP listener (daemon / remote multiplayer).
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Encryption (mutual TLS).
	tlsOptions, err := tlsAuthMiddlewareOptions(h.Server)
	if err != nil {
		return nil, err
	}
	h.options = append(h.options, tlsOptions...)

	// Operator authentication/authorization (real tokenAuthFunc + permissions,
	// since localListener is now nil).
	authOptions, err := h.initAuthMiddleware()
	if err != nil {
		return nil, err
	}
	h.options = append(h.options, authOptions...)

	h.serve(ln)

	return ln, nil
}

// Close implements team/server.Handler.Close().
// Original sliver never closes the gRPC HTTP server itself
// with server.Shutdown(), so here we don't close anything.
// Note that the listener itself is controled/closed by
// our core teamserver driver.
func (h *teamserver) Close() error {
	return nil
}
