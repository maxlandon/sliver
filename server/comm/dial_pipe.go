package comm

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
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	"github.com/bishopfox/sliver/protobuf/commpb"
)

// DialPipe - Get a network connection to a host in this Comm.
// Valid stream networks are "tcp", "tcp4" and "tcp6"
func (comm *Comm) DialPipe(name string) (conn net.Conn, err error) {
	return comm.DialContextPipe(context.Background(), name)
}

// DialContextPipe - Get a network connection to a host in this Comm (as route), with a Context. It is not mandatory to
// pass a context with a timeout, though all dial functions from the comm API will automatically include a default one.
func (comm *Comm) DialContextPipe(ctx context.Context, name string) (conn net.Conn, err error) {

	// Get RHost/RPort
	uri, _ := url.Parse(fmt.Sprintf("pipe://%s", name))
	if uri == nil {
		return nil, fmt.Errorf("Address parsing failed: %s", name)
	}

	// Normally the context is never nil, but just in case.
	if ctx == nil {
		ctx = context.Background()
	}

	info := newConnOutboundTCP(uri)      // Prepare connection info.
	info.ID = strconv.Itoa(int(comm.ID)) // The comm is in itself a route, so we give its ID, just in case.

	// The timeout is passed as info for the implant dialer to set the OS-level timeout of the connection.
	if deadline, exists := ctx.Deadline(); exists {
		info.Timeout = time.Until(deadline).Milliseconds()
	}

	// We'll either get an error from opening a connection on the implant, or a working stream.
	pending := make(chan io.ReadWriteCloser, 1)
	errOpen := make(chan error, 1)
	err = fmt.Errorf("Failed to dial pipe://%s: ", name)

	// Get a working channel (io.ReadWriteCloser) from the implant Comm SSH, or an error
	go func(info *commpb.Conn) {
		data, _ := proto.Marshal(info)
		stream, reqs, err := comm.sshConn.OpenChannel(commpb.Request_RouteConn.String(), data)
		if err != nil {
			errOpen <- err
			close(pending)
			return
		}
		go ssh.DiscardRequests(reqs)

		// Pass the stream to be processed into a net.Conn, and close the channel
		pending <- stream
		close(pending)
	}(info)

	// We wait and we will either receive...:
	select {
	// A context timeout or a cancellation before a stream.
	case <-ctx.Done():
		switch ctx.Err() {
		case context.Canceled:
			err = errors.WithMessage(err, "context cancelled")
		case context.DeadlineExceeded:
			err = errors.WithMessage(err, "context timeout exceeded")
		}
		return nil, err

	// An error thrown by the implant.
	case openErr := <-errOpen:
		err = errors.WithMessage(err, openErr.Error())
		return nil, err

	// Or the stream before timeout/cancel
	case connection := <-pending:
		conn = newConnInboundTCP(info, io.ReadWriteCloser(connection)) // Make a working net.Conn.
		comm.active = append(comm.active, conn)                        // Add connection to active

		rLog.Infof("[route] Dialing (%s/%s) %s --> %s (ID: %s)", info.Transport.String(),
			info.Application.String(), conn.LocalAddr().String(), conn.RemoteAddr().String(), info.ID)

		return conn, nil
	}
}

// dialClientPipe - Forwards a Pipe connection coming from a Client Comm to an implant, revolved with current routes.
// (In the end this function means a given Comm can find another Comm and route its connection through it)
// func dialClientPipe(info *commpb.Conn, ch ssh.NewChannel) error {
//
//         // If not found, check routes, return if not found: portfwds and proxies
//         // are supposedly not allowed to contact on the server's interfaces.
//         hostPort := fmt.Sprintf("%s:%d", info.RHost, info.RPort)
//         route, err := ResolveAddress(hostPort)
//         if err != nil || route == nil {
//                 err := ch.Reject(ssh.Prohibited, "NOROUTE")
//                 if err != nil {
//                         rLog.Errorf("Error: rejecting Pipe stream: %s", err)
//                 }
//                 return fmt.Errorf("rejected Client Comm Pipe connection: (bad destination: %s)", hostPort)
//         }
//
//         // We might not have an ID for this connection yet, so add the ID of the route we resolved
//         info.ID = route.ID.String()
//
//         // Get a connection to the implant gateway.
//         dst, err := route.comm.DialContextPipe(context.Background(), "tcp", hostPort)
//         if err != nil {
//                 err = ch.Reject(ssh.ConnectionFailed, err.Error())
//                 if err != nil {
//                         rLog.Errorf("error rejecting Pipe connection: %s", err.Error())
//                 }
//                 return fmt.Errorf("rejected Client Comm Pipe connection: %s", err.Error())
//         }
//
//         // Accept the Comm Client stream
//         src, reqs, err := ch.Accept()
//         if err != nil {
//                 return fmt.Errorf("failed to accept stream (%s)", string(ch.ExtraData()))
//         }
//         go ssh.DiscardRequests(reqs)
//
//         // Pipe
//         err = transportConn(src, dst)
//         if err != nil {
//                 rLog.Warnf("Error transporting connections (%s --> %s:%d): %v",
//                         hostPort, info.LHost, info.LPort, err)
//         }
//
//         // Close connections once we're done, with a delay left so our
//         // custom RPC tunnel has time to transmit the remaining data.
//         closeConnections(src, dst)
//
//         rLog.Infof("[route] Closed Pipe stream %s:%d --> %s:%d",
//                 info.LHost, info.LPort, info.RHost, info.RPort)
//
//         return nil
// }
