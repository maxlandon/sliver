package c2

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
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"google.golang.org/protobuf/proto"

	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	serverHandlers "github.com/bishopfox/sliver/server/handlers"
	"github.com/bishopfox/sliver/server/log"
)

const (
	// defaultServerCert - Default certificate name if bind is "" (all interfaces)
	defaultServerCert = ""

	readBufSize = 1024
)

var (
	mtlsLog = log.NamedLogger("c2", consts.MtlsStr)
)

// ServeListenerConnections - Given a listener, accept and handle any connection and wrap it into
// an implant connection, over which the session will be registered and used. This function is
// standard for any net.Listener based C2 handlers, as they will yield a net.Conn object that can
// be handled by this function and the subfunctions it makes uses of. Compatible with the Comm system.
//
// As well, this function is made so that it will automatically handle
// deregistering transports that have been set on the session at runtime.
func ServeListenerConnections(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			mtlsLog.Errorf("Accept failed: %v", err)
			if errType, ok := err.(*net.OpError); ok && errType.Op == "accept" {
				break
			}
			// Added to handle closed listeners from the Comm system.
			if err == net.ErrClosed {
				break
			}
			// Also added for closed listeners from the Comm system
			if errType, ok := err.(*net.OpError); ok && strings.Contains(errType.Error(), "closed listener") {
				break
			}
			continue
		}

		// For some reason when closing the listener
		// from the Comm system returns a nil connection...
		if conn == nil {
			mtlsLog.Errorf("Accepted a nil conn: %v", err)
			break
		}

		go handleSliverConnection(conn)
	}
}

// handleSliverConnection - Unexported implementation of HandleSessionConnections, which wraps
// a net.Conn (could be an io.ReadWriteCloser as well), into a Session connection object, which
// will support the Sliver RPC communication model.
// This function is also in charge of setting up various cleanup tasks, such
// as session transports reset and deletion from DB upon connection closing.
func handleSliverConnection(conn net.Conn) {
	mtlsLog.Infof("Accepted incoming connection: %s", conn.RemoteAddr())
	implantConn := core.NewImplantConnection(consts.MtlsStr, conn.RemoteAddr().String())

	// In the cleanup function, we add the automatic cleaning/deletion
	// of transports that have been set at runtime and that are currently
	// saved into the database.
	defer func() {
		mtlsLog.Debugf("mtls connection closing") // TODO: Remove
		conn.Close()                              // Close the physical/logical connection
		implantConn.Cleanup()                     // Close the RPC layer
	}()

	done := make(chan bool)
	go func() {
		defer func() {
			done <- true
		}()
		handlers := serverHandlers.GetHandlers()
		for {
			envelope, err := streamReadEnvelope(conn)
			if err != nil {
				mtlsLog.Errorf("Socket read error %v", err)
				return
			}
			implantConn.UpdateLastMessage()
			if envelope.ID != 0 {
				implantConn.RespMutex.RLock()
				if resp, ok := implantConn.Resp[envelope.ID]; ok {
					resp <- envelope // Could deadlock, maybe want to investigate better solutions
				}
				implantConn.RespMutex.RUnlock()
			} else if handler, ok := handlers[envelope.Type]; ok {
				go func() {
					respEnvelope := handler(implantConn, envelope.Data)
					if respEnvelope != nil {
						implantConn.Send <- respEnvelope
					}
				}()
			}
		}
	}()

Loop:
	for {
		select {
		case envelope := <-implantConn.Send:
			err := streamWriteEnvelope(conn, envelope)
			if err != nil {
				mtlsLog.Errorf("Socket write failed %v", err)
				break Loop
			}
		case <-done:
			break Loop
		}
	}
	mtlsLog.Debugf("Closing implant connection %s", implantConn.ID)
}

// streamWriteEnvelope - Writes a message to the stream using length prefix framing
// which is a fancy way of saying we write the length of the message then the message
// e.g. [uint32 length|message] so the receiver can delimit messages properly
func streamWriteEnvelope(connection io.ReadWriteCloser, envelope *sliverpb.Envelope) error {
	data, err := proto.Marshal(envelope)
	if err != nil {
		mtlsLog.Errorf("Envelope marshaling error: %v", err)
		return err
	}
	dataLengthBuf := new(bytes.Buffer)
	binary.Write(dataLengthBuf, binary.LittleEndian, uint32(len(data)))
	connection.Write(dataLengthBuf.Bytes())
	connection.Write(data)
	return nil
}

// streamReadEnvelope - Reads a message from the stream using length prefix framing
// returns messageType, message, and error
func streamReadEnvelope(connection io.ReadWriteCloser) (*sliverpb.Envelope, error) {

	// Read the first four bytes to determine data length
	dataLengthBuf := make([]byte, 4) // Size of uint32
	_, err := connection.Read(dataLengthBuf)
	if err != nil {
		mtlsLog.Errorf("Socket error (read msg-length): %v", err)
		return nil, err
	}
	dataLength := int(binary.LittleEndian.Uint32(dataLengthBuf))

	// Read the length of the data, keep in mind each call to .Read() may not
	// fill the entire buffer length that we specify, so instead we use two buffers
	// readBuf is the result of each .Read() operation, which is then concatinated
	// onto dataBuf which contains all of data read so far and we keep calling
	// .Read() until the running total is equal to the length of the message that
	// we're expecting or we get an error.
	readBuf := make([]byte, readBufSize)
	dataBuf := make([]byte, 0)
	totalRead := 0
	for {
		n, err := connection.Read(readBuf)
		dataBuf = append(dataBuf, readBuf[:n]...)
		totalRead += n
		if totalRead == dataLength {
			break
		}
		if err != nil {
			mtlsLog.Errorf("Read error: %s", err)
			break
		}
	}

	if err != nil {
		mtlsLog.Errorf("Socket error (read data): %v", err)
		return nil, err
	}
	// Unmarshal the protobuf envelope
	envelope := &sliverpb.Envelope{}
	err = proto.Unmarshal(dataBuf, envelope)
	if err != nil {
		mtlsLog.Errorf("Un-marshaling envelope error: %v", err)
		return nil, err
	}
	return envelope, nil
}

// CleanupSessionTransports - Once a session has been killed (and not merely disconnected)
// delete all the transports that have been set at runtime, so that they don't pile up at
// each new session reconnection/restart.
func CleanupSessionTransports(sess *core.Session) (err error) {

	// Get the transports (runtime and build) for the session
	transports, err := db.TransportsBySession(sess.UUID, sess.Name)
	if err != nil {
		return fmt.Errorf("Failed to retrieve session transports: %s", err)
	}
	build, err := db.ImplantBuildByName(sess.Name)
	if err != nil {
		return fmt.Errorf("Failed to retrieve session implant build: %s", err)
	}

	// Diff both lists of transports
	var toDelete = []*models.Transport{}
	for _, transport := range transports {
		found := false
		for _, buildTransport := range build.Transports {
			if buildTransport.ID == transport.ID {
				found = true
				break
			}
		}
		if !found {
			toDelete = append(toDelete, transport)
		}
	}

	// And delete those that have been set at runtime
	for _, transport := range toDelete {
		err = db.Session().Delete(transport).Error
		if err != nil {
			mtlsLog.Errorf("Failed to delete transport from DB: %s", err)
		}
	}

	return
}
