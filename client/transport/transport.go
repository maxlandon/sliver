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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

var (
	// RPC - The RPC client used by the console to make RPC calls to the server.
	// It is also used by the commands and completers package to make calls to the server.
	RPC rpcpb.SliverRPCClient

	// The AdminRPC contains all functions restricted to the server console.
	AdminRPC rpcpb.SliverAdminRPCClient

	// grpcConn - Reference to the current console gRPC connection, that we need
	// when exiting with command "exit"
	grpcConn *grpc.ClientConn
)

const (
	kb = 1024
	mb = kb * 1024
	gb = mb * 1024

	// ClientMaxReceiveMessageSize - Max gRPC message size ~2Gb
	ClientMaxReceiveMessageSize = 2 * gb

	defaultTimeout = time.Duration(10 * time.Second)
)

// ConnectTLS - Establishes a TLS connection on which we will register gRPC clients
func ConnectTLS() (*grpc.ClientConn, error) {

	// Setup TLS
	tlsConfig, err := getTLSConfig(assets.ServerCACertificate, assets.ServerCertificate, assets.ServerPrivateKey)
	if err != nil {
		return nil, err
	}

	// Set gRPC options
	creds := credentials.NewTLS(tlsConfig)
	options := []grpc.DialOption{
		grpc.WithTimeout(defaultTimeout),
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(ClientMaxReceiveMessageSize)),
	}

	// Dial server with these certificates
	server := fmt.Sprintf("%s:%s", assets.ServerLHost, assets.ServerLPort)
	conn, err := grpc.Dial(server, options...)
	if err != nil {
		fmt.Printf("Failed to connect to gRPC: %s", err)
	}

	// Keep a reference to this connection
	grpcConn = conn

	return conn, nil
}

func getTLSConfig(caCertificate string, certificate string, privateKey string) (*tls.Config, error) {

	certPEM, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if err != nil {
		log.Printf("Cannot parse client certificate: %v", err)
		return nil, err
	}

	// Load CA cert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(caCertificate))

	// Setup config with custom certificate validation routine
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{certPEM},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true, // Don't worry I sorta know what I'm doing
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return rootOnlyVerifyCertificate(caCertificate, rawCerts)
		},
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

// rootOnlyVerifyCertificate - Go doesn't provide a method for only skipping hostname validation so
// we have to disable all of the fucking certificate validation and re-implement everything.
// https://github.com/golang/go/issues/21971
func rootOnlyVerifyCertificate(caCertificate string, rawCerts [][]byte) error {

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(caCertificate))
	if !ok {
		log.Printf("Failed to parse root certificate")
		os.Exit(3)
	}

	cert, err := x509.ParseCertificate(rawCerts[0]) // We should only get one cert
	if err != nil {
		log.Printf("Failed to parse certificate: " + err.Error())
		return err
	}

	// Basically we only care if the certificate was signed by our authority
	// Go selects sensible defaults for time and EKU, basically we're only
	// skipping the hostname check, I think?
	options := x509.VerifyOptions{
		Roots: roots,
		// Needs to specify key usage here, otherwise the server rejects verification.
		// KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(options); err != nil {
		log.Printf("Failed to verify certificate: " + err.Error())
		return err
	}

	return nil
}

// SetClientConnGRPC - Keep a reference to the gRPC connection, to be used by some commands.
func SetClientConnGRPC(conn *grpc.ClientConn) {
	grpcConn = conn
}

// CloseClientConnGRPC - The client exists, and we disconnect the gRPC transport.
func CloseClientConnGRPC() error {
	return grpcConn.Close()
}