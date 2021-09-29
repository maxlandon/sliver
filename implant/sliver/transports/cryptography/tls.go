package cryptography

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
	"os"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// TLSConfig - A wrapper around several elements needed to produce a TLS config for either
// a server or a client, depending on the direction of the connection to the implant.
type TLSConfig struct {
	ca   *x509.CertPool
	cert tls.Certificate
	key  []byte
}

// NewCredentialsTLS - Generates a new custom tlsConfig loaded with the Slivers Certificate Authority.
// It may thus load and export any TLS configuration for talking with an implant, bind or reverse.
func NewCredentialsTLS(caCertPEM, certPEM, keyPEM []byte) (creds *TLSConfig) {

	// Load CA cert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error loading server certificate: %v", err)
		// {{end}}
		os.Exit(5)
	}

	creds = &TLSConfig{
		ca:   caCertPool,
		cert: cert,
	}

	return creds
}

// ClientConfig - TLS config used when we dial an implant over Mutual TLS.
// This makes use of a custom function for skipping (only) hostname validation,
// because the tlsConfig verifies only against its own Certificate Authority.
func (t *TLSConfig) ClientConfig(host string) (c *tls.Config) {

	// Client config with custom certificate validation routine
	c = &tls.Config{
		Certificates:          []tls.Certificate{t.cert},
		RootCAs:               t.ca,
		InsecureSkipVerify:    true, // Don't worry I sorta know what I'm doing
		VerifyPeerCertificate: t.rootOnlyVerifyCertificate,
		MinVersion:            tls.VersionTLS13,
	}
	c.BuildNameToCertificate()

	return c
}

// ServerConfig - TLS config used when we listen for incoming Mutual TLS implant connections.
func (t *TLSConfig) ServerConfig(host string) (c *tls.Config) {

	// Server configuration
	c = &tls.Config{
		RootCAs:      t.ca,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    t.ca,
		Certificates: []tls.Certificate{t.cert},
		MinVersion:   tls.VersionTLS13,
	}
	c.BuildNameToCertificate()

	return
}

// rootOnlyVerifyCertificate - Go doesn't provide a method for only skipping hostname validation so
// we have to disable all of the fucking certificate validation and re-implement everything.
// https://github.com/golang/go/issues/21971
func (t *TLSConfig) rootOnlyVerifyCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {

	cert, err := x509.ParseCertificate(rawCerts[0]) // We should only get one cert
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Failed to parse certificate: " + err.Error())
		// {{end}}
		return err
	}

	// Basically we only care if the certificate was signed by our authority
	// Go selects sensible defaults for time and EKU, basically we're only
	// skipping the hostname check, I think?
	options := x509.VerifyOptions{
		Roots: t.ca,
	}
	if _, err := cert.Verify(options); err != nil {
		// {{if .Config.Debug}}
		log.Printf("Failed to verify certificate: " + err.Error())
		// {{end}}
		return err
	}

	return nil
}
