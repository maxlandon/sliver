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
	"fmt"
	"strings"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/certs"
	"github.com/bishopfox/sliver/server/db/models"
)

// SetupHandlerProfile - Root function where all profiles used by HANDLERS are validated and
// optionally populated if some fields are missing. Covers everything: C2 target addresses,
// default ports, connectivity, security details and more.
//
// You can add your own branching with a function checking
// and populating fields specific to/needed by you C2 channel
func SetupHandlerProfile(profile *models.C2Profile) (err error) {

	// If the profile is an HTTP C2, verify the server has everything it needs
	if profile.Channel == sliverpb.C2Channel_HTTP || profile.Channel == sliverpb.C2Channel_HTTPS {

	}

	// Check that all credentials needed by the handler are loaded
	err = SetupHandlerSecurity(profile, profile.Hostname)
	if err != nil {
		return err
	}

	return
}

// SetupHandlerSecurity - Performs more or less the same job as SetupProfileSecurity, in that
// it works on and validates a C2Profile. However, no certification creation is made by default
// here, as handlers are either based on profiles linked to implant builds, or profiles that
// don't need specialized credentials, outside of the base Sliver security features.
func SetupHandlerSecurity(p *models.C2Profile, hostname string) (err error) {

	// MTLS requires a set of TLS certificates
	if p.Channel == sliverpb.C2Channel_MTLS {
	}

	// Parse any user names / logins / key fingerprints,
	// before anyone starts assuming there are certs in place

	return
}

// SetupProfileSecurity - The central point where all C2 Profiles go at some point, for validation of minimum safety levels, as
// well as for more specialized authentication steps that you can add below, for more exotic C2 channels like Wireguard.
func SetupProfileSecurity(p *models.C2Profile, certificateHostname string) (err error) {

	// - TLS authenticated implants
	if p.Channel == sliverpb.C2Channel_MTLS {
		err = setupSecurityMTLS(p, certificateHostname)
		if err != nil {
			return
		}
	}

	// Wireguard implants
	if p.Channel == sliverpb.C2Channel_WG {
		err = setupWireGuardAuth(p)
		if err != nil {
			return
		}
	}

	// HTTP implants
	// The difference here is that instead of generating certificates
	// with implant names as hostnames, we use the domain used by the C2 profile.
	if p.Channel == sliverpb.C2Channel_HTTPS {
		err = setupSecurityHTTPS(p)
		if err != nil {
			return
		}
	}

	return nil
}

// setupSecurityMTLS - Most basic security details for all implant C2s leaving the server.
func setupSecurityMTLS(p *models.C2Profile, certificateHostname string) (err error) {

	// If no credentials whatsoever, this means we need basic certificate setup,
	// but if anything was set before, assume that whoever populated them knew
	// what they were doing...
	if len(p.CACertPEM) > 0 || len(p.CertPEM) > 0 || len(p.KeyPEM) > 0 {
		return nil
	}

	// If the profile is a dialer, it means the implant is going to be the server
	// accepting the connections. Therefore we inverse the roles: we give it the
	// ServerC2 generated certificates.
	if p.Direction == sliverpb.C2Direction_Bind {
		p.CACertPEM, _, _ = certs.GetCertificateAuthorityPEM(certs.MtlsImplantCA)
		p.CertPEM, p.KeyPEM, err = certs.MtlsC2ServerGenerateECCCertificate(certificateHostname)
		if err != nil {
			return err
		}
	}

	// If the profile is a listener, the implant reaches back to the
	// server, so we give it the sliver-specific certifcates and keys.
	if p.Direction == sliverpb.C2Direction_Reverse {
		p.CACertPEM, _, _ = certs.GetCertificateAuthorityPEM(certs.MtlsServerCA)
		p.CertPEM, p.KeyPEM, _ = certs.MtlsC2ImplantGenerateECCCertificate(certificateHostname)
		if err != nil {
			return err
		}
	}

	return nil
}

// setupSecurityHTTPS - HTTPS cert providing has strictly the same functionning as MTLS, except
// that the name of the implant is not passed as host, but the very C2 domain to be targeted.
func setupSecurityHTTPS(p *models.C2Profile) (err error) {

	// If no credentials whatsoever, this means we need basic certificate setup,
	// but if anything was set before, assume that whoever populated them knew
	// what they were doing...
	if len(p.CACertPEM) > 0 || len(p.CertPEM) > 0 || len(p.KeyPEM) > 0 {
		return nil
	}

	// Setup the hostname depending on available Listener domains or implant C2 callback URLs
	var hostname string
	if len(strings.Split(p.Domains, ",")) == 0 {
		hostname = p.Hostname
	} else {
		hostname = strings.Split(p.Domains, ",")[0]
	}

	// If the profile is a dialer, it means the implant is going to be the server
	// accepting the connections. Therefore we inverse the roles: we give it the
	// ServerC2 generated certificates.
	if p.Direction == sliverpb.C2Direction_Bind {
		p.CACertPEM, _, _ = certs.GetCertificateAuthorityPEM(certs.MtlsImplantCA)
		p.CertPEM, p.KeyPEM, err = certs.MtlsC2ServerGenerateECCCertificate(hostname)
		if err != nil {
			return err
		}
	}

	// If the profile is a listener, the implant reaches back to the
	// server, so we give it the sliver-specific certifcates and keys.
	if p.Direction == sliverpb.C2Direction_Reverse {
		p.CACertPEM, _, _ = certs.GetCertificateAuthorityPEM(certs.MtlsServerCA)
		p.CertPEM, p.KeyPEM, _ = certs.MtlsC2ImplantGenerateECCCertificate(hostname)
		if err != nil {
			return err
		}
	}

	return nil
}

// setupWireGuardAuth - Adds an additional public private key pair for layer 3 (IP) encryption.
func setupWireGuardAuth(p *models.C2Profile) (err error) {

	implantPrivKey, _, err := certs.ImplantGenerateWGKeys(p.Hostname)
	_, serverPubKey, err := certs.GetWGServerKeys()
	if err != nil {
		return fmt.Errorf("Failed to embed implant wg keys: %s", err)
	}

	p.ControlServerCert = []byte(serverPubKey)
	p.ControlClientKey = []byte(implantPrivKey)

	return
}
