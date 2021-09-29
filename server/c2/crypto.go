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

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/certs"
	"github.com/bishopfox/sliver/server/cryptography"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
)

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

	// Always set up the basic security level:
	// - TLS authenticated implants
	// - SSH-authenticated Comm system
	if p.Channel == sliverpb.C2Channel_MTLS {
		err = setupSecurityMTLS(p, certificateHostname)
		if err != nil {
			return
		}
	}

	// Specialized Authentication & Encryption setup ----------------------------------
	// Add anything you want.

	err = setupWireGuardAuth(p)

	return nil
}

// InitProfileSecurityCompilation - Any one-time security details, (or last minute ones) that need to happen before
// the C2 profile is used in compiling an implant, or to be sent accross the wire. This is also
// because some elements might not be saved in the database for that matter.
func InitProfileSecurityCompilation(p *models.C2Profile) (profile *sliverpb.C2Profile, err error) {

	// Instantiate something that can go off the wire.
	profile = p.ToProtobuf()

	// Time-based One-Time Passwordzzzz.... or buzzwords ?
	otpSecret, err := cryptography.TOTPServerSecret()
	if err != nil {
		return profile, err
	}
	profile.Credentials.TOTPServerSecret = []byte(otpSecret) // In doubt, use it anyway...

	// Save the profile, which might be anonymous. Update it if not new
	err = db.Session().Find(&p).Save(&p).Error
	if err != nil {
		return profile, err
	}
	profile.ID = p.ID.String()

	// Fully ready to be used
	return profile, nil
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

// setupWireGuardAuth - Adds an additional public private key pair for layer 3 (IP) encryption.
func setupWireGuardAuth(p *models.C2Profile) (err error) {
	if p.Channel != sliverpb.C2Channel_WG {
		return
	}

	implantPrivKey, _, err := certs.ImplantGenerateWGKeys(p.Hostname)
	_, serverPubKey, err := certs.GetWGServerKeys()
	if err != nil {
		return fmt.Errorf("Failed to embed implant wg keys: %s", err)
	}

	p.ControlServerCert = []byte(serverPubKey)
	p.ControlClientKey = []byte(implantPrivKey)

	return
}
