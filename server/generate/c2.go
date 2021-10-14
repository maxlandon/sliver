package generate

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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/certs"
	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/cryptography"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
)

// InitImplantTransports - Given one ore more C2 profiles transmitted along an Implant configuration,
// parse, validate, generate values for all C2s, make them ready for being compiled into a build.
func InitImplantTransports(pbConfig *clientpb.ImplantConfig, cfg *models.ImplantConfig) error {

	// For each C2 profile in the implant config, parse, validate and
	// populate it with everything needed to be compiled into an implant.
	for order, profile := range pbConfig.C2S {

		transport, err := NewTransport(cfg, profile)
		if err != nil {
			return err
		}
		transport.Priority = int32(order)
		cfg.Transports = append(cfg.Transports, transport)
	}

	// Set the connection strategy (how transports are chosen when failed)
	cfg.ConnectionStrategy = pbConfig.ConnectionStrategy

	// Analyze and set up the transports to be compiled in the build
	// so as to be available at runtime, for dynamic C2 switching.
	setTransportRuntime(pbConfig, cfg)

	// If the Comm system enabled, add necessary
	// keys for SSH authentication & encryption.
	configureCommSystem(pbConfig, cfg)

	// Save the transports for retrieval at registration time.

	return nil
}

// NewTransport - Validates all fields for a given transport specified as Protobuf,
// for any supported C2 protocols and targeting a precise implant build configuration.
// You can add your own branching calling a function dealing with your own C2 details and configurations.
func NewTransport(config *models.ImplantConfig, template *sliverpb.Malleable) (transport *models.Transport, err error) {

	// Base information parsing
	profile, err := newProfileFromConfig(template, config.Name)
	if err != nil {
		return nil, err
	}

	// Protocol-specific -----------------------------------------------------------------------

	// HTTP protocols need to check their builtin configuration, as well as
	// serializing those HTTP profiles in order to store them in the Database.
	if profile.Channel == sliverpb.C2_HTTP || profile.Channel == sliverpb.C2_HTTPS {
		err = setupTransportHTTP(template, config, profile)
		if err != nil {
			return nil, err
		}
	}

	// The Wireguard protocol might need a generated IP address
	if profile.Channel == sliverpb.C2_WG {
		err = setupTransportWG(template, config, profile)
		if err != nil {
			return nil, err
		}
	}

	// Transport Security ----------------------------------------------------------------------

	// Setup all certificates, keys and other credentials for the
	// appropriate C2 stack and the direction of the connection,
	// before passing this C2 back to compilation.
	err = c2.SetupMalleableSecurity(profile, config.Name)
	if err != nil {
		return nil, err
	}

	// Once everything is ready, wrap the profile into a transport, ready to be compiled
	return setTransport(profile), nil
}

// InitTransportCompilation - Any one-time security details, (or last minute ones) that need to happen before
// the C2 profile is used in compiling an implant, or to be sent accross the wire. This is also
// because some elements might not be saved in the database for that matter.
func InitTransportCompilation(p *models.Malleable) (profile *sliverpb.Malleable, err error) {

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

// newProfileFromConfig - Copy a C2 profile into a model, optionally validate somethings.
func newProfileFromConfig(p *sliverpb.Malleable, certificateHostname string) (*models.Malleable, error) {

	id, _ := uuid.NewV4()

	profile := &models.Malleable{
		// Core
		ID:               id,
		ContextSessionID: uuid.FromStringOrNil(p.ContextSessionID),
		Type:             p.Type,
		Channel:          p.C2,
		Direction:        p.Direction,
		Name:             p.Name,
		Hostname:         p.Hostname,
		Port:             p.Port,
		ControlPort:      p.ControlPort,
		KeyExchangePort:  p.KeyExchangePort,
		Path:             p.Path,
		Domains:          strings.Join(p.Domains, ","),
		// Technicals
		PollTimeout:         p.PollTimeout,
		MaxConnectionErrors: p.MaxConnectionErrors,
		Active:              p.Active,
		CommDisabled:        p.CommDisabled,
		Interval:            p.Interval,
		Jitter:              p.Jitter,
		// HTTP
		ProxyURL: p.ProxyURL,
		Website:  p.Website,
		// Security & Indentity
		CACertPEM:         p.Credentials.CACertPEM,
		CertPEM:           p.Credentials.CertPEM,
		KeyPEM:            p.Credentials.KeyPEM,
		ControlServerCert: p.Credentials.ControlServerCert,
		ControlClientKey:  p.Credentials.ControlClientKey,
		ServerFingerprint: p.Credentials.ServerFingerprint, // REMOVE
		LetsEncrypt:       p.LetsEncrypt,
	}

	// If this profile has no ID and no name, this means it is a buffer profile
	// that was used with one of the generate stage --flags, which are kinda legacy.
	// So because we need to know of these transports when the session registers and
	// that we need to manipulate them with the transports command, we mark them
	// as anonymous first, then assign them an ID by saving them to DB, so they can
	// send this ID back when calling home.
	if p.ID == "" && p.Name == "" {
		profile.Anonymous = true
	}

	// HTTP configuration

	return profile, nil
}

// setupTransportHTTP - Validates and/or populates any required HTTP C2 Profile stuff.
func setupTransportHTTP(p *sliverpb.Malleable, config *models.ImplantConfig, profile *models.Malleable) error {

	// If there are any miningful values set up, don't touch anything
	// and pass along, we assume the guy throwing the config has set it up already.
	if p.HTTP != nil && len(p.HTTP.SessionFiles) > 0 && len(p.HTTP.KeyExchangeFiles) > 0 {
		return nil
	}

	// Load default HTTP configuration, either compiled in server or in server config path
	if p.HTTP == nil {
		httpConfig := configs.GetHTTPC2Config().RandomImplantConfig()
		p.HTTP = httpConfig.MalleableHTTP // DOES NOT LOAD ANY SERVER VALUES
	}

	// Generate User agent for the implant
	p.HTTP.UserAgent = configs.GetHTTPC2Config().GenerateUserAgent(config.GOOS, config.GOARCH)

	data, err := proto.Marshal(p.HTTP)
	if err != nil {
		return fmt.Errorf("marshalling error: %s", err)
	}

	profile.HTTP = &models.MalleableHTTP{
		MalleableID: profile.ID,
		UserAgent:   p.HTTP.UserAgent,
		Data:        data,
	}

	return nil
}

// setupTransportWG - Validates and/or populates any required Wireguard C2 Profile stuff.
func setupTransportWG(p *sliverpb.Malleable, config *models.ImplantConfig, profile *models.Malleable) error {

	// If the profile already contains a Wireguard tunnel IP address, it is in the hostname.
	// Do not change it, and return the profile as is.
	// TODO: check valid IP
	if len(p.Domains) == 1 {
		return nil
	}

	// Else, generate a unique IP Address and return it
	tunIP, err := c2.GenerateUniqueIP()
	if err != nil {
		return err
	}
	profile.Domains = tunIP.String()

	return nil
}

//
// --- COMPILATION HELPERS  ------------------------------------------------------------------------------------------
//

func setTransportRuntime(pbConfig *clientpb.ImplantConfig, cfg *models.ImplantConfig) {

	// Determine which C2 stacks must be compiled, including those to be only available at runtime.
	var compiledC2s []string
	var runtimeC2s []string
	// Either include them all
	if cfg.RuntimeC2s == "all" {
		cfg.MTLSc2Enabled = true
		cfg.HTTPc2Enabled = true
		cfg.DNSc2Enabled = true
		cfg.WGc2Enabled = true
		cfg.NamePipec2Enabled = true
		cfg.TCPc2Enabled = true
	} else {
		// Or filter them
		for _, c2 := range strings.Split(cfg.RuntimeC2s, ",") {
			compiledC2s = append(compiledC2s, c2)
		}
	}

	mtls := append([]string{sliverpb.C2_MTLS.String()}, compiledC2s...)
	if cfg.MTLSc2Enabled = c2Enabled(mtls, cfg.Transports); cfg.MTLSc2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2_MTLS.String()))
	}

	wg := append([]string{sliverpb.C2_WG.String()}, compiledC2s...)
	if cfg.WGc2Enabled = c2Enabled(wg, cfg.Transports); cfg.WGc2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2_WG.String()))
	}

	http := append([]string{sliverpb.C2_HTTP.String(), sliverpb.C2_HTTPS.String()}, compiledC2s...)
	if cfg.HTTPc2Enabled = c2Enabled(http, cfg.Transports); cfg.HTTPc2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2_HTTP.String()))
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2_HTTPS.String()))
	}

	dns := append([]string{sliverpb.C2_DNS.String()}, compiledC2s...)
	if cfg.DNSc2Enabled = c2Enabled(dns, cfg.Transports); cfg.DNSc2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2_DNS.String()))
	}

	namedpipe := append([]string{sliverpb.C2_NamedPipe.String()}, compiledC2s...)
	if cfg.NamePipec2Enabled = c2Enabled(namedpipe, cfg.Transports); cfg.NamePipec2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2_NamedPipe.String()))
	}

	tcp := append([]string{sliverpb.C2_TCP.String()}, compiledC2s...)
	if cfg.TCPc2Enabled = c2Enabled(tcp, cfg.Transports); cfg.TCPc2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2_TCP.String()))
	}

	// Save the list of compiled C2 stacks in the config
	cfg.RuntimeC2s = strings.Join(runtimeC2s, ",")

	// Determine if SSH comm is enabled and needs to be compiled
	cfg.CommEnabled = isCommEnabled(pbConfig, cfg.Transports)

}

func c2Enabled(schemes []string, transports []*models.Transport) bool {
	for _, transport := range transports {
		for _, scheme := range schemes {
			if strings.ToLower(scheme) == strings.ToLower(transport.Profile.Channel.String()) {
				return true
			}
		}
	}
	return false
}

func isBeaconEnabled(cfg *clientpb.ImplantConfig, transport []*models.Transport) (enabled bool) {
	return true
}

// setTransport - wrap a C2 profile into a transport, ready to be used for compilation
func setTransport(c2 *models.Malleable) (transport *models.Transport) {
	id, _ := uuid.NewV4()
	transport = &models.Transport{
		ID:        id,
		ProfileID: c2.ID,
		Profile:   c2,
	}

	// All profiles will be saved with new IDs when saving the transports,
	// so mark them as Anonymous so that we don't have them on the back each time.
	c2.Anonymous = true

	return
}

// Comm System -------------------------------------------------------------------------------

func isCommEnabled(cfg *clientpb.ImplantConfig, transports []*models.Transport) (enabled bool) {
	// If there is at least one protocol that does not
	// explicitely denies it we set it true by default.
	for _, transport := range transports {
		if !transport.Profile.CommDisabled {
			enabled = true
		}
	}

	// BUT the user can choose to override all per-C2 settings
	// and either disable it entirely (--no-comms) or leave it on by default
	return !cfg.CommDisabled
}

// configureCommSystem - Populate the certificates and keys needed by the SSH Comm system
func configureCommSystem(pbConfig *clientpb.ImplantConfig, cfg *models.ImplantConfig) {
	if cfg.CommEnabled {
		// Make a fingerprint of the implant's private key, for SSH-layer authentication
		_, serverCAKey, err := certs.GetECCCertificate(certs.CommCA, "server")
		if err != nil {
			_, serverCAKey, _ = certs.CommGenerateECCCertificate("server")
		}
		signer, _ := ssh.ParsePrivateKey(serverCAKey)
		keyBytes := sha256.Sum256(signer.PublicKey().Marshal())
		fingerprint := base64.StdEncoding.EncodeToString(keyBytes[:])
		cfg.CommServerFingerprint = fingerprint

		// And generate the SSH keypair
		clientCert, clientKey, _ := certs.CommGenerateECCCertificate(pbConfig.Name)
		cfg.CommServerCert = string(clientCert)
		cfg.CommServerKey = string(clientKey)
	}
}
