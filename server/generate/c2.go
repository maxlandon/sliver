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
	"strings"

	"github.com/gofrs/uuid"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/certs"
	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/db/models"
)

// C2ProfileFromConfig - Copy a C2 profile into a model, optionally validate somethings.
func C2ProfileFromConfig(p *sliverpb.C2Profile, certificateHostname string) (*models.C2Profile, error) {

	id, _ := uuid.NewV4()

	profile := &models.C2Profile{
		// Core
		ID:        id,
		Name:      p.Name,
		Hostname:  p.Hostname,
		Port:      p.Port,
		Type:      p.Type,
		Channel:   p.C2,
		Direction: p.Direction,
		// Technicals
		PollTimeout:         p.PollTimeout,
		MaxConnectionErrors: p.MaxConnectionErrors,
		IsFallback:          p.IsFallback,
		Active:              p.Active,
		ControlPort:         p.ControlPort,
		CommDisabled:        p.CommDisabled,
		// Beaconing
		Interval: p.Interval,
		Jitter:   p.Jitter,
		// HTTP
		ProxyURL: p.ProxyURL,
		// Security & Indentity
		CACertPEM:         p.Credentials.CACertPEM,
		CertPEM:           p.Credentials.CertPEM,
		KeyPEM:            p.Credentials.KeyPEM,
		ServerFingerprint: p.Credentials.ServerFingerprint, // REMOVE
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

	// Setup all certificates, keys and other credentials
	// before passing this C2 back to compilation.
	err := c2.SetupProfileSecurity(profile, certificateHostname)
	if err != nil {
		return profile, err
	}

	return profile, nil
}

// InitImplantC2Configuration - Given one ore more C2 profiles transmitted along an Implant configuration,
// parse, validate, generate values for all C2s, make them ready for being compiled into a build.
func InitImplantC2Configuration(pbConfig *clientpb.ImplantConfig, cfg *models.ImplantConfig) error {

	// Setup and copy all available C2 profiles. This takes care of basic security also.
	for order, profile := range pbConfig.C2S {

		// Base, validated profile
		validated, err := C2ProfileFromConfig(profile, pbConfig.Name)
		if err != nil {
			return err
		}

		// HTTP protocols need to check their builtin configuration, as well as
		// serializing those HTTP profiles in order to store them in the Database.
		if validated.Channel == sliverpb.C2Channel_HTTP || validated.Channel == sliverpb.C2Channel_HTTPS {
			validated.HTTP.Data = setupC2ProfileClientHTTP(profile, cfg)
		}

		// Finally, add the C2 profile as a transport to the configuration
		transport := setTransport(validated)
		transport.Priority = order
		cfg.Transports = append(cfg.Transports, transport)
	}

	// Analyze and set up the transports to be compiled so as to be available
	// at runtime, for dynamic C2 switching.
	setRuntimeTransports(pbConfig, cfg)

	// If the Comm system enabled, add necessary keys for SSH authentication & encryption.
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

	return nil
}

// setupC2ProfileClientHTTP - Validates and/or populates any required HTTP C2 Profile stuff.
func setupC2ProfileClientHTTP(p *sliverpb.C2Profile, config *models.ImplantConfig) (httpProfileData []byte) {

	// If there are any miningful values set up, don't touch anything
	// and pass along, we assume the guy throwing the config has set it up already.
	if len(p.HTTP.SessionFiles) > 0 && len(p.HTTP.KeyExchangeFiles) > 0 {
		return
	}

	// Load default HTTP configuration, either compiled in server or in server config path
	if p.HTTP == nil {
		httpConfig := configs.GetHTTPC2Config().RandomImplantConfig()
		p.HTTP = httpConfig.C2ProfileHTTP // DOES NOT LOAD ANY SERVER VALUES
	}

	// Generate User agent for the implant
	p.HTTP.UserAgent = configs.GetHTTPC2Config().GenerateUserAgent(config.GOOS, config.GOARCH)

	data, err := proto.Marshal(p.HTTP)
	if err != nil {
		return []byte{}
	}

	return data
}

func setRuntimeTransports(pbConfig *clientpb.ImplantConfig, cfg *models.ImplantConfig) {

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

	mtls := append([]string{sliverpb.C2Channel_MTLS.String()}, compiledC2s...)
	if cfg.MTLSc2Enabled = c2Enabled(mtls, cfg.Transports); cfg.MTLSc2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2Channel_MTLS.String()))
	}

	wg := append([]string{sliverpb.C2Channel_WG.String()}, compiledC2s...)
	if cfg.WGc2Enabled = c2Enabled(wg, cfg.Transports); cfg.WGc2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2Channel_WG.String()))
	}

	http := append([]string{sliverpb.C2Channel_HTTP.String(), sliverpb.C2Channel_HTTPS.String()}, compiledC2s...)
	if cfg.HTTPc2Enabled = c2Enabled(http, cfg.Transports); cfg.HTTPc2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2Channel_HTTP.String()))
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2Channel_HTTPS.String()))
	}

	dns := append([]string{sliverpb.C2Channel_DNS.String()}, compiledC2s...)
	if cfg.DNSc2Enabled = c2Enabled(dns, cfg.Transports); cfg.DNSc2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2Channel_DNS.String()))
	}

	namedpipe := append([]string{sliverpb.C2Channel_NamedPipe.String()}, compiledC2s...)
	if cfg.NamePipec2Enabled = c2Enabled(namedpipe, cfg.Transports); cfg.NamePipec2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2Channel_NamedPipe.String()))
	}

	tcp := append([]string{sliverpb.C2Channel_TCP.String()}, compiledC2s...)
	if cfg.TCPc2Enabled = c2Enabled(tcp, cfg.Transports); cfg.TCPc2Enabled {
		runtimeC2s = append(runtimeC2s, strings.ToLower(sliverpb.C2Channel_TCP.String()))
	}

	// Determine if SSH comm is enabled and needs to be compiled
	cfg.CommEnabled = isCommEnabled(pbConfig, cfg.Transports)

	cfg.IsBeacon = isBeaconEnabled(pbConfig, cfg.Transports)

	// Save the list of compiled C2 stacks in the config
	cfg.RuntimeC2s = strings.Join(runtimeC2s, ",")
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

func isBeaconEnabled(cfg *clientpb.ImplantConfig, transport []*models.Transport) (enabled bool) {
	return true
}

// setTransport - wrap a C2 profile into a transport, ready to be used for compilation
func setTransport(c2 *models.C2Profile) (transport *models.Transport) {
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
