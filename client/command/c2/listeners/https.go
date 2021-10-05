package listeners

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
	"io/ioutil"
)

// HTTPSListener - Start a HTTP(S) listener
type HTTPSListener struct {
	Options struct {
		Domain      string `long:"domain" short:"d" description:"HTTPS C2 domain to callback (conversely, limit responses to specific domain)" required:"true"`
		LHost       string `long:"lhost" short:"L" description:"interface address to bind HTTPS listener to" default:""`
		LPort       uint32 `long:"lport" short:"l" description:"listener TCP listen port" default:"443"`
		LetsEncrypt bool   `long:"lets-encrypt" short:"e" description:"attempt to provision a let's encrypt certificate"`
		Website     string `long:"website" short:"w" description:"website name (see 'websites' command)"`
		Certificate string `long:"certificate" description:"PEM encoded certificate file"`
		PrivateKey  string `long:"key" description:"PEM encoded private key file"`
		Persistent  bool   `long:"persistent" short:"p" description:"make listener persistent across server restarts"`
	} `group:"HTTP(S) listener options"`
}

// Execute - Start a HTTP(S) listener
func (m *HTTPSListener) Execute(args []string) (err error) {
	// domain := m.Options.Domain
	// website := m.Options.Website
	// lport := m.Options.LPort
	// if lport == 0 {
	//         lport = defaultHTTPSLPort
	// }
	//
	// cert, key, err := getLocalCertificatePair(m.Options.Certificate, m.Options.PrivateKey)
	// if err != nil {
	//         return log.Errorf("Failed to load local certificate %v", err)
	// }
	//
	// log.Infof("Starting HTTPS %s:%d listener ...", domain, lport)
	// https, err := transport.RPC.StartHTTPSListener(context.Background(), &clientpb.HTTPListenerReq{
	//         Domain:     domain, //
	//         Website:    website,
	//         Host:       m.Options.LHost, //
	//         Port:       lport,           //
	//         Secure:     true,
	//         Cert:       cert, // NOT SURE
	//         Key:        key,  //NOT SURE
	//         ACME:       m.Options.LetsEncrypt,
	//         Persistent: m.Options.Persistent, //
	// })
	// if err != nil {
	//         return log.Errorf("Failed to start HTTPS listener: %s", err)
	// }
	//
	// log.Infof("Successfully started job #%d\n", https.JobID)
	return
}

func getLocalCertificatePair(certPath, keyPath string) ([]byte, []byte, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil, nil
	}
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}
