package rpc

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
	"time"

	"github.com/bishopfox/sliver/protobuf/builderpb"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/server/build/canaries"
	"github.com/bishopfox/sliver/server/build/codenames"
	"github.com/bishopfox/sliver/server/build/implants"
	"github.com/bishopfox/sliver/server/build/profiles"
	"github.com/bishopfox/sliver/server/certs"
	"github.com/google/uuid"
)

// Generate - Generate a new implant
func (rpc *SliverServer) Generate(ctx context.Context, req *clientpb.GenerateReq) (*clientpb.Generate, error) {
	// Cert PEM encoded certificates
	if req.Config.Name == "" {
		req.Config.Name = codenames.GetCodename()
	}
	caCert, _, _ := certs.GetCertificateAuthorityPEM(certs.ServerCA)
	clientCert, clientKey, err := certs.SliverGenerateECCCertificate(req.Config.Name)
	if err != nil {
		return nil, err
	}
	rsaKey, _, err := certs.SliverGenerateRSACertificate(req.Config.Name)
	if err != nil {
		return nil, err
	}
	req.Config.ECC_CACert = string(caCert)
	req.Config.ECC_ClientCert = string(clientCert)
	req.Config.ECC_ClientKey = string(clientKey)
	req.Config.RSA_Cert = string(rsaKey)
	req.Config.BuildTimeout = int64(time.Hour)
	guid := uuid.New().String()
	buildTask := &builderpb.BuildTask{
		GUID:          guid,
		ImplantConfig: req.Config,
	}
	artifact, err := rpc.buildRPC.Build(ctx, buildTask)
	return &clientpb.Generate{File: artifact.File}, err
}

// Regenerate - Regenerate a previously generated implant
func (rpc *SliverServer) Regenerate(ctx context.Context, req *clientpb.RegenerateReq) (*clientpb.Generate, error) {

	config, err := implants.ImplantConfigByName(req.ImplantName)
	if err != nil {
		return nil, err
	}

	fileData, err := implants.ImplantFileByName(req.ImplantName)
	if err != nil {
		return nil, err
	}

	return &clientpb.Generate{
		File: &commonpb.File{
			Name: config.FileName,
			Data: fileData,
		},
	}, nil
}

// ImplantBuilds - List existing implant builds
func (rpc *SliverServer) ImplantBuilds(ctx context.Context, _ *commonpb.Empty) (*clientpb.ImplantBuilds, error) {
	configs, err := implants.ImplantConfigMap()
	if err != nil {
		return nil, err
	}
	builds := &clientpb.ImplantBuilds{
		Configs: map[string]*clientpb.ImplantConfig{},
	}
	for name, config := range configs {
		builds.Configs[name] = config
	}
	return builds, nil
}

// Canaries - List existing canaries
func (rpc *SliverServer) Canaries(ctx context.Context, _ *commonpb.Empty) (*clientpb.Canaries, error) {
	jsonCanaries, err := canaries.ListCanaries()
	if err != nil {
		return nil, err
	}

	rpcLog.Infof("Found %d canaries", len(jsonCanaries))
	canaries := []*clientpb.DNSCanary{}
	for _, canary := range jsonCanaries {
		canaries = append(canaries, canary.ToProtobuf())
	}

	return &clientpb.Canaries{
		Canaries: canaries,
	}, nil
}

// ImplantProfiles - List profiles
func (rpc *SliverServer) ImplantProfiles(ctx context.Context, _ *commonpb.Empty) (*clientpb.ImplantProfiles, error) {
	implantProfiles := &clientpb.ImplantProfiles{
		Profiles: []*clientpb.ImplantProfile{},
	}
	for name, config := range profiles.Profiles() {
		implantProfiles.Profiles = append(implantProfiles.Profiles, &clientpb.ImplantProfile{
			Name:   name,
			Config: config,
		})
	}
	return implantProfiles, nil
}

// SaveImplantProfile - Save a new profile
func (rpc *SliverServer) SaveImplantProfile(ctx context.Context, profile *clientpb.ImplantProfile) (*clientpb.ImplantProfile, error) {
	return nil, nil
	// config := profiles.ImplantConfigFromProtobuf(profile.Config)
	// profile.Name = path.Base(profile.Name)
	// if 0 < len(profile.Name) && profile.Name != "." {
	// 	rpcLog.Infof("Saving new profile with name %#v", profile.Name)
	// 	err := profiles.ProfileSave(profile.Name, config)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return profile, nil
	// }
	// return nil, errors.New("Invalid profile name")
}

// ShellcodeRDI - Generates a RDI shellcode from a given DLL
func (rpc *SliverServer) ShellcodeRDI(ctx context.Context, req *clientpb.ShellcodeRDIReq) (*clientpb.ShellcodeRDI, error) {
	return nil, nil
	// shellcode, err := generate.ShellcodeRDIFromBytes(req.GetData(), req.GetFunctionName(), req.GetArguments())
	// return &clientpb.ShellcodeRDI{Data: shellcode}, err
}
