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
	"context"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// GetSliverBinary - Get the binary of an implant based on it's profile
func GetSliverBinary(profile *clientpb.ImplantProfile) ([]byte, error) {
	var data []byte
	// get implant builds
	builds, err := transport.RPC.ImplantBuilds(context.Background(), &commonpb.Empty{})
	if err != nil {
		return data, err
	}

	implantName := BuildImplantName(profile.GetConfig().GetName())
	_, ok := builds.GetConfigs()[implantName]
	if implantName == "" || !ok {
		// no built implant found for profile, generate a new one
		log.Infof("No builds found for profile %s, generating a new one", profile.GetName())
		ctrl := make(chan bool)
		log.SpinUntil("Compiling, please wait ...", ctrl)

		generated, err := transport.RPC.Generate(context.Background(), &clientpb.GenerateReq{
			Config: profile.Config,
		})
		ctrl <- true
		<-ctrl
		if err != nil {
			return data, log.Errorf("Error generating implant")
		}
		data = generated.GetFile().GetData()
		profile.Config.Name = BuildImplantName(generated.GetFile().GetName())
		_, err = transport.RPC.SaveImplantProfile(context.Background(), profile)
		if err != nil {
			return data, log.Errorf("Error updating implant profile")
		}
	} else {
		// Found a build, reuse that one
		log.Infof("Sliver name for profile: %s", implantName)
		regenerate, err := transport.RPC.Regenerate(context.Background(), &clientpb.RegenerateReq{
			ImplantName: profile.GetConfig().GetName(),
		})

		if err != nil {
			return data, err
		}
		data = regenerate.GetFile().GetData()
	}
	return data, err
}
