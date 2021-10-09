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
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

func parseC2Transports(g StageOptions, cfg *clientpb.ImplantConfig) (err error) {

	// Targets parsing in C2 Profiles ----------------------------------------------------------------
	if len(g.TransportOptions.MTLS) > 0 {
		for _, address := range g.TransportOptions.MTLS {
			profile := c2.ParseProfile(
				sliverpb.C2Channel_MTLS,      // A Channel using Mutual TLS
				address,                      // Targeting the host:[port] argument of our command
				sliverpb.C2Direction_Reverse, // A listener
				c2.ProfileOptions{},          // This will automatically parse Profile options into the protobuf
			)
			cfg.C2S = append(cfg.C2S, profile)
		}
	}

	if len(g.TransportOptions.WireGuard) > 0 {
		for range g.TransportOptions.WireGuard {
			// for _, address := range g.TransportOptions.WireGuard {

			// Generate a new unique Tunnel IP per address for each string in WireGuard transports
			var tunIP net.IP
			if wg := g.TransportOptions.WireGuard; len(wg) > 0 {
				uniqueWGIP, err := transport.RPC.GenerateUniqueIP(context.Background(), &commonpb.Empty{})
				tunIP = net.ParseIP(uniqueWGIP.IP)
				if err != nil {
					return fmt.Errorf("Failed to generate unique ip for wg peer tun interface")
				}
				log.Infof("Generated unique IP for WireGuard peer tun interface: %s", readline.Yellow(tunIP.String()))
			}

			profile := c2.ParseProfile(
				sliverpb.C2Channel_WG,
				tunIP.String(),
				sliverpb.C2Direction_Reverse,
				c2.ProfileOptions{},
			)

			// Additional Wireguard options
			profile.ControlPort = uint32(g.TransportOptions.TCPComms)
			profile.KeyExchangePort = uint32(g.TransportOptions.KeyExchange)
			cfg.C2S = append(cfg.C2S, profile)
		}
	}

	if len(g.TransportOptions.DNS) > 0 {
		for _, address := range g.TransportOptions.DNS {
			profile := c2.ParseProfile(
				sliverpb.C2Channel_DNS,
				address,
				sliverpb.C2Direction_Reverse,
				c2.ProfileOptions{},
			)
			cfg.C2S = append(cfg.C2S, profile)
		}
	}

	if len(g.TransportOptions.HTTP) > 0 {
		for _, address := range g.TransportOptions.HTTP {
			profile := c2.ParseProfile(
				sliverpb.C2Channel_HTTP,
				address,
				sliverpb.C2Direction_Reverse,
				c2.ProfileOptions{},
			)
			cfg.C2S = append(cfg.C2S, profile)
		}

	}

	if len(g.TransportOptions.NamedPipe) > 0 {
		for _, address := range g.TransportOptions.NamedPipe {
			profile := c2.ParseProfile(
				sliverpb.C2Channel_NamedPipe,
				address,
				sliverpb.C2Direction_Reverse,
				c2.ProfileOptions{},
			)
			cfg.C2S = append(cfg.C2S, profile)
		}
	}

	if len(g.TransportOptions.TCP) > 0 {
		for _, address := range g.TransportOptions.TCP {
			profile := c2.ParseProfile(
				sliverpb.C2Channel_TCP,
				address,
				sliverpb.C2Direction_Reverse,
				c2.ProfileOptions{},
			)
			cfg.C2S = append(cfg.C2S, profile)
		}
	}

	// Base Options -----------------------------------------------------------------------------------

	// If connection settings have been specified, apply them to all profiles indiscriminatly.
	for _, profile := range cfg.C2S {
		profile.MaxConnectionErrors = int32(g.TransportOptions.MaxErrors)
		profile.PollTimeout = int64(g.TransportOptions.PollTimeout) * int64(time.Second)
		profile.Interval = int64(g.TransportOptions.Reconnect) * int64(time.Second)

		// All profiles are fallback by default
		profile.IsFallback = true
		// And they might be forbidden to use SSH multiplexing
		profile.CommDisabled = g.TransportOptions.DisableComm
	}

	// Malleable C2 Profiles ---------------------------------------------------------------------------

	// If no C2 strings specified and C2 profiles IDs given, return
	if len(cfg.C2S) == 0 && len(g.TransportOptions.C2Profiles) == 0 {
		return fmt.Errorf(`Must specify at least: 
                => one of --mtls, --http, --dns, --named-pipe, or --tcp-pivot 
                => one or more C2 profiles with --malleables <malleableID>,<malleableID2>`)
	}

	// Else add the profiles
	if len(g.TransportOptions.C2Profiles) > 0 {
		profiles, err := transport.RPC.GetC2Profiles(context.Background(),
			&clientpb.GetC2ProfilesReq{
				Request: core.ActiveTarget.Request(),
			})
		if err != nil {
			return fmt.Errorf("failed to fetch C2 profiles from server: %s", err)
		}

		// Each matching ID.
		for _, raw := range g.TransportOptions.C2Profiles {
			// Bug in split forces us to redo it here
			var splitted = strings.Split(raw, ",")
			for _, id := range splitted {
				for _, prof := range profiles.Profiles {
					if c2.GetShortID(prof.ID) == id {
						cfg.C2S = append(cfg.C2S, prof)
					}
				}
			}
		}
	}

	// Compatibility verifications ---------------------------------------------------------------------
	for _, c2 := range cfg.C2S {
		if c2.C2 == sliverpb.C2Channel_NamedPipe {
			if cfg.GOOS != "windows" {
				return fmt.Errorf("Named pipe C2 transports can only be used in Windows")
			}
		}
	}

	return
}
