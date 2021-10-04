package dns

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
	"strings"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

const (
	defaultDNSLPort = 53
)

// Listen - Start a DNS listener on the server or in the current context
type Listen struct {
	Args struct {
		LocalAddr string `description:"host:port address to start DNS listener on (default: 0.0.0.0:53)"`
	} `positional-args:"yes"`

	c2.ListenerOptions

	Options struct {
		Domains    []string `long:"domains" short:"d" description:"one or more DNS C2 domains to callback"`
		NoCanaries bool     `long:"no-canaries" short:"c" description:"disable DNS canary detection for this listener"`
	} `group:"DNS listener options"`
}

// Execute - Start a DNS listener on the server or in the current context
func (l *Listen) Execute(args []string) (err error) {

	// Declare profile
	profile := c2.ParseActionProfile(
		sliverpb.C2Channel_DNS,       // A Channel using Mutual TLS
		l.Args.LocalAddr,             // Targeting the host:[port] argument of our command
		sliverpb.C2Direction_Reverse, // A listener
	)
	profile.Persistent = l.ListenerOptions.Core.Persistent
	profile.Canaries = !l.Options.NoCanaries

	domains := l.Options.Domains
	for _, domain := range domains {
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}
	}

	if profile.Port == 0 {
		profile.Port = defaultDNSLPort
	}

	log.Infof("Starting DNS listener with parent domain(s) %v ...", domains)
	res, err := transport.RPC.StartC2Handler(context.Background(), &clientpb.HandlerStartReq{
		Profile: profile,
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Error(err)
	}
	if !res.Success {
		return log.Errorf("An unknown error happened: no success")
	}

	log.Infof("Successfully started DNS listener")
	return
}
