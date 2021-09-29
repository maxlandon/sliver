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

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

const (
	defaultDNSLPort = 53
)

// Listen - Start a DNS listener on the server or in the current context
type Listen struct {
	Args struct {
		Domains []string `description:"one or more DNS C2 domains to callback"`
	} `positional-args:"yes"`
	Options struct {
		LPort      uint32 `long:"lport" short:"p" description:"listener UDP listen port"`
		NoCanaries bool   `long:"no-canaries" short:"c" description:"disable DNS canary detection for this listener"`
		Persistent bool   `long:"persistent" short:"P" description:"make listener persistent across server restarts"`
	} `group:"DNS listener options"`
}

// Execute - Start a DNS listener on the server or in the current context
func (l *Listen) Execute(args []string) (err error) {

	domains := l.Args.Domains
	for _, domain := range domains {
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}
	}

	lport := l.Options.LPort
	if lport == 0 {
		lport = defaultDNSLPort
	}

	log.Infof("Starting DNS listener with parent domain(s) %v ...", domains)
	dns, err := transport.RPC.StartDNSListener(context.Background(), &clientpb.DNSListenerReq{
		Domains:    domains,
		Port:       lport,
		Canaries:   !l.Options.NoCanaries,
		Persistent: l.Options.Persistent,
	})
	if err != nil {
		return log.Errorf("Failed to start DNS listener: %s", err)
	}
	log.Infof("Successfully started job #%d", dns.JobID)

	return
}
