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

	// {{if .Config.CommEnabled}}
	_ "github.com/bishopfox/sliver/implant/sliver/comm"
	// {{end}}

	// {{if .Config.MTLSc2Enabled}}
	_ "github.com/bishopfox/sliver/implant/sliver/transports/mtls"
	// {{end}}

	// {{if .Config.WGc2Enabled}}
	_ "github.com/bishopfox/sliver/implant/sliver/transports/wireguard"
	// {{end}}

	// {{if .Config.HTTPc2Enabled}}
	_ "github.com/bishopfox/sliver/implant/sliver/transports/httpclient"
	// {{end}}

	// {{if .Config.DNSc2Enabled}}
	_ "github.com/bishopfox/sliver/implant/sliver/transports/dnsclient"
	// {{end}}

	// {{if .Config.NamePipec2Enabled}}
	_ "github.com/bishopfox/sliver/implant/sliver/transports/namedpipe"
	// {{end}}

	// {{if .Config.TCPc2Enabled}}
	_ "github.com/bishopfox/sliver/implant/sliver/transports/tcp"
	// {{end}}
)

var (
	profiles = []string{
		// {{range $index, $value := .Transports}}
		`{{$value}}`, // {{$index}}
		// {{end}}
	}
)
