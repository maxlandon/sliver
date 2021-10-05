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

// HTTPListener - Start a HTTP listener
type HTTPListener struct {
	Options struct {
		Domain     string `long:"domain" short:"d" description:"HTTP C2 domain to callback (conversely, limit responses to specific domain)" required:"true"`
		LHost      string `long:"lhost" short:"L" description:"interface address to bind HTTP listener to" default:""`
		LPort      uint32 `long:"lport" short:"l" description:"listener TCP listen port" default:"80"`
		Website    string `long:"website" short:"w" description:"website name (see 'websites' command)"`
		Persistent bool   `long:"persistent" short:"p" description:"make listener persistent across server restarts"`
	} `group:"HTTP listener options"`
}

// Execute - Start a HTTP listener
func (m *HTTPListener) Execute(args []string) (err error) {
	// domain := m.Options.Domain
	// lport := m.Options.LPort
	// if lport == 0 {
	//         lport = defaultHTTPSLPort
	// }
	//
	// log.Infof("Starting HTTP %s:%d listener ...", domain, lport)
	// http, err := transport.RPC.StartHTTPListener(context.Background(), &clientpb.HTTPListenerReq{
	//         Domain:     domain,
	//         Website:    m.Options.Website,
	//         Host:       m.Options.LHost,
	//         Port:       lport,
	//         Secure:     false,
	//         Persistent: m.Options.Persistent,
	// })
	// if err != nil {
	//         return log.Errorf("Failed to start HTTP listener: %s", err)
	// }
	//
	// log.Infof("Successfully started job #%d", http.JobID)
	return
}
