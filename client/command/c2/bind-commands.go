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
	"github.com/maxlandon/gonsole"

	"github.com/bishopfox/sliver/client/completion"
	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/help"

	// Listeners & other C2 components implementations
	"github.com/bishopfox/sliver/client/command/c2/listeners"
	"github.com/bishopfox/sliver/client/command/c2/pivots"
	"github.com/bishopfox/sliver/client/command/c2/websites"
)

// BindCommands - C2 transports might be available in either or both contexts.
// For now, there is a clear seggregation, and server listeners can only be spawned from the server context.
func BindCommands(cc *gonsole.Menu) {

	switch cc.Name {
	// ----------------------------------------------------------------------------------------------
	// All C2 transports that can listen on/ dial from the server.
	// ----------------------------------------------------------------------------------------------
	case constants.ServerMenu:
		// C2 listeners -----------------------------------------------------------------
		stager := cc.AddCommand(constants.StageListenerStr,
			"Start a staging listener (TCP/HTTP/HTTPS), bound to a Sliver profile",
			help.GetHelpFor(constants.StageListenerStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &listeners.StageListener{} })
		stager.AddOptionCompletionDynamic("URL", completion.NewURLCompleterStager().CompleteURL)
		stager.AddOptionCompletionDynamic("Certificate", core.Console.Completer.LocalPathAndFiles)
		stager.AddOptionCompletionDynamic("PrivateKey", core.Console.Completer.LocalPathAndFiles)
		stager.AddOptionCompletion("Profile", completion.ImplantProfiles)

		mtls := cc.AddCommand(constants.MtlsStr,
			"Start an mTLS listener on the server, or on a routed session",
			help.GetHelpFor(constants.MtlsStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &listeners.MTLSListener{} })
		mtls.AddOptionCompletion("LHost", completion.ServerInterfaceAddrs)

		cc.AddCommand(constants.WGStr,
			"Start a WireGuard listener",
			help.GetHelpFor(constants.WGStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &listeners.WireGuardListener{} })

		wgConfig := cc.AddCommand(constants.WgConfigStr,
			"Generate a new WireGuard client config",
			help.GetHelpFor(constants.WgConfigStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &listeners.WireGuardConfig{} })
		wgConfig.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)

		cc.AddCommand(constants.DnsStr,
			"Start a DNS listener on the server",
			help.GetHelpFor(constants.DnsStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &listeners.DNSListener{} })

		https := cc.AddCommand(constants.HttpsStr,
			"Start an HTTP(S) listener on the server",
			help.GetHelpFor(constants.HttpsStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &listeners.HTTPSListener{} })
		https.AddOptionCompletion("Domain", completion.ServerInterfaceAddrs)
		https.AddOptionCompletionDynamic("Certificate", core.Console.Completer.LocalPathAndFiles)
		https.AddOptionCompletionDynamic("PrivateKey", core.Console.Completer.LocalPathAndFiles)

		http := cc.AddCommand(constants.HttpStr,
			"Start an HTTP listener on the server",
			help.GetHelpFor(constants.HttpStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &listeners.HTTPListener{} })
		http.AddOptionCompletion("LHost", completion.ServerInterfaceAddrs)

		// Websites -----------------------------------------------------------------
		ws := cc.AddCommand(constants.WebsitesStr,
			"Manage websites (used with HTTP C2) (prints website name argument by default)",
			"",
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &websites.Websites{} })

		ws.SubcommandsOptional = true

		ws.AddCommand(constants.WebsitesShowStr,
			"Print the contents of a website",
			"",
			"",
			[]string{""},
			func() gonsole.Commander { return &websites.WebsitesShow{} })

		ws.AddCommand(constants.RmStr,
			"Remove an entire website",
			"", "", []string{""},
			func() gonsole.Commander { return &websites.WebsitesDelete{} })

		wa := ws.AddCommand(constants.AddWebContentStr,
			"Add content to a website",
			"", "", []string{""},
			func() gonsole.Commander { return &websites.WebsitesAddContent{} })
		wa.AddOptionCompletionDynamic("Content", core.Console.Completer.LocalPathAndFiles)

		wd := ws.AddCommand(constants.RmWebContentStr,
			"Remove content from a website",
			"", "", []string{""},
			func() gonsole.Commander { return &websites.WebsitesDeleteContent{} })
		wd.AddOptionCompletionDynamic("Content", core.Console.Completer.LocalPathAndFiles)

		wu := ws.AddCommand(constants.WebUpdateStr,
			"Update a website's content type",
			"", "", []string{""},
			func() gonsole.Commander { return &websites.WebsiteType{} })
		wu.AddOptionCompletionDynamic("Content", core.Console.Completer.LocalPathAndFiles)

	// ----------------------------------------------------------------------------------------------
	// All C2 transports that can listen on/ dial from the implant.
	// ----------------------------------------------------------------------------------------------
	case constants.SliverMenu:
		// C2 listeners -----------------------------------------------------------------
		tcp := cc.AddCommand(constants.TCPListenerStr,
			"Start a TCP pivot listener (unencrypted!)",
			"",
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &pivots.TCPPivot{} })
		tcp.AddOptionCompletion("LHost", completion.ActiveSessionIfaceAddrs)

		cc.AddCommand(constants.NamedPipeStr,
			"Start a named pipe pivot listener",
			"",
			constants.TransportsGroup,
			[]string{"windows"}, // Command is only available if the sliver host OS is Windows
			func() gonsole.Commander { return &pivots.NamedPipePivot{} })
	}
}
