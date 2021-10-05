package command

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
	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/command/c2/dns"
	"github.com/bishopfox/sliver/client/command/c2/http"
	"github.com/bishopfox/sliver/client/command/c2/https"
	"github.com/bishopfox/sliver/client/command/c2/listeners"
	"github.com/bishopfox/sliver/client/command/c2/malleable"
	"github.com/bishopfox/sliver/client/command/c2/mtls"
	"github.com/bishopfox/sliver/client/command/c2/pivots"
	"github.com/bishopfox/sliver/client/command/c2/tcp"
	"github.com/bishopfox/sliver/client/command/c2/transports"
	"github.com/bishopfox/sliver/client/command/c2/websites"
	"github.com/bishopfox/sliver/client/command/c2/wg"
)

// bindCommands - C2 transports might be available in either or both contexts.
// For now, there is a clear seggregation, and server listeners can only be spawned from the server context.
func bindCommandsC2(cc *gonsole.Menu) {

	//
	// Malleable C2 Profiles -------------------------------------------------------------------
	//

	malleableCmd := cc.AddCommand(constants.MalleableStr,
		"C2 Profiles creation & management commands",
		help.GetHelpFor(constants.MtlsStr),
		constants.TransportsGroup,
		[]string{""},
		func() gonsole.Commander { return &malleable.Malleable{} })

	// New C2 Profiles commands per C2 stack  -----------
	malleableDialer := malleableCmd.AddCommand(constants.DialerStr,
		"Create a new dialer (bind) C2 Profile for any available protocol",
		help.GetHelpFor(constants.DialerStr),
		"creation",
		[]string{""},
		func() gonsole.Commander { return &c2.Dialer{} })

	malleableListener := malleableCmd.AddCommand(constants.ListenerStr,
		"Create a new listener (reverse) C2 Profile for any available protocol",
		help.GetHelpFor(constants.DialerStr),
		"creation",
		[]string{""},
		func() gonsole.Commander { return &c2.Dialer{} })

	// C2 profiles management commands -----------------
	malleableList := malleableCmd.AddCommand(constants.ListStr,
		"List all or some C2 profiles (passed as arguments)",
		help.GetHelpFor(constants.ListStr),
		"management",
		[]string{""},
		func() gonsole.Commander { return &malleable.List{} })
	malleableList.AddArgumentCompletion("ProfileID", completion.MalleableIDs)

	malleableShow := malleableCmd.AddCommand(constants.ShowStr,
		"Show one or more C2 profiles in detailed output",
		help.GetHelpFor(constants.ShowStr),
		"management",
		[]string{""},
		func() gonsole.Commander { return &malleable.Show{} })
	malleableShow.AddArgumentCompletion("ProfileID", completion.MalleableIDs)

	malleableRm := malleableCmd.AddCommand(constants.RmStr,
		"Remove one or more C2 profiles",
		help.GetHelpFor(constants.RmStr),
		"management",
		[]string{""},
		func() gonsole.Commander { return &malleable.Remove{} })
	malleableRm.AddArgumentCompletion("ProfileID", completion.MalleableIDs)

	//
	// MutualTLS ---------------------
	//
	mtlsCmd := cc.AddCommand(constants.MtlsStr,
		"Mutual TLS handlers usage & management",
		help.GetHelpFor(constants.MtlsStr),
		constants.TransportsGroup,
		[]string{"comm"},
		func() gonsole.Commander { return &mtls.MTLS{} })

	mtlsListen := mtlsCmd.AddCommand(constants.ListenStr,
		"Start an mTLS listener on the server, or on a routed session",
		help.GetHelpFor(constants.ListenStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &mtls.Listen{} })
	mtlsListen.AddArgumentCompletion("LocalAddr", completion.ServerInterfaceAddrs)

	mtlsListener := malleableListener.AddCommand(constants.MtlsStr,
		"Create and configure a new MutualTLS Listener profile (reverse from implant)",
		help.GetHelpFor(constants.ListenerStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &mtls.Listener{} })
	mtlsListener.AddArgumentCompletion("LocalAddr", completion.ServerInterfaceAddrs)

	mtlsDial := mtlsCmd.AddCommand(constants.DialStr,
		"Dial an implant listening for incoming MutualTLS connections",
		help.GetHelpFor(constants.DialStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &mtls.Dial{} })
	mtlsDial.AddArgumentCompletion("RemoteAddr", completion.ServerInterfaceAddrs)

	mtlsDialer := malleableDialer.AddCommand(constants.MtlsStr,
		"Create and configure a new MutualTLS Dialer profile (bind to implant)",
		help.GetHelpFor(constants.DialerStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &mtls.Dialer{} })
	mtlsDialer.AddArgumentCompletion("RemoteAddr", completion.ServerInterfaceAddrs)

	//
	// TCP --------------------------
	//
	tcpCmd := cc.AddCommand(constants.TcpStr,
		"TCP handlers usage & management",
		help.GetHelpFor(constants.MtlsStr),
		constants.TransportsGroup,
		[]string{"comm"},
		func() gonsole.Commander { return &tcp.TCP{} })

	tcpListen := tcpCmd.AddCommand(constants.ListenStr,
		"Start an TCP listener on the server, or on a routed session",
		help.GetHelpFor(constants.ListenStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &tcp.Listen{} })
	tcpListen.AddArgumentCompletion("LocalAddr", completion.ServerInterfaceAddrs)

	tcpListener := malleableListener.AddCommand(constants.TcpStr,
		"Create and configure a new TCP Listener profile (reverse from implant)",
		help.GetHelpFor(constants.ListenerStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &tcp.Listener{} })
	tcpListener.AddArgumentCompletion("LocalAddr", completion.ServerInterfaceAddrs)

	tcpDial := tcpCmd.AddCommand(constants.DialStr,
		"Dial an implant listening for incoming TCP connections",
		help.GetHelpFor(constants.DialStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &tcp.Dial{} })
	tcpDial.AddArgumentCompletion("RemoteAddr", completion.ServerInterfaceAddrs)

	tcpDialer := malleableDialer.AddCommand(constants.TcpStr,
		"Create and configure a new TCP Dialer profile (bind to implant)",
		help.GetHelpFor(constants.DialerStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &tcp.Dialer{} })
	tcpDialer.AddArgumentCompletion("RemoteAddr", completion.ServerInterfaceAddrs)

	//
	// Transports --------------------------------------------------------------------------------
	//

	transportCmd := cc.AddCommand(constants.TransportsStr,
		"Session transports management commands (accepts an session ID before the command from server menu)",
		help.GetHelpFor(constants.TransportsStr),
		constants.SessionsGroup,
		[]string{""},
		func() gonsole.Commander { return &transports.Transports{} })
	transportCmd.AddArgumentCompletion("SessionID", completion.SessionIDs)

	transportAdd := transportCmd.AddCommand(constants.AddStr,
		"Load a C2 profile as an available transport to the current session or context",
		help.GetHelpFor(constants.RmStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &transports.Add{} })
	transportAdd.AddArgumentCompletion("ProfileID", completion.MalleableIDs)

	transportRm := transportCmd.AddCommand(constants.RmStr,
		"Remove one or more transports from the current session or context",
		help.GetHelpFor(constants.RmStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &transports.Remove{} })
	transportRm.AddArgumentCompletion("TransportID", completion.TransportsIDs)

	transportList := transportCmd.AddCommand(constants.ListStr,
		"List all or some transports (passed as arguments)",
		help.GetHelpFor(constants.ListStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &transports.List{} })
	transportList.AddArgumentCompletion("TransportID", completion.TransportsIDs)

	transportShow := transportCmd.AddCommand(constants.ShowStr,
		"Show one or more transports in detailed output",
		help.GetHelpFor(constants.ShowStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &transports.Show{} })
	transportShow.AddArgumentCompletion("TransportID", completion.MalleableIDs)

	transportSwitch := transportCmd.AddCommand(constants.SwitchStr,
		"Switch to a given transport for the current session or context one",
		help.GetHelpFor(constants.SwitchStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &transports.Switch{} })
	transportSwitch.AddArgumentCompletion("TransportID", completion.TransportsIDs)

	switch cc.Name {
	// ----------------------------------------------------------------------------------------------
	// All C2 transports that can listen on/ dial from the server.
	// ----------------------------------------------------------------------------------------------
	case constants.ServerMenu:

		//
		// WireGuard ------------------------------
		//
		wgCmd := cc.AddCommand(constants.WGStr,
			"WireGuard VPN handlers management",
			help.GetHelpFor(constants.WGStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &c2.GenericCmd{} })

		wgCmd.AddCommand(constants.ListenStr,
			// wgListen := wg.AddCommand(constants.WGStr,
			"Start a WireGuard listener in the current context",
			help.GetHelpFor(constants.WGStr),
			"",
			[]string{""},
			func() gonsole.Commander { return &wg.Listen{} })

		wgListener := malleableListener.AddCommand(constants.WGStr,
			"Create and configure a WireGuard listener C2 profile",
			help.GetHelpFor(constants.ListenerStr),
			"",
			[]string{""},
			func() gonsole.Commander { return &wg.Listener{} })
		wgListener.AddArgumentCompletion("LocalAddr", completion.ServerInterfaceAddrs)

		wgConfig := wgCmd.AddCommand(constants.ConfigSTR,
			"Generate a new WireGuard client config",
			help.GetHelpFor(constants.WgConfigStr),
			"",
			[]string{""},
			func() gonsole.Commander { return &wg.WireGuardConfig{} })
		wgConfig.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)

		//
		// DNS ------------------------------------
		//
		dnsCmd := cc.AddCommand(constants.DnsStr,
			"DNS handlers usage & management",
			help.GetHelpFor(constants.MtlsStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &dns.DNS{} })

		// dnsListen := dnsCmd.AddCommand(constants.ListenStr,
		dnsCmd.AddCommand(constants.ListenStr,
			"Start a DNS listener on the server",
			help.GetHelpFor(constants.DnsStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &dns.Listen{} })

		//
		// HTTP ------------------------------------
		//
		httpsCmd := cc.AddCommand(constants.HttpsStr,
			"HTTPS handlers usage & management",
			help.GetHelpFor(constants.HttpStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &http.HTTP{} })

		httpsListen := httpsCmd.AddCommand(constants.ListenStr,
			"Start an HTTP(S) listener on the server",
			help.GetHelpFor(constants.ListenStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &https.Listen{} })
		httpsListen.AddArgumentCompletion("LocalAddr", completion.ServerInterfaceAddrs)
		httpsListen.AddOptionCompletion("Domain", completion.ServerInterfaceAddrs)
		httpsListen.AddOptionCompletionDynamic("Certificate", core.Console.Completer.LocalPathAndFiles)
		httpsListen.AddOptionCompletionDynamic("PrivateKey", core.Console.Completer.LocalPathAndFiles)

		httpsListener := malleableListener.AddCommand(constants.HttpsStr,
			"Create a complete HTTPS server C2 profile",
			help.GetHelpFor(constants.HttpsStr),
			"",
			[]string{""},
			func() gonsole.Commander { return &https.Listener{} })
		httpsListener.AddArgumentCompletion("LocalAddr", completion.ServerInterfaceAddrs)
		httpsListener.AddOptionCompletion("Domain", completion.ServerInterfaceAddrs)
		httpsListener.AddOptionCompletionDynamic("Certificate", core.Console.Completer.LocalPathAndFiles)
		httpsListener.AddOptionCompletionDynamic("PrivateKey", core.Console.Completer.LocalPathAndFiles)

		httpsServe := httpsCmd.AddCommand(constants.ServeStr,
			"Serve an implant stage over an HTTPS server",
			help.GetHelpFor(constants.ServeStr),
			"",
			[]string{""},
			func() gonsole.Commander { return &https.Serve{} })
		httpsServe.AddArgumentCompletion("LocalAddr", completion.ServerInterfaceAddrs)
		httpsServe.AddOptionCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)
		httpsServe.AddOptionCompletion("Domain", completion.ServerInterfaceAddrs)
		httpsServe.AddOptionCompletionDynamic("Certificate", core.Console.Completer.LocalPathAndFiles)
		httpsServe.AddOptionCompletionDynamic("PrivateKey", core.Console.Completer.LocalPathAndFiles)

		httpCmd := cc.AddCommand(constants.HttpStr,
			"HTTP handlers usage & management",
			help.GetHelpFor(constants.HttpStr),
			constants.TransportsGroup,
			[]string{""},
			func() gonsole.Commander { return &http.HTTP{} })

		httpListen := httpCmd.AddCommand(constants.ListenStr,
			"Start an HTTP listener on the server (no TLS, but comms encrypted)",
			help.GetHelpFor(constants.HttpStr),
			"",
			[]string{""},
			func() gonsole.Commander { return &http.Listen{} })
		httpListen.AddOptionCompletion("LHost", completion.ServerInterfaceAddrs)

		httpListener := malleableListener.AddCommand(constants.HttpStr,
			"Create a complete HTTP server C2 profile (no TLS, but comms encrypted)",
			help.GetHelpFor(constants.HttpStr),
			"",
			[]string{""},
			func() gonsole.Commander { return &http.Listener{} })
		httpListener.AddArgumentCompletion("LocalAddr", completion.ServerInterfaceAddrs)
		httpListener.AddOptionCompletion("Domain", completion.ServerInterfaceAddrs)

		httpServe := httpCmd.AddCommand(constants.ServeStr,
			"Serve an implant stage over an HTTP server",
			help.GetHelpFor(constants.ServeStr),
			"",
			[]string{""},
			func() gonsole.Commander { return &http.Serve{} })
		httpServe.AddArgumentCompletion("LocalAddr", completion.ServerInterfaceAddrs)
		httpServe.AddOptionCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)

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

		// Websites --------------------------------
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
