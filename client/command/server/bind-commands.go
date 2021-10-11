package server

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
	"fmt"

	"github.com/maxlandon/gonsole"

	"github.com/bishopfox/sliver/client/completion"
	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/help"
	"github.com/bishopfox/sliver/client/util"

	// Commands implementations
	"github.com/bishopfox/sliver/client/command/c2/pivots"
	"github.com/bishopfox/sliver/client/command/server/beacons"
	"github.com/bishopfox/sliver/client/command/server/canaries"
	ccore "github.com/bishopfox/sliver/client/command/server/core"
	"github.com/bishopfox/sliver/client/command/server/generate"
	"github.com/bishopfox/sliver/client/command/server/hosts"
	"github.com/bishopfox/sliver/client/command/server/jobs"
	"github.com/bishopfox/sliver/client/command/server/log"
	"github.com/bishopfox/sliver/client/command/server/loot"
	"github.com/bishopfox/sliver/client/command/server/monitor"
	"github.com/bishopfox/sliver/client/command/server/operators"
	"github.com/bishopfox/sliver/client/command/server/prelude"
	"github.com/bishopfox/sliver/client/command/server/profiles"
	"github.com/bishopfox/sliver/client/command/server/reaction"
	"github.com/bishopfox/sliver/client/command/server/sessions"
	"github.com/bishopfox/sliver/client/command/server/update"
	"github.com/bishopfox/sliver/client/command/server/use"
	"github.com/bishopfox/sliver/client/command/sliver/generic/info"
	"github.com/bishopfox/sliver/client/command/sliver/generic/portfwd"
)

// BindCommands - All commands bound in this function are NOT speaking with implants sessions,
// but can still be used when the user is interacting with Slivers. A precise context is passed so
// that we can selectively bind these commands to contexts from outside.
func BindCommands(cc *gonsole.Menu) {

	// Default (local) Shell Exec ---------------------------------------------------------------

	// Unknown commands, in the server context, are automatically passed to the system.
	core.Console.GetMenu(constants.ServerMenu).UnknownCommandHandler = util.Shell

	// Core Commands ----------------------------------------------------------------------------
	cc.AddCommand("exit", // Command name
		"Exit from the client/server console", // Short description (completions & hints)
		"",                                    // Long description
		constants.CoreServerGroup,             // The group of the command (completions, menu structuring)
		[]string{""},                          // A filter by which to hide/show the command.
		func() gonsole.Commander { return &ccore.Exit{} }) // The command generator, yielding instances.

	cc.AddCommand(constants.VersionStr,
		"Display version information",
		help.GetHelpFor(constants.VersionStr),
		constants.CoreServerGroup,
		[]string{""},
		func() gonsole.Commander { return &update.Version{} })

	// Cd has a context-sensitive name.
	var cdCmdStr string
	switch cc.Name {
	case constants.ServerMenu:
		cdCmdStr = constants.CdStr
	case constants.SliverMenu:
		cdCmdStr = constants.LcdStr
	}

	cd := cc.AddCommand(cdCmdStr,
		"Change the client working directory",
		"",
		constants.CoreServerGroup,
		[]string{""},
		func() gonsole.Commander { return &ccore.ChangeClientDirectory{} })
	cd.AddArgumentCompletionDynamic("Path", core.Console.Completer.LocalPath)

	cc.AddCommand(constants.LicensesStr,
		"Display project licenses (core & libraries)",
		"",
		constants.CoreServerGroup,
		[]string{""},
		func() gonsole.Commander { return &update.Licenses{} })

	updates := cc.AddCommand(constants.UpdateStr,
		"Check for newer Sliver console/server releases",
		help.GetHelpFor(constants.UpdateStr),
		constants.CoreServerGroup,
		[]string{""},
		func() gonsole.Commander { return &update.Updates{} })
	updates.AddOptionCompletionDynamic("Proxy", completion.NewURLCompleterProxyUpdate().CompleteURL) // Option completions
	updates.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)

	cc.AddCommand(constants.OperatorsStr,
		"List operators and their status",
		help.GetHelpFor(constants.OperatorsStr),
		constants.CoreServerGroup,
		[]string{""},
		func() gonsole.Commander { return &operators.Operators{} })

	// Log management ---------------------------------------------------------------------------
	log := cc.AddCommand(constants.LogStr,
		"Manage log levels of one or more components",
		"",
		constants.CoreServerGroup,
		[]string{""},
		func() gonsole.Commander { return &log.Log{} })
	log.AddArgumentCompletion("Level", completion.LogLevels)
	log.AddArgumentCompletion("Components", completion.Loggers)

	// Prelude Operator -----------------------------------------------------------------------------
	prelud := cc.AddCommand(constants.PreludeOperatorStr,
		"Prelude's Operator management (displays status by default)",
		help.GetHelpFor(constants.MonitorStr),
		constants.CoreServerGroup,
		[]string{""},
		func() gonsole.Commander { return &prelude.Operator{} })
	prelud.SubcommandsOptional = true

	prelConn := prelud.AddCommand(constants.ConnectStr,
		"Connect to a Prelude's Operator instance",
		help.GetHelpFor(constants.ConnectStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &prelude.Connect{} })
	prelConn.AddArgumentCompletionDynamic("URL", completion.NewURLCompleterProxyUpdate().CompleteURL) // Option completions

	// Jobs management --------------------------------------------------------------------------
	j := cc.AddCommand(constants.JobsStr,
		"Job management commands",
		help.GetHelpFor(constants.JobsStr),
		constants.CoreServerGroup,
		[]string{""},
		func() gonsole.Commander { return &jobs.Jobs{} })

	j.SubcommandsOptional = true

	kill := j.AddCommand(constants.JobsKillStr,
		"Kill one or more jobs given their ID",
		"", "", []string{""},
		func() gonsole.Commander { return &jobs.JobsKill{} })
	kill.AddArgumentCompletion("JobID", completion.JobIDs)

	j.AddCommand(constants.JobsKillAllStr,
		"Kill all active jobs on server",
		"", "", []string{""},
		func() gonsole.Commander { return &jobs.JobsKillAll{} })

	// Session Management ----------------------------------------------------------------------------
	interact := cc.AddCommand(constants.UseStr,
		"Interact with a session/beacon",
		help.GetHelpFor(constants.UseStr),
		constants.SessionsGroup,
		[]string{""},
		func() gonsole.Commander { return &use.Use{} })
	interact.AddArgumentCompletion("ID", completion.SessionAndBeaconIDs)

	s := cc.AddCommand(constants.SessionsStr,
		"Session management (all contexts)",
		help.GetHelpFor(constants.SessionsStr),
		constants.SessionsGroup,
		[]string{""},
		func() gonsole.Commander { return &sessions.Sessions{} })

	s.SubcommandsOptional = true

	sinteract := s.AddCommand("interact",
		"Interact with an implant",
		help.GetHelpFor(constants.UseStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &sessions.Interact{} })
	sinteract.AddArgumentCompletion("SessionID", completion.SessionIDs)

	sessionKill := s.AddCommand(constants.KillStr,
		"Kill one or more implant sessions",
		"", "", []string{""},
		func() gonsole.Commander { return &sessions.SessionsKill{} })
	sessionKill.AddArgumentCompletion("SessionID", completion.SessionIDs)

	s.AddCommand(constants.JobsKillAllStr,
		"Kill all registered sessions",
		"", "", []string{""},
		func() gonsole.Commander { return &sessions.SessionsKillAll{} })

	s.AddCommand(constants.PruneStr,
		"Clean sessions marked Dead",
		"", "", []string{""},
		func() gonsole.Commander { return &sessions.SessionsClean{} })

	pivots := cc.AddCommand(constants.PivotsListStr,
		"Pivots management command, prints them by default",
		help.GetHelpFor(constants.PivotsListStr),
		constants.SessionsGroup,
		[]string{""},
		func() gonsole.Commander { return &pivots.Pivots{} })
	pivots.AddOptionCompletion("SessionID", completion.SessionIDs)

	// Beacon Management ----------------------------------------------------------------------------
	beac := cc.AddCommand(constants.BeaconsStr,
		"Beacon management (all contexts)",
		help.GetHelpFor(constants.BeaconsStr),
		constants.SessionsGroup,
		[]string{""},
		func() gonsole.Commander { return &beacons.Beacons{} })

	beac.SubcommandsOptional = true

	beacRm := beac.AddCommand(constants.RmStr,
		"Remove one or more implant beacons",
		"", "", []string{""},
		func() gonsole.Commander { return &beacons.BeaconsRm{} })
	beacRm.AddArgumentCompletion("BeaconID", completion.BeaconIDs)

	// Reactions ------------------------------------------------------------------------------------

	reacts := cc.AddCommand(constants.ReactionStr,
		"Automatic event reactions management",
		help.GetHelpFor(constants.ReactionStr),
		constants.SessionsGroup,
		[]string{""},
		func() gonsole.Commander { return &reaction.Reaction{} })
	reacts.AddOptionCompletion("Types", completion.ReactableEventTypes)
	reacts.SubcommandsOptional = true

	set := reacts.AddCommand(constants.SetStr,
		"Set a reaction to an event",
		help.GetHelpFor(constants.SetStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &reaction.Set{} })
	set.AddArgumentCompletion("Event", completion.ReactableEventTypes)

	unset := reacts.AddCommand(constants.UnsetStr,
		"Unset one or more reactions to an event",
		help.GetHelpFor(constants.UnsetStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &reaction.Unset{} })
	unset.AddArgumentCompletion("ReactionID", completion.ReactionIDs)

	reacts.AddCommand(constants.ReloadStr,
		"Reload reactions from disk, replaces the current configuration",
		help.GetHelpFor(constants.ReloadStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &reaction.Reload{} })

	reacts.AddCommand(constants.SaveStr,
		"Save current reactions to disk",
		help.GetHelpFor(constants.SaveStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &reaction.Save{} })

	// Hosts & IOCs Management ----------------------------------------------------------------------
	hst := cc.AddCommand(constants.HostsStr,
		"Manage the database of hosts",
		help.GetHelpFor(constants.HostsStr),
		constants.DataGroup,
		[]string{""},
		func() gonsole.Commander { return &hosts.Hosts{} })

	hst.SubcommandsOptional = true

	hstRm := hst.AddCommand(constants.RmStr,
		"Remove one or more hosts from the database",
		help.GetHelpFor(constants.RmStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &hosts.RmHost{} })
	hstRm.AddArgumentCompletion("HostID", completion.HostUUIDs)

	iocs := cc.AddCommand(constants.IOCStr,
		"Manage the list of IOCs for hosts",
		help.GetHelpFor(constants.IOCStr),
		constants.ThreatMonGroup,
		[]string{""},
		func() gonsole.Commander { return &hosts.IOCs{} })

	iocs.SubcommandsOptional = true

	iocsRm := iocs.AddCommand(constants.RmStr,
		"Remove one or more IOCs from the database",
		help.GetHelpFor(constants.RmStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &hosts.RemoveIOCs{} })
	iocsRm.AddArgumentCompletion("IOC", completion.HostIOCs)

	// Loot management -----------------------------------------------------------------------------------
	lootCmd := cc.AddCommand(constants.LootStr,
		"Manage the server's loot store",
		help.GetHelpFor(constants.LootStr),
		constants.DataGroup,
		[]string{""},
		func() gonsole.Commander { return &loot.Loot{} })

	lootCmd.AddCommand(constants.ListStr,
		// lootList := lootCmd.AddCommand(constants.ListStr,
		"Display the server's loot store with various filters & displays (args &|| filters)",
		help.GetHelpFor(constants.LootStr),
		"management",
		[]string{""},
		func() gonsole.Commander { return &loot.List{} })

	lootRm := lootCmd.AddCommand(constants.RmStr,
		"Remove one or more pieces of loot from the server's loot store",
		help.GetHelpFor(constants.LootStr),
		"management",
		[]string{""},
		func() gonsole.Commander { return &loot.Rm{} })
	lootRm.AddArgumentCompletion("LootID", completion.LootIDs)

	lootRename := lootCmd.AddCommand(constants.RenameStr,
		"Rename a piece of existing loot",
		help.GetHelpFor(constants.LootStr),
		"management",
		[]string{""},
		func() gonsole.Commander { return &loot.Rename{} })
	lootRename.AddArgumentCompletion("LootID", completion.LootIDs)

	lootFetch := lootCmd.AddCommand(constants.LootFetchStr,
		"Fetch a piece of loot from the server's loot store",
		help.GetHelpFor(constants.LootFetchStr),
		"management",
		[]string{""},
		func() gonsole.Commander { return &loot.Fetch{} })
	lootFetch.AddArgumentCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)
	lootFetch.AddArgumentCompletion("LootID", completion.LootIDs)

	lootLocal := lootCmd.AddCommand(constants.LootLocalStr,
		"Add a local file to the server's loot store",
		help.GetHelpFor(constants.LootFetchStr),
		"management",
		[]string{""},
		func() gonsole.Commander { return &loot.Local{} })
	lootLocal.AddArgumentCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)

	lootRemote := lootCmd.AddCommand(constants.LootRemoteStr,
		"Add a remote file from the current session to the server's loot store",
		help.GetHelpFor(constants.LootFetchStr),
		"management",
		[]string{"loot"}, // This command will be hidden from us when we don't interact with a session.
		func() gonsole.Commander { return &loot.Remote{} })
	lootRemote.AddArgumentCompletionDynamic("RemotePath", completion.CompleteRemotePathAndFiles)

	lootCmd.AddCommand(constants.AddStr,
		"Add credentials to the server's loot store",
		help.GetHelpFor(constants.LootStr),
		"credentials",
		[]string{""},
		func() gonsole.Commander { return &loot.AddCredentials{} })

	// Stage / Stager Generation -------------------------------------------------------------------------
	g := cc.AddCommand(constants.GenerateStr,
		"Configure and compile an implant (staged or stager)",
		"",
		constants.BuildsGroup,
		[]string{""},
		func() gonsole.Commander { return &generate.Generate{} })

	gb := g.AddCommand("beacon",
		"Configure and compile a Sliver (beacon) stage implant",
		help.GetHelpFor(constants.GenerateStr),
		"", []string{""},
		func() gonsole.Commander { return &generate.GenerateBeacon{} })
	gb.AddOptionCompletion("Platform", completion.CompleteStagePlatforms)
	gb.AddOptionCompletion("Format", completion.CompleteStageFormats)
	gb.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)
	gb.AddOptionCompletion("MTLS", completion.ServerInterfaceAddrs)
	gb.AddOptionCompletion("HTTP", completion.ServerInterfaceAddrs)
	gb.AddOptionCompletion("DNS", completion.ServerInterfaceAddrs)
	gb.AddOptionCompletion("TCPPivot", completion.ActiveSessionIfaceAddrs)
	gb.AddOptionCompletion("Malleables", completion.MalleableIDs)

	st := g.AddCommand("stage",
		"Configure and compile a Sliver (stage) implant",
		help.GetHelpFor(constants.GenerateStr),
		"", []string{""},
		func() gonsole.Commander { return &generate.GenerateStage{} })
	st.AddOptionCompletion("Platform", completion.CompleteStagePlatforms)
	st.AddOptionCompletion("Format", completion.CompleteStageFormats)
	st.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)
	st.AddOptionCompletion("MTLS", completion.ServerInterfaceAddrs)
	st.AddOptionCompletion("HTTP", completion.ServerInterfaceAddrs)
	st.AddOptionCompletion("DNS", completion.ServerInterfaceAddrs)
	st.AddOptionCompletion("TCPPivot", completion.ActiveSessionIfaceAddrs)
	st.AddOptionCompletion("Malleables", completion.MalleableIDs)

	sg := g.AddCommand(constants.StagerStr,
		"Generate a stager shellcode payload using MSFVenom, (to file: --save, to stdout: --format",
		help.GetHelpFor(constants.StagerStr),
		"", []string{""},
		func() gonsole.Commander { return &generate.GenerateStager{} })
	sg.AddOptionCompletion("Arch", completion.CompleteMsfArchs)
	sg.AddOptionCompletion("Format", completion.CompleteMsfFormats)
	sg.AddOptionCompletion("Protocol", completion.CompleteMsfProtocols)
	sg.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)
	sg.AddOptionCompletion("LHost", completion.ServerInterfaceAddrs)

	g.AddCommand(constants.InfoStr,
		"Display information on the Sliver server's compiler configuration",
		"",
		"", []string{""},
		func() gonsole.Commander { return &generate.GenerateInfo{} })

	// Builds Management / Generation ------------------------------------------------------------------
	builds := cc.AddCommand(constants.ImplantBuildsStr,
		"List old implant builds",
		help.GetHelpFor(constants.ImplantBuildsStr),
		constants.BuildsGroup,
		[]string{""},
		func() gonsole.Commander { return &generate.Builds{} })

	builds.SubcommandsOptional = true
	buildsRm := builds.AddCommand(constants.RmStr,
		"Remove one or more implant builds from the server database",
		help.GetHelpFor(fmt.Sprintf("%s.%s", constants.ImplantBuildsStr, constants.RmStr)),
		"",
		[]string{""},
		func() gonsole.Commander { return &generate.RemoveBuild{} })
	buildsRm.AddArgumentCompletion("Names", completion.ImplantNames)

	regenerate := builds.AddCommand(constants.RegenerateStr,
		"Recompile an implant by name, passed as argument (completed)",
		help.GetHelpFor(constants.RegenerateStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &generate.Regenerate{} })
	regenerate.AddArgumentCompletion("ImplantName", completion.ImplantNames)
	regenerate.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)

	// Profiles Management / Generation ----------------------------------------------------------------
	p := cc.AddCommand(constants.ProfilesStr,
		"Implant profiles management commands",
		help.GetHelpFor(constants.ProfilesStr),
		constants.BuildsGroup,
		[]string{""},
		func() gonsole.Commander { return &profiles.Profiles{} })
	p.SubcommandsOptional = true

	pn := p.AddCommand(constants.NewStr,
		"Configure and save a new (stage) implant profile",
		help.GetHelpFor(constants.ProfilesStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &profiles.NewProfile{} })
	pn.AddOptionCompletion("Platform", completion.CompleteStagePlatforms)
	pn.AddOptionCompletion("Format", completion.CompleteStageFormats)
	pn.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)
	pn.AddOptionCompletion("MTLS", completion.ServerInterfaceAddrs)
	pn.AddOptionCompletion("HTTP", completion.ServerInterfaceAddrs)
	pn.AddOptionCompletion("DNS", completion.ServerInterfaceAddrs)
	pn.AddOptionCompletion("TCPPivot", completion.ActiveSessionIfaceAddrs)

	profileDelete := p.AddCommand(constants.RmStr,
		"Delete one or more existing implant profiles",
		"",
		"",
		[]string{""},
		func() gonsole.Commander { return &profiles.ProfileDelete{} })
	profileDelete.AddArgumentCompletion("Profile", completion.ImplantProfiles)

	pg := p.AddCommand(constants.GenerateStr,
		"Compile an implant based on a profile, passed as argument (completed)",
		help.GetHelpFor(constants.GenerateStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &profiles.ProfileGenerate{} })
	pg.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)

	// Threat Monitoring -----------------------------------------------------------------------------
	cc.AddCommand(constants.CanariesStr,
		"List previously generated DNS canaries",
		help.GetHelpFor(constants.CanariesStr),
		constants.ThreatMonGroup,
		[]string{""},
		func() gonsole.Commander { return &canaries.Canaries{} })

	mon := cc.AddCommand(constants.MonitorStr,
		"Threat monitoring management",
		help.GetHelpFor(constants.MonitorStr),
		constants.ThreatMonGroup,
		[]string{""},
		func() gonsole.Commander { return &monitor.Monitor{} })

	mon.AddCommand(constants.StartStr,
		"Start monitoring threat intel for implants",
		help.GetHelpFor(constants.StartStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &monitor.Start{} })

	mon.AddCommand(constants.StopStr,
		"Stop monitoring loops for threat intel",
		help.GetHelpFor(constants.StartStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &monitor.Stop{} })

	// Context-sensitive commands / alias -----------------------------------------------------------
	switch cc.Name {
	case constants.ServerMenu:
		// The info command is a session management one
		// in server context, but a core one in session context.
		info := cc.AddCommand(constants.InfoStr,
			"Show session information",
			"",
			constants.SessionsGroup,
			[]string{""},
			func() gonsole.Commander { return &info.SessionInfo{} })
		info.AddArgumentCompletion("SessionID", completion.SessionIDs)

		//  Network Tools ----------------------------------------------------------------------

		// The root portfwd command is accessible in both menus: in the server, you can only print
		// forwarders, so no subcommands will be attached. When there is an active session, the commands
		// to add/remove a forwarder will become available.
		cc.AddCommand(constants.PortfwdStr,
			"In-band TCP port forwarders management",
			help.GetHelpFor(constants.PortfwdStr),
			constants.NetworkToolsGroup,
			[]string{""},
			func() gonsole.Commander { return &portfwd.Portfwd{} })
	}

}
