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
	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/command/server/canaries"
	ccore "github.com/bishopfox/sliver/client/command/server/core"
	"github.com/bishopfox/sliver/client/command/server/generate"
	"github.com/bishopfox/sliver/client/command/server/jobs"
	"github.com/bishopfox/sliver/client/command/server/log"
	"github.com/bishopfox/sliver/client/command/server/operators"
	"github.com/bishopfox/sliver/client/command/server/sessions"
	"github.com/bishopfox/sliver/client/command/server/update"
	"github.com/bishopfox/sliver/client/command/sliver"
)

var (
	// Most commands just need access to a precise context.
	serverMenu *gonsole.Menu
)

// BindCommands - All commands bound in this function are NOT speaking with implants sessions,
// but can still be used when the user is interacting with Slivers. A precise context is passed so
// that we can selectively bind these commands to contexts from outside.
func BindCommands(cc *gonsole.Menu) {

	// Keep a reference to this context, command implementations might want to use it.
	serverMenu = cc

	// Default (local) Shell Exec ---------------------------------------------------------------

	// Unknown commands, in the server context, are automatically passed to the system.
	serverMenu.UnknownCommandHandler = util.Shell

	// Core Commands ----------------------------------------------------------------------------
	cc.AddCommand("exit", // Command name
		"Exit from the client/server console", // Short description (completions & hints)
		"",                                    // Long description
		constants.CoreServerGroup,             // The group of the command (completions, menu structuring)
		[]string{""},                          // A filter by which to hide/show the command.
		func() interface{} { return &ccore.Exit{} }) // The command generator, yielding instances.

	cc.AddCommand(constants.VersionStr,
		"Display version information",
		help.GetHelpFor(constants.VersionStr),
		constants.CoreServerGroup,
		[]string{""},
		func() interface{} { return &update.Version{} })

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
		func() interface{} { return &ccore.ChangeClientDirectory{} })
	cd.AddArgumentCompletionDynamic("Path", core.Console.Completer.LocalPath)

	cc.AddCommand(constants.LicensesStr,
		"Display project licenses (core & libraries)",
		"",
		constants.CoreServerGroup,
		[]string{""},
		func() interface{} { return &update.Licenses{} })

	updates := cc.AddCommand(constants.UpdateStr,
		"Check for newer Sliver console/server releases",
		help.GetHelpFor(constants.UpdateStr),
		constants.CoreServerGroup,
		[]string{""},
		func() interface{} { return &update.Updates{} })
	updates.AddOptionCompletionDynamic("Proxy", completion.NewURLCompleterProxyUpdate().CompleteURL) // Option completions
	updates.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)

	cc.AddCommand(constants.OperatorsStr,
		"List operators and their status",
		help.GetHelpFor(constants.OperatorsStr),
		constants.CoreServerGroup,
		[]string{""},
		func() interface{} { return &operators.Operators{} })

	// Log management ---------------------------------------------------------------------------
	log := cc.AddCommand(constants.LogStr,
		"Manage log levels of one or more components",
		"",
		constants.CoreServerGroup,
		[]string{""},
		func() interface{} { return &log.Log{} })
	log.AddArgumentCompletion("Level", completion.LogLevels)
	log.AddArgumentCompletion("Components", completion.Loggers)

	// Jobs management --------------------------------------------------------------------------
	j := cc.AddCommand(constants.JobsStr,
		"Job management commands",
		help.GetHelpFor(constants.JobsStr),
		constants.CoreServerGroup,
		[]string{""},
		func() interface{} { return &jobs.Jobs{} })

	j.SubcommandsOptional = true

	kill := j.AddCommand(constants.JobsKillStr,
		"Kill one or more jobs given their ID",
		"", "", []string{""},
		func() interface{} { return &jobs.JobsKill{} })
	kill.AddArgumentCompletion("JobID", completion.JobIDs)

	j.AddCommand(constants.JobsKillAllStr,
		"Kill all active jobs on server",
		"", "", []string{""},
		func() interface{} { return &jobs.JobsKillAll{} })

	// Session Management ----------------------------------------------------------------------------
	interact := cc.AddCommand(constants.UseStr,
		"Interact with an implant",
		help.GetHelpFor(constants.UseStr),
		constants.SessionsGroup,
		[]string{""},
		func() interface{} { return &sessions.Interact{} })
	interact.AddArgumentCompletion("SessionID", completion.SessionIDs)

	s := cc.AddCommand(constants.SessionsStr,
		"Session management (all contexts)",
		help.GetHelpFor(constants.SessionsStr),
		constants.SessionsGroup,
		[]string{""},
		func() interface{} { return &sessions.Sessions{} })

	s.SubcommandsOptional = true

	sinteract := s.AddCommand("interact",
		"Interact with an implant",
		help.GetHelpFor(constants.UseStr),
		"",
		[]string{""},
		func() interface{} { return &sessions.Interact{} })
	sinteract.AddArgumentCompletion("SessionID", completion.SessionIDs)

	sessionKill := s.AddCommand(constants.KillStr,
		"Kill one or more implant sessions",
		"", "", []string{""},
		func() interface{} { return &sessions.SessionsKill{} })
	sessionKill.AddArgumentCompletion("SessionID", completion.SessionIDs)

	s.AddCommand(constants.JobsKillAllStr,
		"Kill all registered sessions",
		"", "", []string{""},
		func() interface{} { return &sessions.SessionsKillAll{} })

	s.AddCommand(constants.PruneStr,
		"Clean sessions marked Dead",
		"", "", []string{""},
		func() interface{} { return &sessions.SessionsClean{} })

	pivots := cc.AddCommand(constants.PivotsListStr,
		"Pivots management command, prints them by default",
		help.GetHelpFor(constants.PivotsListStr),
		"",
		[]string{""},
		func() interface{} { return &c2.Pivots{} })
	pivots.AddOptionCompletion("SessionID", completion.SessionIDs)

	// Stage / Stager Generation -------------------------------------------------------------------------
	g := cc.AddCommand(constants.GenerateStr,
		"Configure and compile an implant (staged or stager)",
		"",
		constants.BuildsGroup,
		[]string{""},
		func() interface{} { return &generate.Generate{} })

	st := g.AddCommand("stage",
		"Configure and compile a Sliver (stage) implant",
		help.GetHelpFor(constants.GenerateStr),
		"", []string{""},
		func() interface{} { return &generate.GenerateStage{} })
	st.AddOptionCompletion("Platform", completion.CompleteStagePlatforms)
	st.AddOptionCompletion("Format", completion.CompleteStageFormats)
	st.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)
	st.AddOptionCompletion("MTLS", completion.ServerInterfaceAddrs)
	st.AddOptionCompletion("HTTP", completion.ServerInterfaceAddrs)
	st.AddOptionCompletion("DNS", completion.ServerInterfaceAddrs)
	st.AddOptionCompletion("TCPPivot", completion.ActiveSessionIfaceAddrs)

	sg := g.AddCommand(constants.StagerStr,
		"Generate a stager shellcode payload using MSFVenom, (to file: --save, to stdout: --format",
		help.GetHelpFor(constants.StagerStr),
		"", []string{""},
		func() interface{} { return &generate.GenerateStager{} })
	sg.AddOptionCompletion("Format", completion.CompleteMsfFormats)
	sg.AddOptionCompletion("Protocol", completion.CompleteMsfProtocols)
	sg.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)

	// Profiles Management / Generation ----------------------------------------------------------------
	p := cc.AddCommand(constants.ProfilesStr,
		"Implant profiles management commands",
		help.GetHelpFor(constants.ProfilesStr),
		constants.BuildsGroup,
		[]string{""},
		func() interface{} { return &generate.ProfilesCmd{} })

	pn := p.AddCommand(constants.NewStr,
		"Configure and save a new (stage) implant profile",
		help.GetHelpFor(constants.ProfilesStr),
		constants.BuildsGroup,
		[]string{""},
		func() interface{} { return &generate.NewProfile{} })
	pn.AddOptionCompletion("Platform", completion.CompleteStagePlatforms)
	pn.AddOptionCompletion("Format", completion.CompleteStageFormats)

	pr := p.AddCommand("list",
		"List existing implant profiles",
		help.GetHelpFor(constants.ProfilesStr),
		constants.BuildsGroup,
		[]string{""},
		func() interface{} { return &generate.Profiles{} })
	pr.SubcommandsOptional = true

	profileDelete := p.AddCommand(constants.RmStr,
		"Delete one or more existing implant profiles",
		"", "", []string{""},
		func() interface{} { return &generate.ProfileDelete{} })
	profileDelete.AddArgumentCompletion("Profile", completion.ImplantProfiles)

	p.AddCommand(constants.GenerateStr,
		"Compile an implant based on a profile, passed as argument (completed)",
		help.GetHelpFor(constants.GenerateStr),
		constants.BuildsGroup,
		[]string{""},
		func() interface{} { return &generate.ProfileGenerate{} })

	builds := cc.AddCommand(constants.ImplantBuildsStr,
		"List old implant builds",
		help.GetHelpFor(constants.ImplantBuildsStr),
		constants.BuildsGroup,
		[]string{""},
		func() interface{} { return &generate.Builds{} })

	regenerate := cc.AddCommand(constants.RegenerateStr,
		"Recompile an implant by name, passed as argument (completed)",
		help.GetHelpFor(constants.RegenerateStr),
		constants.BuildsGroup,
		[]string{""},
		func() interface{} { return &generate.Regenerate{} })
	regenerate.AddArgumentCompletion("ImplantName", completion.ImplantNames)

	builds.SubcommandsOptional = true
	buildsRm := builds.AddCommand(constants.RmStr,
		"Remove one or more implant builds from the server database",
		help.GetHelpFor(fmt.Sprintf("%s.%s", constants.ImplantBuildsStr, constants.RmStr)),
		"",
		[]string{""},
		func() interface{} { return &generate.RemoveBuild{} })
	buildsRm.AddArgumentCompletion("Names", completion.ImplantNames)

	cc.AddCommand(constants.CanariesStr,
		"List previously generated DNS canaries",
		help.GetHelpFor(constants.CanariesStr),
		constants.BuildsGroup,
		[]string{""},
		func() interface{} { return &canaries.Canaries{} })

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
			func() interface{} { return &sliver.SessionInfo{} })
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
			func() interface{} { return &sliver.Portfwd{} })
	}

}
