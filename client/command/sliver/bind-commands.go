package sliver

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

	// Command implementations

	"github.com/bishopfox/sliver/client/command/sliver/generic/dllhijack"
	"github.com/bishopfox/sliver/client/command/sliver/generic/env"
	"github.com/bishopfox/sliver/client/command/sliver/generic/execute"
	"github.com/bishopfox/sliver/client/command/sliver/generic/extensions"
	"github.com/bishopfox/sliver/client/command/sliver/generic/filesystem"
	"github.com/bishopfox/sliver/client/command/sliver/generic/info"
	"github.com/bishopfox/sliver/client/command/sliver/generic/network"
	"github.com/bishopfox/sliver/client/command/sliver/generic/portfwd"
	"github.com/bishopfox/sliver/client/command/sliver/generic/proc"
	"github.com/bishopfox/sliver/client/command/sliver/generic/screenshot"
	"github.com/bishopfox/sliver/client/command/sliver/generic/sessions"
	"github.com/bishopfox/sliver/client/command/sliver/generic/shell"
	"github.com/bishopfox/sliver/client/command/sliver/generic/wireguard"

	windowsCmds "github.com/bishopfox/sliver/client/command/sliver/windows"
)

// BindCommands - Register all commands available only when interacting with a Sliver session.
// This function will also, at the end, register Windows commands, in the same context but with
// filters so that only Windows-based hosts will have these Windows commands available.
func BindCommands(cc *gonsole.Menu) {

	// Core Commands --------------------------------------------------------------------
	cc.AddCommand(constants.BackgroundStr,
		"Background the current session",
		help.GetHelpFor(constants.BackgroundStr),
		constants.CoreSessionGroup,
		[]string{""},
		func() gonsole.Commander { return &sessions.Background{} })

	cc.AddCommand(constants.KillStr,
		"Kill the current session",
		help.GetHelpFor(constants.KillStr),
		constants.CoreSessionGroup,
		[]string{""},
		func() gonsole.Commander { return &sessions.Kill{} })

	cc.AddCommand(constants.SetStr,
		"Set a value for the current session", "",
		constants.CoreSessionGroup,
		[]string{""},
		func() gonsole.Commander { return &sessions.Set{} })

	cc.AddCommand(constants.PingStr,
		"Send round trip message to implant (does not use ICMP)", "",
		constants.CoreSessionGroup,
		[]string{""},
		func() gonsole.Commander { return &sessions.Ping{} })

	shell := cc.AddCommand(constants.ShellStr,
		"Start an interactive shell on the session host (not opsec!)", "",
		constants.CoreSessionGroup,
		[]string{""},
		func() gonsole.Commander { return &shell.Shell{} })
	shell.AddOptionCompletionDynamic("Path", completion.CompleteRemotePathAndFiles)

	// Env Commands --------------------------------------------------------------------
	envr := cc.AddCommand(constants.EnvStr,
		"Manage target environment variables", "",
		constants.CoreSessionGroup,
		[]string{""},
		func() gonsole.Commander { return &env.EnvCmd{} })

	envr.AddCommand("get",
		"Get one or more host environment variables", "",
		constants.CoreSessionGroup,
		[]string{""},
		func() gonsole.Commander { return &env.GetEnv{} })

	envr.AddCommand("set",
		"Set an environment variable", "",
		constants.CoreSessionGroup,
		[]string{""},
		func() gonsole.Commander { return &env.SetEnv{} })

	// Info ----------------------------------------------------------------------------
	cc.AddCommand(constants.InfoStr,
		"Show session information", "",
		constants.InfoGroup,
		[]string{""},
		func() gonsole.Commander { return &info.SessionInfo{} })

	cc.AddCommand(constants.GetUIDStr,
		"Get session User ID", "",
		constants.InfoGroup,
		[]string{""},
		func() gonsole.Commander { return &info.UID{} })

	cc.AddCommand(constants.GetGIDStr,
		"Get session User group ID", "",
		constants.InfoGroup,
		[]string{""},
		func() gonsole.Commander { return &info.GID{} })

	cc.AddCommand(constants.GetPIDStr,
		"Get session Process ID", "",
		constants.InfoGroup,
		[]string{""},
		func() gonsole.Commander { return &info.PID{} })

	cc.AddCommand(constants.WhoamiStr,
		"Get session username", "",
		constants.InfoGroup,
		[]string{""},
		func() gonsole.Commander { return &info.Whoami{} })

	cc.AddCommand(constants.ScreenshotStr,
		"Take a screenshot", "",
		constants.InfoGroup,
		[]string{""},
		func() gonsole.Commander { return &screenshot.Screenshot{} })

	cc.AddCommand(constants.IfconfigStr,
		"Show session network interfaces", "",
		constants.InfoGroup,
		[]string{""},
		func() gonsole.Commander { return &network.Ifconfig{} })

	cc.AddCommand(constants.NetstatStr,
		"Print network connection information", "",
		constants.InfoGroup,
		[]string{""},
		func() gonsole.Commander { return &network.Netstat{} })

	// Filesystem ----------------------------------------------------------------------
	cd := cc.AddCommand(constants.CdStr,
		"Change session working directory", "",
		constants.FilesystemGroup,
		[]string{""},
		func() gonsole.Commander { return &filesystem.ChangeDirectory{} })
	cd.AddArgumentCompletionDynamic("Path", completion.CompleteRemotePath)

	ls := cc.AddCommand(constants.LsStr,
		"List session directory contents", "",
		constants.FilesystemGroup,
		[]string{""},
		func() gonsole.Commander { return &filesystem.ListDirectories{} })
	ls.AddArgumentCompletionDynamic("Path", completion.CompleteRemotePathAndFiles)

	rm := cc.AddCommand(constants.RmStr,
		"Remove directory/file contents from the session's host", "",
		constants.FilesystemGroup,
		[]string{""},
		func() gonsole.Commander { return &filesystem.Rm{} })
	rm.AddArgumentCompletionDynamic("Path", completion.CompleteRemotePathAndFiles)

	mkdir := cc.AddCommand(constants.MkdirStr,
		"Create one or more directories on the implant's host", "",
		constants.FilesystemGroup,
		[]string{""},
		func() gonsole.Commander { return &filesystem.Mkdir{} })
	mkdir.AddArgumentCompletionDynamic("Path", completion.CompleteRemotePath)

	cc.AddCommand(constants.PwdStr,
		"Print the session current working directory", "",
		constants.FilesystemGroup,
		[]string{""},
		func() gonsole.Commander { return &filesystem.Pwd{} })

	cat := cc.AddCommand(constants.CatStr,
		"Print one or more files to screen", "",
		constants.FilesystemGroup,
		[]string{""},
		func() gonsole.Commander { return &filesystem.Cat{} })
	cat.AddArgumentCompletionDynamic("Path", completion.CompleteRemotePathAndFiles)

	download := cc.AddCommand(constants.DownloadStr,
		"Download one or more files from the target to the client", "",
		constants.FilesystemGroup,
		[]string{""},
		func() gonsole.Commander { return &filesystem.Download{} })
	download.AddArgumentCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)
	download.AddArgumentCompletionDynamic("RemotePath", completion.CompleteRemotePathAndFiles)

	upload := cc.AddCommand(constants.UploadStr,
		"Upload one or more files from the client to the target filesystem", "",
		constants.FilesystemGroup,
		[]string{""},
		func() gonsole.Commander { return &filesystem.Upload{} })
	upload.AddArgumentCompletionDynamic("RemotePath", completion.CompleteRemotePathAndFiles)
	upload.AddArgumentCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)

	// Proc -------------------------------------------------------------------------------
	cc.AddCommand(constants.PsStr,
		"List host processes", "",
		constants.ProcGroup,
		[]string{""},
		func() gonsole.Commander { return &proc.PS{} })

	procDump := cc.AddCommand(constants.ProcdumpStr,
		"Dump process memory (process ID argument, or options)", "",
		constants.ProcGroup,
		[]string{""},
		func() gonsole.Commander { return &proc.ProcDump{} })
	procDump.AddArgumentCompletion("PID", completion.SessionProcesses)
	procDump.AddOptionCompletion("Name", completion.SessionProcessNames)

	terminate := cc.AddCommand(constants.TerminateStr,
		"Kill/terminate one or more running host processes", "",
		constants.ProcGroup,
		[]string{""},
		func() gonsole.Commander { return &proc.Terminate{} })
	terminate.AddArgumentCompletion("PID", completion.SessionProcesses)

	// Execution --------------------------------------------------------------------------
	exec := cc.AddCommand(constants.ExecuteStr,
		"Execute a program on the remote system", "",
		constants.ExecuteGroup,
		[]string{""},
		func() gonsole.Commander { return &execute.Execute{} })
	exec.AddArgumentCompletionDynamic("Args", completion.CompleteRemotePathAndFiles)

	msf := cc.AddCommand(constants.MsfStr,
		"Execute an MSF payload in the current process", "",
		constants.ExecuteGroup,
		[]string{""},
		func() gonsole.Commander { return &execute.MSF{} })
	msf.AddOptionCompletion("LHost", completion.ServerInterfaceAddrs)
	msf.AddOptionCompletion("Payload", completion.CompleteMsfVenomPayloads)
	msf.AddOptionCompletion("Encoder", completion.CompleteMsfEncoders)

	msfInject := cc.AddCommand(constants.MsfInjectStr,
		"Inject an MSF payload into a process (ID as argument)", "",
		constants.ExecuteGroup,
		[]string{""},
		func() gonsole.Commander { return &execute.MSFInject{} })
	msfInject.AddArgumentCompletion("PID", completion.SessionProcesses)
	msf.AddOptionCompletion("LHost", completion.ServerInterfaceAddrs)
	msfInject.AddOptionCompletion("Payload", completion.CompleteMsfVenomPayloads)
	msfInject.AddOptionCompletion("Encoder", completion.CompleteMsfEncoders)

	execSh := cc.AddCommand(constants.ExecuteShellcodeStr,
		"Executes the given shellcode in the sliver process", "",
		constants.ExecuteGroup,
		[]string{""},
		func() gonsole.Commander { return &execute.ExecuteShellcode{} })
	execSh.AddArgumentCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)
	execSh.AddOptionCompletionDynamic("RemotePath", completion.CompleteRemotePathAndFiles)
	execSh.AddOptionCompletion("PID", completion.SessionProcesses)

	sideload := cc.AddCommand(constants.SideloadStr,
		"Load and execute a shared object (shared library/DLL) in a remote process", "",
		constants.ExecuteGroup,
		[]string{""},
		func() gonsole.Commander { return &execute.Sideload{} })
	sideload.AddArgumentCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)
	sideload.AddArgumentCompletionDynamic("Args", completion.CompleteRemotePathAndFiles)
	sideload.AddOptionCompletionDynamic("RemotePath", completion.CompleteRemotePathAndFiles)
	sideload.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPathAndFiles)

	execSSH := cc.AddCommand(constants.SSHStr,
		"SSH to a host reachable from session and execute a command", "",
		constants.SSHStr,
		[]string{""},
		func() gonsole.Commander { return &execute.ExecuteShellcode{} })
	execSSH.AddArgumentCompletionDynamic("UserHost", completion.UserAtHostSSH)
	execSSH.AddOptionCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)
	execSSH.AddOptionCompletionDynamic("RemotePath", completion.CompleteRemotePathAndFiles)
	// execSSH.AddOptionCompletionDynamic("Password", completion.Passwords)

	// Extensions  -------------------------------------------------------------------------

	loadExtension := cc.AddCommand(constants.ExtensionStr,
		"Load an extension through the current Sliver session", "",
		constants.ExtensionsGroup,
		[]string{""},
		func() gonsole.Commander { return &extensions.LoadExtension{} })
	loadExtension.AddArgumentCompletionDynamic("Path", core.Console.Completer.LocalPathAndFiles)

	//  Network Tools ----------------------------------------------------------------------

	// WireGuard
	wgPortFwd := cc.AddCommand(constants.WgPortFwdStr,
		"Manage ports forwarded by the WireGuard tun interface. Prints them by default",
		help.GetHelpFor(constants.WgPortFwdStr),
		constants.NetworkToolsGroup,
		[]string{constants.WireGuardGroup},
		func() gonsole.Commander { return &wireguard.WireGuardPortFwd{} })

	wgPortFwd.SubcommandsOptional = true

	wgPortfwdAdd := wgPortFwd.AddCommand("add",
		"Add a port forward from the WireGuard tun interface to a host on the target network",
		help.GetHelpFor(constants.WgPortFwdStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &wireguard.WireGuardPortFwdAdd{} })
	wgPortfwdAdd.AddOptionCompletion("Remote", completion.ServerInterfaceAddrs)

	wgPortfwdRm := wgPortFwd.AddCommand("rm",
		"Remove one or more port forwards from the WireGuard tun interface",
		help.GetHelpFor(constants.WgPortFwdStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &wireguard.WireGuardPortFwdAdd{} })
	wgPortfwdRm.AddArgumentCompletion("ID", completion.CompleteWireGuardPortfwds)

	wgSocks := cc.AddCommand(constants.WgSocksStr,
		"Manage Socks servers listening on the WireGuard tun interface. Lists them by default.",
		help.GetHelpFor(constants.WgSocksStr),
		constants.NetworkToolsGroup,
		[]string{constants.WireGuardGroup},
		func() gonsole.Commander { return &wireguard.WireGuardSocks{} })

	wgSocks.SubcommandsOptional = true

	wgSocks.AddCommand("start",
		"Start a socks5 listener on the WireGuard tun interface",
		help.GetHelpFor(constants.WgSocksStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &wireguard.WireGuardSocksStart{} })

	wgSocksStop := wgSocks.AddCommand(constants.RmStr,
		"Stop one or more socks5 listeners on the WireGuard tun interface",
		help.GetHelpFor(constants.WgSocksStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &wireguard.WireGuardPortFwdAdd{} })
	wgSocksStop.AddArgumentCompletion("ID", completion.CompleteWireGuardSocksServers)

	// In-Band Port Forwards

	pfwd := cc.AddCommand(constants.PortfwdStr,
		"In-band TCP port forwarders management (add/rm only available in session menu)",
		help.GetHelpFor(constants.PortfwdStr),
		constants.NetworkToolsGroup,
		[]string{""},
		func() gonsole.Commander { return &portfwd.Portfwd{} })

	pfwd.SubcommandsOptional = true

	portfwdAdd := pfwd.AddCommand("add",
		"Create a new port forwarding tunnel",
		help.GetHelpFor(constants.PortfwdStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &portfwd.PortfwdAdd{} })
	portfwdAdd.AddOptionCompletion("Bind", core.Console.Completer.ClientInterfaceAddrs)
	portfwdAdd.AddOptionCompletion("Remote", completion.ServerInterfaceAddrs)

	portfwdRm := pfwd.AddCommand(constants.RmStr,
		"Remove a port forwarding tunnel",
		help.GetHelpFor(constants.PortfwdStr),
		"",
		[]string{""},
		func() gonsole.Commander { return &portfwd.PortfwdRm{} })
	portfwdRm.AddArgumentCompletion("ID", completion.CompleteInBandForwarders)

	// Persistence -------------------------------------------------------------------------
	dllh := cc.AddCommand(constants.DLLHijackStr,
		"Plant a malicious DLL (or implant DLL) into a reference and upload to target (completed)",
		help.GetHelpFor(constants.DLLHijackStr),
		constants.PersistenceGroup,
		[]string{""},
		func() gonsole.Commander { return &dllhijack.DllHijack{} })
	dllh.AddArgumentCompletionDynamic("TargetPath", completion.CompleteRemotePath)
	dllh.AddArgumentCompletionDynamic("RemotePath", completion.CompleteRemotePathAndFiles)
	dllh.AddOptionCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)
	dllh.AddOptionCompletionDynamic("File", core.Console.Completer.LocalPathAndFiles)
	dllh.AddOptionCompletion("Profile", completion.ImplantProfiles)

	// Windows -----------------------------------------------------------------------------
	windowsCmds.BindCommands(cc)
}
