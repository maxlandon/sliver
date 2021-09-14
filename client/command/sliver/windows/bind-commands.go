package windows

import (
	"github.com/maxlandon/gonsole"

	"github.com/bishopfox/sliver/client/completion"
	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/help"

	// Command implementations
	"github.com/bishopfox/sliver/client/command/sliver/windows/execute"
	"github.com/bishopfox/sliver/client/command/sliver/windows/persistence"
	"github.com/bishopfox/sliver/client/command/sliver/windows/priv"
	"github.com/bishopfox/sliver/client/command/sliver/windows/registry"
)

const (
	// ANSI Colors
	normal    = "\033[0m"
	black     = "\033[30m"
	red       = "\033[31m"
	green     = "\033[32m"
	orange    = "\033[33m"
	blue      = "\033[34m"
	purple    = "\033[35m"
	cyan      = "\033[36m"
	gray      = "\033[37m"
	bold      = "\033[1m"
	clearln   = "\r\x1b[2K"
	upN       = "\033[%dA"
	downN     = "\033[%dB"
	underline = "\033[4m"

	// Info - Display colorful information
	Info = bold + cyan + "[*] " + normal
	// Debug - Display debug information
	Debug = bold + purple + "[-] " + normal
	// Error - Notify error to a user
	Error = bold + red + "[!] " + normal
	// Warning - Notify important information, not an error
	Warning = bold + orange + "[!] " + normal
	// Woot - Display success
	Woot = bold + green + "[$] " + normal
)

// BindCommands - Binds Windows-specific commands for Windows-based Sliver session.
func BindCommands(cc *gonsole.Menu) {

	// Priv -------------------------------------------------------------------------------
	cc.AddCommand(constants.ImpersonateStr,
		"Impersonate a logged in user", "",
		constants.PrivGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &priv.Impersonate{} })

	cc.AddCommand(constants.RevToSelfStr,
		"Revert to self: lose stolen Windows token", "",
		constants.PrivGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &priv.Rev2Self{} })

	cc.AddCommand(constants.GetSystemStr,
		"Spawns a new sliver session as the NT AUTHORITY\\SYSTEM user ", "",
		constants.PrivGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &priv.GetSystem{} })

	cc.AddCommand(constants.MakeTokenStr,
		"Create a new Logon Session with the specified credentials", "",
		constants.PrivGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &priv.MakeToken{} })

	cc.AddCommand(constants.RunAsStr,
		"Run a new process in the context of the designated user", "",
		constants.ExecuteGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &priv.RunAs{} })

	// Execution --------------------------------------------------------------------------
	migrate := cc.AddCommand(constants.MigrateStr,
		"Migrate into a remote host process", "",
		constants.ProcGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &execute.Migrate{} })
	migrate.AddArgumentCompletion("PID", completion.SessionProcesses)

	execAssembly := cc.AddCommand(constants.ExecuteAssemblyStr,
		"Loads and executes a .NET assembly in a child process", "",
		constants.ExecuteGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &execute.ExecuteAssembly{} })
	execAssembly.AddArgumentCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)
	execAssembly.AddArgumentCompletionDynamic("Args", completion.CompleteRemotePathAndFiles)
	execAssembly.AddOptionCompletionDynamic("Path", completion.CompleteRemotePathAndFiles)
	execAssembly.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)
	execAssembly.AddOptionCompletion("Arch", completion.CompleteAssemblyArchs)

	spawnDll := cc.AddCommand(constants.SpawnDllStr,
		"Load and execute a Reflective DLL in a remote process", "",
		constants.ExecuteGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &execute.SpawnDLL{} })
	spawnDll.AddArgumentCompletionDynamic("LocalPath", core.Console.Completer.LocalPathAndFiles)
	spawnDll.AddArgumentCompletionDynamic("Args", completion.CompleteRemotePathAndFiles)
	spawnDll.AddOptionCompletionDynamic("Save", core.Console.Completer.LocalPath)

	// Persistence ------------------------------------------------------------------------
	cc.AddCommand(constants.PsExecStr,
		"Start a sliver service on the session target", "",
		constants.PersistenceGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &persistence.Service{} })

	backdoor := cc.AddCommand(constants.BackdoorStr,
		"Infect a remote file with a sliver shellcode", "",
		constants.PersistenceGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &persistence.Backdoor{} })
	backdoor.AddArgumentCompletionDynamic("RemotePath", completion.CompleteRemotePathAndFiles)

	// Registry ---------------------------------------------------------------------------
	reg := cc.AddCommand(constants.RegistryStr,
		"Windows Registry management commands",
		help.GetHelpFor(constants.RegistryStr),
		constants.PersistenceGroup,
		[]string{constants.SliverWinHelpGroup},
		func() interface{} { return &registry.Registry{} })

	reg.AddCommand(constants.RegistryReadStr,
		"Read values from the Windows Registry",
		help.GetHelpFor(constants.RegistryReadStr),
		"", []string{constants.SliverWinHelpGroup},
		func() interface{} { return &registry.RegistryRead{} })

	reg.AddCommand(constants.RegistryWriteStr,
		"Write values to the Windows Registry",
		help.GetHelpFor(constants.RegistryWriteStr),
		"", []string{constants.SliverWinHelpGroup},
		func() interface{} { return &registry.RegistryWrite{} })

	reg.AddCommand(constants.RegistryCreateKeyStr,
		"Create a Registry key",
		help.GetHelpFor(constants.RegistryCreateKeyStr),
		"", []string{constants.SliverWinHelpGroup},
		func() interface{} { return &registry.RegistryCreateKey{} })
}
