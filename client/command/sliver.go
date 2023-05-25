package command

import (
	"io"

	"github.com/reeflective/console"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/command/alias"
	"github.com/bishopfox/sliver/client/command/backdoor"
	"github.com/bishopfox/sliver/client/command/cursed"
	"github.com/bishopfox/sliver/client/command/dllhijack"
	"github.com/bishopfox/sliver/client/command/environment"
	"github.com/bishopfox/sliver/client/command/exec"
	"github.com/bishopfox/sliver/client/command/extensions"
	"github.com/bishopfox/sliver/client/command/filesystem"
	"github.com/bishopfox/sliver/client/command/generate"
	"github.com/bishopfox/sliver/client/command/help"
	"github.com/bishopfox/sliver/client/command/info"
	"github.com/bishopfox/sliver/client/command/kill"
	"github.com/bishopfox/sliver/client/command/network"
	"github.com/bishopfox/sliver/client/command/pivots"
	"github.com/bishopfox/sliver/client/command/portfwd"
	"github.com/bishopfox/sliver/client/command/privilege"
	"github.com/bishopfox/sliver/client/command/processes"
	"github.com/bishopfox/sliver/client/command/reconfig"
	"github.com/bishopfox/sliver/client/command/registry"
	"github.com/bishopfox/sliver/client/command/rportfwd"
	"github.com/bishopfox/sliver/client/command/screenshot"
	"github.com/bishopfox/sliver/client/command/sessions"
	"github.com/bishopfox/sliver/client/command/shell"
	"github.com/bishopfox/sliver/client/command/socks"
	"github.com/bishopfox/sliver/client/command/tasks"
	"github.com/bishopfox/sliver/client/command/use"
	"github.com/bishopfox/sliver/client/command/wireguard"
	client "github.com/bishopfox/sliver/client/console"
	consts "github.com/bishopfox/sliver/client/constants"
)

// SliverCommands returns all commands bound to the implant menu.
func SliverCommands(con *client.SliverConsole) console.Commands {
	// Interrupts: trigger functionality with keystrokes.
	con.App.Menu("implant").AddInterrupt(io.EOF, func(_ *console.Console) {
		sessions.BackgroundCmd(con.App.CurrentMenu().Command, con, nil)
	})

	sliverCommands := func() *cobra.Command {
		sliver := &cobra.Command{
			Short: "Implant commands",
		}

		groups := []*cobra.Group{
			{ID: consts.SliverCoreHelpGroup, Title: consts.SliverCoreHelpGroup},
			{ID: consts.InfoHelpGroup, Title: consts.InfoHelpGroup},
			{ID: consts.FilesystemHelpGroup, Title: consts.FilesystemHelpGroup},
			{ID: consts.NetworkHelpGroup, Title: consts.NetworkHelpGroup},
			{ID: consts.ExecutionHelpGroup, Title: consts.ExecutionHelpGroup},
			{ID: consts.PrivilegesHelpGroup, Title: consts.PrivilegesHelpGroup},
			{ID: consts.ProcessHelpGroup, Title: consts.ProcessHelpGroup},
			{ID: consts.AliasHelpGroup, Title: consts.AliasHelpGroup},
			{ID: consts.ExtensionHelpGroup, Title: consts.ExtensionHelpGroup},
		}
		sliver.AddGroup(groups...)

		// Load Aliases
		aliasManifests := assets.GetInstalledAliasManifests()
		n := 0
		for _, manifest := range aliasManifests {
			_, err := alias.LoadAlias(manifest, sliver, con)
			if err != nil {
				con.PrintErrorf("Failed to load alias: %s", err)
				// client.Client.PrintErrorf("Failed to load alias: %s\n", err)
				continue
			}
			n++
		}

		// Load Extensions
		extensionManifests := assets.GetInstalledExtensionManifests()
		n = 0
		for _, manifest := range extensionManifests {
			ext, err := extensions.LoadExtensionManifest(manifest)
			// Absorb error in case there's no extensions manifest
			if err != nil {
				con.PrintErrorf("Failed to load extension: %s", err)
				// client.Client.PrintErrorf("Failed to load extension: %s", err)
				continue
			}
			extensions.ExtensionRegisterCommand(ext, sliver, con)
			n++
		}
		// if 0 < n {
		// 	con.PrintInfof("Loaded %d extension(s) from disk\n", n)
		// }
		// .App.SetPrintHelp(help.HelpCmd(con)) // Responsible for display long-form help templates, etc.

		// [ Reconfig ] ---------------------------------------------------------------

		reconfigCmd := &cobra.Command{
			Use:   consts.ReconfigStr,
			Short: "Reconfigure the active beacon/session",
			Long:  help.GetHelpFor([]string{consts.ReconfigStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				reconfig.ReconfigCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.SliverCoreHelpGroup,
			Annotations: HideCommand(consts.BeaconCmdsFilter),
		}
		sliver.AddCommand(reconfigCmd)
		Flags("reconfig", reconfigCmd, func(f *pflag.FlagSet) {
			f.StringP("reconnect-interval", "r", "", "reconnect interval for implant")
			f.StringP("beacon-interval", "i", "", "beacon callback interval")
			f.StringP("beacon-jitter", "j", "", "beacon callback jitter (random up to)")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		renameCmd := &cobra.Command{
			Use:   consts.RenameStr,
			Short: "Rename the active beacon/session",
			Long:  help.GetHelpFor([]string{consts.RenameStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				reconfig.RenameCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.SliverCoreHelpGroup,
		}
		sliver.AddCommand(renameCmd)

		Flags("rename", renameCmd, func(f *pflag.FlagSet) {
			f.StringP("name", "n", "", "change implant name to")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Sessions ] --------------------------------------------------------------

		sessionsCmd := &cobra.Command{
			Use:   consts.SessionsStr,
			Short: "Session management",
			Long:  help.GetHelpFor([]string{consts.SessionsStr}),
			Run: func(cmd *cobra.Command, args []string) {
				sessions.SessionsCmd(cmd, con, args)
			},
			GroupID: consts.SliverCoreHelpGroup,
		}
		Flags("sessions", sessionsCmd, func(f *pflag.FlagSet) {
			f.StringP("interact", "i", "", "interact with a session")
			f.StringP("kill", "k", "", "kill the designated session")
			f.BoolP("kill-all", "K", false, "kill all the sessions")
			f.BoolP("clean", "C", false, "clean out any sessions marked as [DEAD]")
			f.BoolP("force", "F", false, "force session action without waiting for results")

			f.StringP("filter", "f", "", "filter sessions by substring")
			f.StringP("filter-re", "e", "", "filter sessions by regular expression")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		FlagComps(sessionsCmd, func(comp *carapace.ActionMap) {
			(*comp)["interact"] = use.BeaconAndSessionIDCompleter(con)
			(*comp)["kill"] = use.BeaconAndSessionIDCompleter(con)
		})
		sliver.AddCommand(sessionsCmd)

		sessionsPruneCmd := &cobra.Command{
			Use:   consts.PruneStr,
			Short: "Kill all stale/dead sessions",
			Long:  help.GetHelpFor([]string{consts.SessionsStr, consts.PruneStr}),
			Run: func(cmd *cobra.Command, args []string) {
				sessions.SessionsPruneCmd(cmd, con, args)
			},
		}
		Flags("prune", sessionsCmd, func(f *pflag.FlagSet) {
			f.BoolP("force", "F", false, "Force the killing of stale/dead sessions")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		sessionsCmd.AddCommand(sessionsPruneCmd)

		backgroundCmd := &cobra.Command{
			Use:   consts.BackgroundStr,
			Short: "Background an active session",
			Long:  help.GetHelpFor([]string{consts.BackgroundStr}),
			Run: func(cmd *cobra.Command, args []string) {
				sessions.BackgroundCmd(cmd, con, args)
			},
			GroupID: consts.SliverCoreHelpGroup,
		}
		Flags("use", backgroundCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		sliver.AddCommand(backgroundCmd)

		killCmd := &cobra.Command{
			Use:   consts.KillStr,
			Short: "Kill a session",
			Long:  help.GetHelpFor([]string{consts.KillStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				kill.KillCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.SliverCoreHelpGroup,
		}
		sliver.AddCommand(killCmd)
		Flags("use", backgroundCmd, func(f *pflag.FlagSet) {
			f.BoolP("force", "F", false, "Force kill,  does not clean up")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		openSessionCmd := &cobra.Command{
			Use:   consts.InteractiveStr,
			Short: "Task a beacon to open an interactive session (Beacon only)",
			Long:  help.GetHelpFor([]string{consts.InteractiveStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				sessions.InteractiveCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.SliverCoreHelpGroup,
			Annotations: HideCommand(consts.BeaconCmdsFilter),
		}
		sliver.AddCommand(openSessionCmd)
		Flags("", openSessionCmd, func(f *pflag.FlagSet) {
			f.StringP("mtls", "m", "", "mtls connection strings")
			f.StringP("wg", "g", "", "wg connection strings")
			f.StringP("http", "b", "", "http(s) connection strings")
			f.StringP("dns", "n", "", "dns connection strings")
			f.StringP("named-pipe", "p", "", "namedpipe connection strings")
			f.StringP("tcp-pivot", "i", "", "tcppivot connection strings")

			f.StringP("delay", "d", "0s", "delay opening the session (after checkin) for a given period of time")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Close ] --------------------------------------------------------------
		closeSessionCmd := &cobra.Command{
			Use:   consts.CloseStr,
			Short: "Close an interactive session without killing the remote process",
			Long:  help.GetHelpFor([]string{consts.CloseStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				sessions.CloseSessionCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.SliverCoreHelpGroup,
		}
		sliver.AddCommand(closeSessionCmd)
		Flags("", closeSessionCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Tasks ] --------------------------------------------------------------

		tasksCmd := &cobra.Command{
			Use:   consts.TasksStr,
			Short: "Beacon task management",
			Long:  help.GetHelpFor([]string{consts.TasksStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				tasks.TasksCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.SliverCoreHelpGroup,
		}
		Flags("", tasksCmd, func(f *pflag.FlagSet) {
			f.BoolP("overflow", "O", false, "overflow terminal width (display truncated rows)")
			f.IntP("skip-pages", "S", 0, "skip the first n page(s)")
			f.StringP("filter", "f", "", "filter based on task type (case-insensitive prefix matching)")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		sliver.AddCommand(tasksCmd)

		fetchCmd := &cobra.Command{
			Use:   consts.FetchStr,
			Short: "Fetch the details of a beacon task",
			Long:  help.GetHelpFor([]string{consts.TasksStr, consts.FetchStr}),
			Args:  cobra.RangeArgs(0, 1), // 	a.String("id", "beacon task ID", grumble.Default(""))
			RunE: func(cmd *cobra.Command, args []string) error {
				tasks.TasksFetchCmd(cmd, con, args)
				return nil
			},
		}
		tasksCmd.AddCommand(fetchCmd)
		Flags("", fetchCmd, func(f *pflag.FlagSet) {
			f.BoolP("overflow", "O", false, "overflow terminal width (display truncated rows)")
			f.IntP("skip-pages", "S", 0, "skip the first n page(s)")
			f.StringP("filter", "f", "", "filter based on task type (case-insensitive prefix matching)")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		cancelCmd := &cobra.Command{
			Use:   consts.CancelStr,
			Short: "Cancel a pending beacon task",
			Long:  help.GetHelpFor([]string{consts.TasksStr, consts.CancelStr}),
			Args:  cobra.RangeArgs(0, 1), // 	a.String("id", "beacon task ID", grumble.Default(""))
			RunE: func(cmd *cobra.Command, args []string) error {
				tasks.TasksCancelCmd(cmd, con, args)
				return nil
			},
		}
		tasksCmd.AddCommand(cancelCmd)
		Flags("", cancelCmd, func(f *pflag.FlagSet) {
			f.BoolP("overflow", "O", false, "overflow terminal width (display truncated rows)")
			f.IntP("skip-pages", "S", 0, "skip the first n page(s)")
			f.StringP("filter", "f", "", "filter based on task type (case-insensitive prefix matching)")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Info ] --------------------------------------------------------------

		infoCmd := &cobra.Command{
			Use:   consts.InfoStr,
			Short: "Get info about session",
			Long:  help.GetHelpFor([]string{consts.InfoStr}),
			Run: func(cmd *cobra.Command, args []string) {
				info.InfoCmd(cmd, con, args)
			},
			GroupID: consts.InfoHelpGroup,
		}
		Flags("use", infoCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		carapace.Gen(infoCmd).PositionalCompletion(use.BeaconAndSessionIDCompleter(con))
		sliver.AddCommand(infoCmd)

		pingCmd := &cobra.Command{
			Use:   consts.PingStr,
			Short: "Send round trip message to implant (does not use ICMP)",
			Long:  help.GetHelpFor([]string{consts.PingStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				info.PingCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.InfoHelpGroup,
		}
		sliver.AddCommand(pingCmd)
		Flags("", pingCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		getPIDCmd := &cobra.Command{
			Use:   consts.GetPIDStr,
			Short: "Get session pid",
			Long:  help.GetHelpFor([]string{consts.GetPIDStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				info.PIDCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.InfoHelpGroup,
		}
		sliver.AddCommand(getPIDCmd)
		Flags("", getPIDCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		getUIDCmd := &cobra.Command{
			Use:   consts.GetUIDStr,
			Short: "Get session process UID",
			Long:  help.GetHelpFor([]string{consts.GetUIDStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				info.UIDCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.InfoHelpGroup,
		}
		sliver.AddCommand(getUIDCmd)
		Flags("", getUIDCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		getGIDCmd := &cobra.Command{
			Use:   consts.GetGIDStr,
			Short: "Get session process GID",
			Long:  help.GetHelpFor([]string{consts.GetGIDStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				info.GIDCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.InfoHelpGroup,
		}
		sliver.AddCommand(getGIDCmd)
		Flags("", getGIDCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		whoamiCmd := &cobra.Command{
			Use:   consts.WhoamiStr,
			Short: "Get session user execution context",
			Long:  help.GetHelpFor([]string{consts.WhoamiStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				info.WhoamiCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.InfoHelpGroup,
		}
		sliver.AddCommand(whoamiCmd)
		Flags("", whoamiCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Shell ] --------------------------------------------------------------

		shellCmd := &cobra.Command{
			Use:   consts.ShellStr,
			Short: "Start an interactive shell",
			Long:  help.GetHelpFor([]string{consts.ShellStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				shell.ShellCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.ExecutionHelpGroup,
			Annotations: HideCommand(consts.SessionCmdsFilter),
		}
		sliver.AddCommand(shellCmd)
		Flags("", shellCmd, func(f *pflag.FlagSet) {
			f.BoolP("no-pty", "y", false, "disable use of pty on macos/linux")
			f.StringP("shell-path", "s", "", "path to shell interpreter")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Exec ] --------------------------------------------------------------

		executeCmd := &cobra.Command{
			Use:   consts.ExecuteStr,
			Short: "Execute a program on the remote system",
			Long:  help.GetHelpFor([]string{consts.ExecuteStr}),
			Args:  cobra.MinimumNArgs(1),
			// 	a.String("command", "command to execute")
			// 	a.StringList("arguments", "arguments to the command")
			RunE: func(cmd *cobra.Command, args []string) error {
				exec.ExecuteCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.ExecutionHelpGroup,
		}
		sliver.AddCommand(executeCmd)
		Flags("", executeCmd, func(f *pflag.FlagSet) {
			f.BoolP("token", "T", false, "execute command with current token (windows only)")
			f.BoolP("output", "o", false, "capture command output")
			f.BoolP("save", "s", false, "save output to a file")
			f.BoolP("loot", "X", false, "save output as loot")
			f.BoolP("ignore-stderr", "S", false, "don't print STDERR output")
			f.StringP("stdout", "O", "", "remote path to redirect STDOUT to")
			f.StringP("stderr", "E", "", "remote path to redirect STDERR to")
			f.StringP("name", "n", "", "name to assign loot (optional)")
			f.Uint32P("ppid", "P", 0, "parent process id (optional, Windows only)")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		executeAssemblyCmd := &cobra.Command{
			Use:   consts.ExecuteAssemblyStr,
			Short: "Loads and executes a .NET assembly in a child process (Windows Only)",
			Long:  help.GetHelpFor([]string{consts.ExecuteAssemblyStr}),
			Args:  cobra.MinimumNArgs(1),
			// 	a.String("filepath", "path the assembly file")
			// 	a.StringList("arguments", "arguments to pass to the assembly entrypoint", grumble.Default([]string{}))
			RunE: func(cmd *cobra.Command, args []string) error {
				exec.ExecuteAssemblyCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.ExecutionHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
		}
		sliver.AddCommand(executeAssemblyCmd)
		Flags("", executeAssemblyCmd, func(f *pflag.FlagSet) {
			f.StringP("process", "p", "notepad.exe", "hosting process to inject into")
			f.StringP("method", "m", "", "Optional method (a method is required for a .NET DLL)")
			f.StringP("class", "c", "", "Optional class name (required for .NET DLL)")
			f.StringP("app-domain", "d", "", "AppDomain name to create for .NET assembly. Generated randomly if not set.")
			f.StringP("arch", "a", "x84", "Assembly target architecture: x86, x64, x84 (x86+x64)")
			f.BoolP("in-process", "i", false, "Run in the current sliver process")
			f.StringP("runtime", "r", "", "Runtime to use for running the assembly (only supported when used with --in-process)")
			f.BoolP("save", "s", false, "save output to file")
			f.BoolP("loot", "X", false, "save output as loot")
			f.StringP("name", "n", "", "name to assign loot (optional)")
			f.Uint32P("ppid", "P", 0, "parent process id (optional)")
			f.StringP("process-arguments", "A", "", "arguments to pass to the hosting process")
			f.BoolP("amsi-bypass", "M", false, "Bypass AMSI on Windows (only supported when used with --in-process)")
			f.BoolP("etw-bypass", "E", false, "Bypass ETW on Windows (only supported when used with --in-process)")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		executeShellcodeCmd := &cobra.Command{
			Use:   consts.ExecuteShellcodeStr,
			Short: "Executes the given shellcode in the sliver process",
			Long:  help.GetHelpFor([]string{consts.ExecuteShellcodeStr}),
			Args:  cobra.ExactArgs(1), // 	a.String("filepath", "path the shellcode file")
			RunE: func(cmd *cobra.Command, args []string) error {
				exec.ExecuteShellcodeCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.ExecutionHelpGroup,
		}
		sliver.AddCommand(executeShellcodeCmd)
		Flags("", executeShellcodeCmd, func(f *pflag.FlagSet) {
			f.BoolP("rwx-pages", "r", false, "Use RWX permissions for memory pages")
			f.Uint32P("pid", "p", 0, "Pid of process to inject into (0 means injection into ourselves)")
			f.StringP("process", "n", `c:\windows\system32\notepad.exe`, "Process to inject into when running in interactive mode")
			f.BoolP("interactive", "i", false, "Inject into a new process and interact with it")
			f.BoolP("shikata-ga-nai", "S", false, "encode shellcode using shikata ga nai prior to execution")
			f.StringP("architecture", "A", "amd64", "architecture of the shellcode: 386, amd64 (used with --shikata-ga-nai flag)")
			f.IntP("iterations", "I", 1, "number of encoding iterations (used with --shikata-ga-nai flag)")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		sideloadCmd := &cobra.Command{
			Use:   consts.SideloadStr,
			Short: "Load and execute a shared object (shared library/DLL) in a remote process",
			Long:  help.GetHelpFor([]string{consts.SideloadStr}),
			Args:  cobra.MinimumNArgs(1),
			// 	a.String("filepath", "path the shared library file")
			// 	a.StringList("args", "arguments for the binary", grumble.Default([]string{}))
			RunE: func(cmd *cobra.Command, args []string) error {
				exec.SideloadCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.ExecutionHelpGroup,
		}
		sliver.AddCommand(sideloadCmd)
		Flags("", sideloadCmd, func(f *pflag.FlagSet) {
			f.StringP("entry-point", "e", "", "Entrypoint for the DLL (Windows only)")
			f.StringP("process", "p", `c:\windows\system32\notepad.exe`, "Path to process to host the shellcode")
			f.BoolP("unicode", "w", false, "Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)")
			f.BoolP("save", "s", false, "save output to file")
			f.BoolP("loot", "X", false, "save output as loot")
			f.StringP("name", "n", "", "name to assign loot (optional)")
			f.BoolP("keep-alive", "k", false, "don't terminate host process once the execution completes")
			f.Uint32P("ppid", "P", 0, "parent process id (optional)")
			f.StringP("process-arguments", "A", "", "arguments to pass to the hosting process")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		spawnDllCmd := &cobra.Command{
			Use:   consts.SpawnDllStr,
			Short: "Load and execute a Reflective DLL in a remote process",
			Long:  help.GetHelpFor([]string{consts.SpawnDllStr}),
			Args:  cobra.MinimumNArgs(1),
			// 	a.String("filepath", "path the DLL file")
			// 	a.StringList("arguments", "arguments to pass to the DLL entrypoint", grumble.Default([]string{}))
			RunE: func(cmd *cobra.Command, args []string) error {
				exec.SpawnDllCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.ExecutionHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
		}
		sliver.AddCommand(spawnDllCmd)
		Flags("", spawnDllCmd, func(f *pflag.FlagSet) {
			f.StringP("process", "p", `c:\windows\system32\notepad.exe`, "Path to process to host the shellcode")
			f.StringP("export", "e", "ReflectiveLoader", "Entrypoint of the Reflective DLL")
			f.BoolP("save", "s", false, "save output to file")
			f.BoolP("loot", "X", false, "save output as loot")
			f.StringP("name", "n", "", "name to assign loot (optional)")
			f.BoolP("keep-alive", "k", false, "don't terminate host process once the execution completes")
			f.UintP("ppid", "P", 0, "parent process id (optional)")
			f.StringP("process-arguments", "A", "", "arguments to pass to the hosting process")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		migrateCmd := &cobra.Command{
			Use:   consts.MigrateStr,
			Short: "Migrate into a remote process",
			Long:  help.GetHelpFor([]string{consts.MigrateStr}),
			Args:  cobra.ExactArgs(1), // 	a.Uint("pid", "pid")
			RunE: func(cmd *cobra.Command, args []string) error {
				exec.MigrateCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.ExecutionHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
		}
		sliver.AddCommand(migrateCmd)
		Flags("", migrateCmd, func(f *pflag.FlagSet) {
			f.BoolP("disable-sgn", "S", true, "disable shikata ga nai shellcode encoder")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		msfCmd := &cobra.Command{
			Use:   consts.MsfStr,
			Short: "Execute an MSF payload in the current process",
			Long:  help.GetHelpFor([]string{consts.MsfStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				exec.MsfCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.ExecutionHelpGroup,
		}
		sliver.AddCommand(msfCmd)
		Flags("", msfCmd, func(f *pflag.FlagSet) {
			f.StringP("payload", "m", "meterpreter_reverse_https", "msf payload")
			f.StringP("lhost", "L", "", "listen host")
			f.IntP("lport", "l", 4444, "listen port")
			f.StringP("encoder", "e", "", "msf encoder")
			f.IntP("iterations", "i", 1, "iterations of the encoder")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		msfInjectCmd := &cobra.Command{
			Use:   consts.MsfInjectStr,
			Short: "Inject an MSF payload into a process",
			Long:  help.GetHelpFor([]string{consts.MsfInjectStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				exec.MsfInjectCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.ExecutionHelpGroup,
		}
		sliver.AddCommand(msfInjectCmd)
		Flags("", msfInjectCmd, func(f *pflag.FlagSet) {
			f.IntP("pid", "p", -1, "pid to inject into")
			f.StringP("payload", "m", "meterpreter_reverse_https", "msf payload")
			f.StringP("lhost", "L", "", "listen host")
			f.IntP("lport", "l", 4444, "listen port")
			f.StringP("encoder", "e", "", "msf encoder")
			f.IntP("iterations", "i", 1, "iterations of the encoder")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		psExecCmd := &cobra.Command{
			Use:   consts.PsExecStr,
			Short: "Start a sliver service on a remote target",
			Long:  help.GetHelpFor([]string{consts.PsExecStr}),
			Args:  cobra.ExactArgs(1), // 	a.String("hostname", "hostname")
			RunE: func(cmd *cobra.Command, args []string) error {
				exec.PsExecCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.ExecutionHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
		}
		sliver.AddCommand(psExecCmd)
		Flags("", psExecCmd, func(f *pflag.FlagSet) {
			f.StringP("service-name", "s", "Sliver", "name that will be used to register the service")
			f.StringP("service-description", "d", "Sliver implant", "description of the service")
			f.StringP("profile", "p", "", "profile to use for service binary")
			f.StringP("binpath", "b", "c:\\windows\\temp", "directory to which the executable will be uploaded")
			f.StringP("custom-exe", "c", "", "custom service executable to use instead of generating a new Sliver")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		sshCmd := &cobra.Command{
			Use:   consts.SSHStr,
			Short: "Run a SSH command on a remote host",
			Long:  help.GetHelpFor([]string{consts.SSHStr}),
			Args:  cobra.MinimumNArgs(1),
			// 	a.String("hostname", "remote host to SSH to")
			// 	a.StringList("command", "command line with arguments")
			RunE: func(cmd *cobra.Command, args []string) error {
				exec.SSHCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.ExecutionHelpGroup,
		}
		sliver.AddCommand(sshCmd)
		Flags("", sshCmd, func(f *pflag.FlagSet) {
			f.UintP("port", "p", 22, "SSH port")
			f.StringP("private-key", "i", "", "path to private key file")
			f.StringP("password", "P", "", "SSH user password")
			f.StringP("login", "l", "", "username to use to connect")
			f.BoolP("skip-loot", "s", false, "skip the prompt to use loot credentials")
			f.StringP("kerberos-config", "c", "/etc/krb5.conf", "path to remote Kerberos config file")
			f.StringP("kerberos-keytab", "k", "", "path to Kerberos keytab file")
			f.StringP("kerberos-realm", "r", "", "Kerberos realm")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Filesystem ] ---------------------------------------------

		mvCmd := &cobra.Command{
			Use:   consts.MvStr,
			Short: "Move or rename a file",
			Long:  help.GetHelpFor([]string{consts.MvStr}),
			Args:  cobra.ExactArgs(2),
			// 	a.String("src", "path to source file")
			// 	a.String("dst", "path to dest file")
			RunE: func(cmd *cobra.Command, args []string) error {
				filesystem.MvCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.FilesystemHelpGroup,
		}
		sliver.AddCommand(mvCmd)
		Flags("", mvCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		lsCmd := &cobra.Command{
			Use:   consts.LsStr,
			Short: "List current directory",
			Long:  help.GetHelpFor([]string{consts.LsStr}),
			Args:  cobra.RangeArgs(0, 1), // 	a.String("path", "path to enumerate", grumble.Default("."))
			Run: func(cmd *cobra.Command, args []string) {
				filesystem.LsCmd(cmd, con, args)
			},
			GroupID: consts.FilesystemHelpGroup,
		}
		sliver.AddCommand(lsCmd)
		Flags("", lsCmd, func(f *pflag.FlagSet) {
			f.BoolP("reverse", "r", false, "reverse sort order")
			f.BoolP("modified", "m", false, "sort by modified time")
			f.BoolP("size", "s", false, "sort by size")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		rmCmd := &cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove a file or directory",
			Long:  help.GetHelpFor([]string{consts.RmStr}),
			Args:  cobra.ExactArgs(1), // 	a.String("path", "path to the file to remove")
			RunE: func(cmd *cobra.Command, args []string) error {
				filesystem.RmCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.FilesystemHelpGroup,
		}
		sliver.AddCommand(rmCmd)
		Flags("", rmCmd, func(f *pflag.FlagSet) {
			f.BoolP("recursive", "r", false, "recursively remove files")
			f.BoolP("force", "F", false, "ignore safety and forcefully remove files")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		mkdirCmd := &cobra.Command{
			Use:   consts.MkdirStr,
			Short: "Make a directory",
			Long:  help.GetHelpFor([]string{consts.MkdirStr}),
			Args:  cobra.ExactArgs(1),
			// 	a.String("path", "path to the directory to create")
			RunE: func(cmd *cobra.Command, args []string) error {
				filesystem.MkdirCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.FilesystemHelpGroup,
		}
		sliver.AddCommand(mkdirCmd)
		Flags("", mkdirCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		cdCmd := &cobra.Command{
			Use:   consts.CdStr,
			Short: "Change directory",
			Long:  help.GetHelpFor([]string{consts.CdStr}),
			Args:  cobra.RangeArgs(0, 1), // 	a.String("path", "path to the directory", grumble.Default("."))
			Run: func(cmd *cobra.Command, args []string) {
				filesystem.CdCmd(cmd, con, args)
			},
			GroupID: consts.FilesystemHelpGroup,
		}
		sliver.AddCommand(cdCmd)
		Flags("", cdCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		pwdCmd := &cobra.Command{
			Use:   consts.PwdStr,
			Short: "Print working directory",
			Long:  help.GetHelpFor([]string{consts.PwdStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				filesystem.PwdCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.FilesystemHelpGroup,
		}
		sliver.AddCommand(pwdCmd)
		Flags("", pwdCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		catCmd := &cobra.Command{
			Use:   consts.CatStr,
			Short: "Dump file to stdout",
			Long:  help.GetHelpFor([]string{consts.CatStr}),
			Args:  cobra.ExactArgs(1),
			// 	a.String("path", "path to the file to print")
			RunE: func(cmd *cobra.Command, args []string) error {
				filesystem.CatCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.FilesystemHelpGroup,
		}
		sliver.AddCommand(catCmd)
		Flags("", catCmd, func(f *pflag.FlagSet) {
			f.BoolP("colorize-output", "c", false, "colorize output")
			f.BoolP("hex", "x", false, "display as a hex dump")
			f.BoolP("loot", "X", false, "save output as loot")
			f.StringP("name", "n", "", "name to assign loot (optional)")
			f.StringP("type", "T", "", "force a specific loot type (file/cred) if looting (optional)")
			f.StringP("file-type", "F", "", "force a specific file type (binary/text) if looting (optional)")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		downloadCmd := &cobra.Command{
			Use:   consts.DownloadStr,
			Short: "Download a file",
			Long:  help.GetHelpFor([]string{consts.DownloadStr}),
			Args:  cobra.RangeArgs(1, 2),
			// 	a.String("remote-path", "path to the file or directory to download")
			// 	a.String("local-path", "local path where the downloaded file will be saved", grumble.Default("."))
			RunE: func(cmd *cobra.Command, args []string) error {
				filesystem.DownloadCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.FilesystemHelpGroup,
		}
		sliver.AddCommand(downloadCmd)
		Flags("", downloadCmd, func(f *pflag.FlagSet) {
			f.BoolP("loot", "X", false, "save output as loot")
			f.StringP("type", "T", "", "force a specific loot type (file/cred) if looting")
			f.StringP("file-type", "F", "", "force a specific file type (binary/text) if looting")
			f.StringP("name", "n", "", "name to assign the download if looting")
			f.BoolP("recurse", "r", false, "recursively download all files in a directory")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		uploadCmd := &cobra.Command{
			Use:   consts.UploadStr,
			Short: "Upload a file",
			Long:  help.GetHelpFor([]string{consts.UploadStr}),
			Args:  cobra.RangeArgs(1, 2),
			// 	a.String("local-path", "local path to the file to upload")
			// 	a.String("remote-path", "path to the file or directory to upload to", grumble.Default(""))
			RunE: func(cmd *cobra.Command, args []string) error {
				filesystem.UploadCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.FilesystemHelpGroup,
		}
		sliver.AddCommand(uploadCmd)
		Flags("", uploadCmd, func(f *pflag.FlagSet) {
			f.BoolP("ioc", "i", false, "track uploaded file as an ioc")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Network ] ---------------------------------------------

		ifconfigCmd := &cobra.Command{
			Use:   consts.IfconfigStr,
			Short: "View network interface configurations",
			Long:  help.GetHelpFor([]string{consts.IfconfigStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				network.IfconfigCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.NetworkHelpGroup,
		}
		sliver.AddCommand(ifconfigCmd)
		Flags("", ifconfigCmd, func(f *pflag.FlagSet) {
			f.BoolP("all", "A", false, "show all network adapters (default only shows IPv4)")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		netstatCmd := &cobra.Command{
			Use:   consts.NetstatStr,
			Short: "Print network connection information",
			Long:  help.GetHelpFor([]string{consts.NetstatStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				network.NetstatCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.NetworkHelpGroup,
		}
		sliver.AddCommand(netstatCmd)
		Flags("", netstatCmd, func(f *pflag.FlagSet) {
			f.BoolP("tcp", "T", true, "display information about TCP sockets")
			f.BoolP("udp", "u", false, "display information about UDP sockets")
			f.BoolP("ip4", "4", true, "display information about IPv4 sockets")
			f.BoolP("ip6", "6", false, "display information about IPv6 sockets")
			f.BoolP("listen", "l", false, "display information about listening sockets")
			f.BoolP("numeric", "n", false, "display numeric addresses (disable hostname resolution)")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Processes ] ---------------------------------------------

		psCmd := &cobra.Command{
			Use:   consts.PsStr,
			Short: "List remote processes",
			Long:  help.GetHelpFor([]string{consts.PsStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				processes.PsCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.ProcessHelpGroup,
		}
		sliver.AddCommand(psCmd)
		Flags("", psCmd, func(f *pflag.FlagSet) {
			f.IntP("pid", "p", -1, "filter based on pid")
			f.StringP("exe", "e", "", "filter based on executable name")
			f.StringP("owner", "o", "", "filter based on owner")
			f.BoolP("print-cmdline", "c", false, "print command line arguments")
			f.BoolP("overflow", "O", false, "overflow terminal width (display truncated rows)")
			f.IntP("skip-pages", "S", 0, "skip the first n page(s)")
			f.BoolP("tree", "T", false, "print process tree")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		procdumpCmd := &cobra.Command{
			Use:   consts.ProcdumpStr,
			Short: "Dump process memory",
			Long:  help.GetHelpFor([]string{consts.ProcdumpStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				processes.ProcdumpCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.ProcessHelpGroup,
		}
		sliver.AddCommand(procdumpCmd)
		Flags("", procdumpCmd, func(f *pflag.FlagSet) {
			f.IntP("pid", "p", -1, "target pid")
			f.StringP("name", "n", "", "target process name")
			f.StringP("save", "s", "", "save to file (will overwrite if exists)")
			f.BoolP("loot", "X", false, "save output as loot")
			f.StringP("loot-name", "N", "", "name to assign when adding the memory dump to the loot store (optional)")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		terminateCmd := &cobra.Command{
			Use:   consts.TerminateStr,
			Short: "Terminate a process on the remote system",
			Long:  help.GetHelpFor([]string{consts.TerminateStr}),
			Args:  cobra.ExactArgs(1), // 	a.Uint("pid", "pid")
			RunE: func(cmd *cobra.Command, args []string) error {
				processes.TerminateCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.ProcessHelpGroup,
		}
		sliver.AddCommand(terminateCmd)
		Flags("", terminateCmd, func(f *pflag.FlagSet) {
			f.BoolP("force", "F", false, "disregard safety and kill the PID")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Privileges ] ---------------------------------------------

		runAsCmd := &cobra.Command{
			Use:   consts.RunAsStr,
			Short: "Run a new process in the context of the designated user (Windows Only)",
			Long:  help.GetHelpFor([]string{consts.RunAsStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				privilege.RunAsCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.PrivilegesHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
		}
		sliver.AddCommand(runAsCmd)
		Flags("", runAsCmd, func(f *pflag.FlagSet) {
			f.StringP("username", "u", "", "user to impersonate")
			f.StringP("process", "p", "", "process to start")
			f.StringP("args", "a", "", "arguments for the process")
			f.StringP("domain", "d", "", "domain of the user")
			f.StringP("password", "P", "", "password of the user")
			f.BoolP("show-window", "s", false, `
			Log on, but use the specified credentials on the network only. The new process uses the same token as the caller, but the system creates a new logon session within LSA, and the process uses the specified credentials as the default credentials.`)
			f.BoolP("net-only", "n", false, "use ")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		impersonateCmd := &cobra.Command{
			Use:   consts.ImpersonateStr,
			Short: "Impersonate a logged in user.",
			Long:  help.GetHelpFor([]string{consts.ImpersonateStr}),
			Args:  cobra.ExactArgs(1),
			// 	a.String("username", "name of the user account to impersonate")
			RunE: func(cmd *cobra.Command, args []string) error {
				privilege.ImpersonateCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.PrivilegesHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
		}
		sliver.AddCommand(impersonateCmd)
		Flags("", impersonateCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		revToSelfCmd := &cobra.Command{
			Use:   consts.RevToSelfStr,
			Short: "Revert to self: lose stolen Windows token",
			Long:  help.GetHelpFor([]string{consts.RevToSelfStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				privilege.RevToSelfCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.PrivilegesHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
		}
		sliver.AddCommand(revToSelfCmd)
		Flags("", revToSelfCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		getSystemCmd := &cobra.Command{
			Use:   consts.GetSystemStr,
			Short: "Spawns a new sliver session as the NT AUTHORITY\\SYSTEM user (Windows Only)",
			Long:  help.GetHelpFor([]string{consts.GetSystemStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				privilege.GetSystemCmd(cmd, con, args)
				return nil
			},
			GroupID:     consts.PrivilegesHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
		}
		sliver.AddCommand(getSystemCmd)
		Flags("", getSystemCmd, func(f *pflag.FlagSet) {
			f.StringP("process", "p", "spoolsv.exe", "SYSTEM process to inject into")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		makeTokenCmd := &cobra.Command{
			Use:         consts.MakeTokenStr,
			Short:       "Create a new Logon Session with the specified credentials",
			Long:        help.GetHelpFor([]string{consts.MakeTokenStr}),
			GroupID:     consts.PrivilegesHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
			RunE: func(cmd *cobra.Command, args []string) error {
				privilege.MakeTokenCmd(cmd, con, args)
				return nil
			},
		}
		sliver.AddCommand(makeTokenCmd)
		Flags("", makeTokenCmd, func(f *pflag.FlagSet) {
			f.StringP("username", "u", "", "username of the user to impersonate")
			f.StringP("password", "p", "", "password of the user to impersonate")
			f.StringP("domain", "d", "", "domain of the user to impersonate")
			f.StringP("logon-type", "T", "LOGON_NEW_CREDENTIALS", "logon type to use")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		chmodCmd := &cobra.Command{
			Use:   consts.ChmodStr,
			Short: "Change permissions on a file or directory",
			Long:  help.GetHelpFor([]string{consts.ChmodStr}),
			Args:  cobra.ExactArgs(2),
			// 	a.String("path", "path to the file to remove")
			// 	a.String("mode", "file permissions in octal, e.g. 0644")
			RunE: func(cmd *cobra.Command, args []string) error {
				filesystem.ChmodCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.PrivilegesHelpGroup,
		}
		sliver.AddCommand(chmodCmd)
		Flags("", chmodCmd, func(f *pflag.FlagSet) {
			f.BoolP("recursive", "r", false, "recursively change permissions on files")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		chownCmd := &cobra.Command{
			Use:   consts.ChownStr,
			Short: "Change owner on a file or directory",
			Long:  help.GetHelpFor([]string{consts.ChownStr}),
			Args:  cobra.ExactArgs(3),
			// 	a.String("path", "path to the file to remove")
			// 	a.String("uid", "User, e.g. root")
			// 	a.String("gid", "Group, e.g. root")
			RunE: func(cmd *cobra.Command, args []string) error {
				filesystem.ChownCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.PrivilegesHelpGroup,
		}
		sliver.AddCommand(chownCmd)
		Flags("", chownCmd, func(f *pflag.FlagSet) {
			f.BoolP("recursive", "r", false, "recursively change permissions on files")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		chtimesCmd := &cobra.Command{
			Use:   consts.ChtimesStr,
			Short: "Change access and modification times on a file (timestomp)",
			Long:  help.GetHelpFor([]string{consts.ChtimesStr}),
			Args:  cobra.ExactArgs(3),
			// 	a.String("path", "path to the file to remove")
			// 	a.String("atime", "Last accessed time in DateTime format, i.e. 2006-01-02 15:04:05")
			// 	a.String("mtime", "Last modified time in DateTime format, i.e. 2006-01-02 15:04:05")
			RunE: func(cmd *cobra.Command, args []string) error {
				filesystem.ChtimesCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.PrivilegesHelpGroup,
		}
		sliver.AddCommand(chtimesCmd)
		Flags("", chtimesCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Screenshot ] ---------------------------------------------

		screenshotCmd := &cobra.Command{
			Use:   consts.ScreenshotStr,
			Short: "Take a screenshot",
			Long:  help.GetHelpFor([]string{consts.ScreenshotStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				screenshot.ScreenshotCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.InfoHelpGroup,
		}
		sliver.AddCommand(screenshotCmd)
		Flags("", screenshotCmd, func(f *pflag.FlagSet) {
			f.StringP("save", "s", "", "save to file (will overwrite if exists)")
			f.BoolP("loot", "X", false, "save output as loot")
			f.StringP("name", "n", "", "name to assign loot (optional)")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Backdoor ] ---------------------------------------------

		backdoorCmd := &cobra.Command{
			Use:   consts.BackdoorStr,
			Short: "Infect a remote file with a sliver shellcode",
			Long:  help.GetHelpFor([]string{consts.BackdoorStr}),
			Args:  cobra.ExactArgs(1),
			// 	a.String("remote-file", "path to the file to backdoor")
			GroupID:     consts.ExecutionHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
			RunE: func(cmd *cobra.Command, args []string) error {
				backdoor.BackdoorCmd(cmd, con, args)
				return nil
			},
		}
		sliver.AddCommand(backdoorCmd)
		Flags("", backdoorCmd, func(f *pflag.FlagSet) {
			f.StringP("profile", "p", "", "profile to use for service binary")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// // [ DLL Hijack ] -----------------------------------------------------------------

		dllhijackCmd := &cobra.Command{
			Use:         consts.DLLHijackStr,
			Short:       "Plant a DLL for a hijack scenario",
			Long:        help.GetHelpFor([]string{consts.DLLHijackStr}),
			GroupID:     consts.ExecutionHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
			Args:        cobra.ExactArgs(1),
			// 	a.String("target-path", "Path to upload the DLL to on the remote system")
			RunE: func(cmd *cobra.Command, args []string) error {
				dllhijack.DllHijackCmd(cmd, con, args)
				return nil
			},
		}
		sliver.AddCommand(dllhijackCmd)
		Flags("", dllhijackCmd, func(f *pflag.FlagSet) {
			f.StringP("reference-path", "r", "", "Path to the reference DLL on the remote system")
			f.StringP("reference-file", "R", "", "Path to the reference DLL on the local system")
			f.StringP("file", "f", "", "Local path to the DLL to plant for the hijack")
			f.StringP("profile", "p", "", "Profile name to use as a base DLL")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Get Privs ] -----------------------------------------------------------------
		getprivsCmd := &cobra.Command{
			Use:         consts.GetPrivsStr,
			Short:       "Get current privileges (Windows only)",
			Long:        help.GetHelpFor([]string{consts.GetPrivsStr}),
			GroupID:     consts.PrivilegesHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
			RunE: func(cmd *cobra.Command, args []string) error {
				privilege.GetPrivsCmd(cmd, con, args)
				return nil
			},
		}
		sliver.AddCommand(getprivsCmd)
		Flags("", getprivsCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		//

		// [ Environment ] ---------------------------------------------

		envCmd := &cobra.Command{
			Use:   consts.EnvStr,
			Short: "List environment variables",
			Long:  help.GetHelpFor([]string{consts.EnvStr}),
			Args:  cobra.RangeArgs(0, 1),
			// 	a.String("name", "environment variable to fetch", grumble.Default(""))
			RunE: func(cmd *cobra.Command, args []string) error {
				environment.EnvGetCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.InfoHelpGroup,
		}
		sliver.AddCommand(envCmd)
		Flags("", envCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		envSetCmd := &cobra.Command{
			Use:   consts.SetStr,
			Short: "Set environment variables",
			Long:  help.GetHelpFor([]string{consts.EnvStr, consts.SetStr}),
			Args:  cobra.ExactArgs(2),
			// 	a.String("name", "environment variable name")
			// 	a.String("value", "value to assign")
			RunE: func(cmd *cobra.Command, args []string) error {
				environment.EnvSetCmd(cmd, con, args)
				return nil
			},
		}
		envCmd.AddCommand(envSetCmd)
		Flags("", envSetCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		envUnsetCmd := &cobra.Command{
			Use:   consts.UnsetStr,
			Short: "Clear environment variables",
			Long:  help.GetHelpFor([]string{consts.EnvStr, consts.UnsetStr}),
			Args:  cobra.ExactArgs(1),
			// 	a.String("name", "environment variable name")
			RunE: func(cmd *cobra.Command, args []string) error {
				environment.EnvUnsetCmd(cmd, con, args)
				return nil
			},
		}
		envCmd.AddCommand(envUnsetCmd)
		Flags("", envUnsetCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Registry ] ---------------------------------------------

		registryCmd := &cobra.Command{
			Use:         consts.RegistryStr,
			Short:       "Windows registry operations",
			Long:        help.GetHelpFor([]string{consts.RegistryStr}),
			GroupID:     consts.InfoHelpGroup,
			Annotations: HideCommand(consts.WindowsCmdsFilter),
		}
		sliver.AddCommand(registryCmd)

		registryReadCmd := &cobra.Command{
			Use:   consts.RegistryReadStr,
			Short: "Read values from the Windows registry",
			Long:  help.GetHelpFor([]string{consts.RegistryReadStr}),
			Args:  cobra.ExactArgs(1),
			// 	a.String("registry-path", "registry path")
			RunE: func(cmd *cobra.Command, args []string) error {
				registry.RegReadCmd(cmd, con, args)
				return nil
			},
		}
		registryCmd.AddCommand(registryReadCmd)
		Flags("", registryCmd, func(f *pflag.FlagSet) {
			f.StringP("hive", "H", "HKCU", "registry hive")
			f.StringP("hostname", "o", "", "remote host to read values from")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		registryWriteCmd := &cobra.Command{
			Use:   consts.RegistryWriteStr,
			Short: "Write values to the Windows registry",
			Long:  help.GetHelpFor([]string{consts.RegistryWriteStr}),
			Args:  cobra.ExactArgs(2),
			// 	a.String("registry-path", "registry path")
			// 	a.String("value", "value to write")
			RunE: func(cmd *cobra.Command, args []string) error {
				registry.RegWriteCmd(cmd, con, args)
				return nil
			},
		}
		registryCmd.AddCommand(registryWriteCmd)
		Flags("", registryWriteCmd, func(f *pflag.FlagSet) {
			f.StringP("hive", "H", "HKCU", "registry hive")
			f.StringP("hostname", "o", "", "remote host to write values to")
			f.StringP("type", "T", "string", "type of the value to write (string, dword, qword, binary). If binary, you must provide a path to a file with --path")
			f.StringP("path", "p", "", "path to the binary file to write")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		registryCreateKeyCmd := &cobra.Command{
			Use:   consts.RegistryCreateKeyStr,
			Short: "Create a registry key",
			Long:  help.GetHelpFor([]string{consts.RegistryCreateKeyStr}),
			Args:  cobra.ExactArgs(1),
			// 	a.String("registry-path", "registry path")
			RunE: func(cmd *cobra.Command, args []string) error {
				registry.RegCreateKeyCmd(cmd, con, args)
				return nil
			},
		}
		registryCmd.AddCommand(registryCreateKeyCmd)
		Flags("", registryCreateKeyCmd, func(f *pflag.FlagSet) {
			f.StringP("hive", "H", "HKCU", "registry hive")
			f.StringP("hostname", "o", "", "remote host to write values to")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		registryDeleteKeyCmd := &cobra.Command{
			Use:   consts.RegistryDeleteKeyStr,
			Short: "Remove a registry key",
			Long:  help.GetHelpFor([]string{consts.RegistryDeleteKeyStr}),
			Args:  cobra.ExactArgs(1),
			// 	a.String("registry-path", "registry path")
			RunE: func(cmd *cobra.Command, args []string) error {
				registry.RegDeleteKeyCmd(cmd, con, args)
				return nil
			},
		}
		registryCmd.AddCommand(registryDeleteKeyCmd)
		Flags("", registryDeleteKeyCmd, func(f *pflag.FlagSet) {
			f.StringP("hive", "H", "HKCU", "registry hive")
			f.StringP("hostname", "o", "", "remote host to remove value from")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		registryListSubCmd := &cobra.Command{
			Use:   consts.RegistryListSubStr,
			Short: "List the sub keys under a registry key",
			Long:  help.GetHelpFor([]string{consts.RegistryListSubStr}),
			Args:  cobra.ExactArgs(1),
			// 	a.String("registry-path", "registry path")
			RunE: func(cmd *cobra.Command, args []string) error {
				registry.RegListSubKeysCmd(cmd, con, args)
				return nil
			},
		}
		registryCmd.AddCommand(registryListSubCmd)
		Flags("", registryListSubCmd, func(f *pflag.FlagSet) {
			f.StringP("hive", "H", "HKCU", "registry hive")
			f.StringP("hostname", "o", "", "remote host to write values to")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		registryListValuesCmd := &cobra.Command{
			Use:   consts.RegistryListValuesStr,
			Short: "List the values for a registry key",
			Long:  help.GetHelpFor([]string{consts.RegistryListValuesStr}),
			Args:  cobra.ExactArgs(1),
			// 	a.String("registry-path", "registry path")
			RunE: func(cmd *cobra.Command, args []string) error {
				registry.RegListValuesCmd(cmd, con, args)
				return nil
			},
		}
		registryCmd.AddCommand(registryListValuesCmd)
		Flags("", registryListValuesCmd, func(f *pflag.FlagSet) {
			f.StringP("hive", "H", "HKCU", "registry hive")
			f.StringP("hostname", "o", "", "remote host to write values to")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Reverse Port Forwarding ] --------------------------------------------------------------

		rportfwdCmd := &cobra.Command{
			Use:   consts.RportfwdStr,
			Short: "reverse port forwardings",
			Long:  help.GetHelpFor([]string{consts.RportfwdStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				rportfwd.RportFwdListenersCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.NetworkHelpGroup,
		}
		sliver.AddCommand(rportfwdCmd)
		Flags("", rportfwdCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		rportfwdAddCmd := &cobra.Command{
			Use:   consts.AddStr,
			Short: "Add and start reverse port forwarding",
			Long:  help.GetHelpFor([]string{consts.RportfwdStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				rportfwd.StartRportFwdListenerCmd(cmd, con, args)
				return nil
			},
		}
		rportfwdCmd.AddCommand(rportfwdAddCmd)
		Flags("", rportfwdAddCmd, func(f *pflag.FlagSet) {
			f.StringP("remote", "r", "", "remote address <ip>:<port> connection is forwarded to")
			f.StringP("bind", "b", "", "bind address <ip>:<port> implants listen on")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		rportfwdRmCmd := &cobra.Command{
			Use:   consts.RmStr,
			Short: "Stop and remove reverse port forwarding",
			Long:  help.GetHelpFor([]string{consts.RportfwdStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				rportfwd.StopRportFwdListenerCmd(cmd, con, args)
				return nil
			},
		}
		rportfwdCmd.AddCommand(rportfwdRmCmd)
		Flags("", rportfwdRmCmd, func(f *pflag.FlagSet) {
			f.Uint32P("id", "i", 0, "id of portfwd to remove")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Pivots ] --------------------------------------------------------------

		pivotsCmd := &cobra.Command{
			Use:   consts.PivotsStr,
			Short: "List pivots for active session",
			Long:  help.GetHelpFor([]string{consts.PivotsStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				pivots.PivotsCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.SliverCoreHelpGroup,
		}
		sliver.AddCommand(pivotsCmd)
		Flags("", pivotsCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		namedPipeCmd := &cobra.Command{
			Use:   consts.NamedPipeStr,
			Short: "Start a named pipe pivot listener",
			Long:  help.GetHelpFor([]string{consts.PivotsStr, consts.NamedPipeStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				pivots.StartNamedPipeListenerCmd(cmd, con, args)
				return nil
			},
		}
		pivotsCmd.AddCommand(namedPipeCmd)
		Flags("", namedPipeCmd, func(f *pflag.FlagSet) {
			f.StringP("bind", "b", "", "name of the named pipe to bind pivot listener")
			f.BoolP("allow-all", "a", false, "allow all users to connect")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		tcpListenerCmd := &cobra.Command{
			Use:   consts.TCPListenerStr,
			Short: "Start a TCP pivot listener",
			Long:  help.GetHelpFor([]string{consts.PivotsStr, consts.TCPListenerStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				pivots.StartTCPListenerCmd(cmd, con, args)
				return nil
			},
		}
		pivotsCmd.AddCommand(tcpListenerCmd)
		Flags("", tcpListenerCmd, func(f *pflag.FlagSet) {
			f.StringP("bind", "b", "", "remote interface to bind pivot listener")
			f.Uint16P("lport", "l", generate.DefaultTCPPivotPort, "tcp pivot listener port")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		pivotStopCmd := &cobra.Command{
			Use:   consts.StopStr,
			Short: "Stop a pivot listener",
			Long:  help.GetHelpFor([]string{consts.PivotsStr, consts.StopStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				pivots.StopPivotListenerCmd(cmd, con, args)
				return nil
			},
		}
		pivotsCmd.AddCommand(pivotStopCmd)
		Flags("", pivotStopCmd, func(f *pflag.FlagSet) {
			f.Uint32P("id", "i", 0, "id of the pivot listener to stop")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		pivotDetailsCmd := &cobra.Command{
			Use:   consts.DetailsStr,
			Short: "Get details of a pivot listener",
			Long:  help.GetHelpFor([]string{consts.PivotsStr, consts.StopStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				pivots.PivotDetailsCmd(cmd, con, args)
				return nil
			},
		}
		pivotsCmd.AddCommand(pivotDetailsCmd)
		Flags("", pivotDetailsCmd, func(f *pflag.FlagSet) {
			f.IntP("id", "i", 0, "id of the pivot listener to get details for")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		graphCmd := &cobra.Command{
			Use:   consts.GraphStr,
			Short: "Get pivot listeners graph",
			Long:  help.GetHelpFor([]string{consts.PivotsStr, "graph"}),
			RunE: func(cmd *cobra.Command, args []string) error {
				pivots.PivotsGraphCmd(cmd, con, args)
				return nil
			},
		}
		pivotsCmd.AddCommand(graphCmd)

		// [ Portfwd ] --------------------------------------------------------------

		portfwdCmd := &cobra.Command{
			Use:   consts.PortfwdStr,
			Short: "In-band TCP port forwarding",
			Long:  help.GetHelpFor([]string{consts.PortfwdStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				portfwd.PortfwdCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.NetworkHelpGroup,
		}
		sliver.AddCommand(portfwdCmd)
		Flags("", portfwdCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		addCmd := &cobra.Command{
			Use:   consts.AddStr,
			Short: "Create a new port forwarding tunnel",
			Long:  help.GetHelpFor([]string{consts.PortfwdStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				portfwd.PortfwdAddCmd(cmd, con, args)
				return nil
			},
		}
		portfwdCmd.AddCommand(addCmd)
		Flags("", addCmd, func(f *pflag.FlagSet) {
			f.StringP("remote", "r", "", "remote target host:port (e.g., 10.0.0.1:445)")
			f.StringP("bind", "b", "127.0.0.1:8080", "bind port forward to interface")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		portfwdRmCmd := &cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove a port forwarding tunnel",
			Long:  help.GetHelpFor([]string{consts.PortfwdStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				portfwd.PortfwdRmCmd(cmd, con, args)
				return nil
			},
		}
		portfwdCmd.AddCommand(portfwdRmCmd)
		Flags("", portfwdRmCmd, func(f *pflag.FlagSet) {
			f.IntP("id", "i", 0, "id of portfwd to remove")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Socks ] --------------------------------------------------------------

		socksCmd := &cobra.Command{
			Use:   consts.Socks5Str,
			Short: "In-band SOCKS5 Proxy",
			Long:  help.GetHelpFor([]string{consts.Socks5Str}),
			RunE: func(cmd *cobra.Command, args []string) error {
				socks.SocksCmd(cmd, con, args)
				return nil
			},
			GroupID: consts.NetworkHelpGroup,
		}
		sliver.AddCommand(socksCmd)
		Flags("", socksCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		socksStartCmd := &cobra.Command{
			Use:   consts.StartStr,
			Short: "Start an in-band SOCKS5 proxy",
			Long:  help.GetHelpFor([]string{consts.Socks5Str}),
			RunE: func(cmd *cobra.Command, args []string) error {
				socks.SocksStartCmd(cmd, con, args)
				return nil
			},
		}
		socksCmd.AddCommand(socksStartCmd)
		Flags("", socksStartCmd, func(f *pflag.FlagSet) {
			f.StringP("host", "H", "127.0.0.1", "Bind a Socks5 Host")
			f.StringP("port", "P", "1081", "Bind a Socks5 Port")
			f.StringP("user", "u", "", "socks5 auth username (will generate random password)")
		})

		socksStopCmd := &cobra.Command{
			Use:   consts.StopStr,
			Short: "Stop a SOCKS5 proxy",
			Long:  help.GetHelpFor([]string{consts.Socks5Str}),
			RunE: func(cmd *cobra.Command, args []string) error {
				socks.SocksStopCmd(cmd, con, args)
				return nil
			},
		}
		socksCmd.AddCommand(socksStopCmd)
		Flags("", socksStopCmd, func(f *pflag.FlagSet) {
			f.Uint64P("id", "i", 0, "id of portfwd to remove")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ WireGuard ] --------------------------------------------------------------

		wgPortFwdCmd := &cobra.Command{
			Use:   consts.WgPortFwdStr,
			Short: "List ports forwarded by the WireGuard tun interface",
			Long:  help.GetHelpFor([]string{consts.WgPortFwdStr}),
			Run: func(cmd *cobra.Command, args []string) {
				wireguard.WGPortFwdListCmd(cmd, con, args)
			},
			GroupID:     consts.NetworkHelpGroup,
			Annotations: HideCommand(consts.WireguardCmdsFilter),
		}
		Flags("wg portforward", wgPortFwdCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		wgPortFwdAddCmd := &cobra.Command{
			Use:   consts.AddStr,
			Short: "Add a port forward from the WireGuard tun interface to a host on the target network",
			Long:  help.GetHelpFor([]string{consts.WgPortFwdStr, consts.AddStr}),
			Run: func(cmd *cobra.Command, args []string) {
				wireguard.WGPortFwdAddCmd(cmd, con, args)
			},
		}
		Flags("wg portforward", wgPortFwdAddCmd, func(f *pflag.FlagSet) {
			f.Int32P("bind", "b", 1080, "port to listen on the WireGuard tun interface")
			f.StringP("remote", "r", "", "remote target host:port (e.g., 10.0.0.1:445)")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		wgPortFwdCmd.AddCommand(wgPortFwdAddCmd)

		wgPortFwdRmCmd := &cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove a port forward from the WireGuard tun interface",
			Long:  help.GetHelpFor([]string{consts.WgPortFwdStr, consts.RmStr}),
			Args:  cobra.ExactArgs(1), // 	a.Int("id", "forwarder id")
			Run: func(cmd *cobra.Command, args []string) {
				wireguard.WGPortFwdRmCmd(cmd, con, args)
			},
		}
		Flags("wg portforward", wgPortFwdRmCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		wgPortFwdCmd.AddCommand(wgPortFwdRmCmd)
		sliver.AddCommand(wgPortFwdCmd)

		wgSocksCmd := &cobra.Command{
			Use:   consts.WgSocksStr,
			Short: "List socks servers listening on the WireGuard tun interface",
			Long:  help.GetHelpFor([]string{consts.WgSocksStr}),
			Run: func(cmd *cobra.Command, args []string) {
				wireguard.WGSocksListCmd(cmd, con, args)
			},
			GroupID:     consts.NetworkHelpGroup,
			Annotations: HideCommand(consts.WireguardCmdsFilter),
		}
		Flags("wg socks", wgSocksCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		wgSocksStartCmd := &cobra.Command{
			Use:   consts.StartStr,
			Short: "Start a socks5 listener on the WireGuard tun interface",
			Long:  help.GetHelpFor([]string{consts.WgSocksStr, consts.StartStr}),
			Run: func(cmd *cobra.Command, args []string) {
				wireguard.WGSocksStartCmd(cmd, con, args)
			},
		}
		wgSocksCmd.AddCommand(wgSocksStartCmd)
		Flags("wg socks", wgSocksStartCmd, func(f *pflag.FlagSet) {
			f.Int32P("bind", "b", 3090, "port to listen on the WireGuard tun interface")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		wgSocksStopCmd := &cobra.Command{
			Use:   consts.StopStr,
			Short: "Stop a socks5 listener on the WireGuard tun interface",
			Long:  help.GetHelpFor([]string{consts.WgSocksStr, consts.StopStr}),
			Run: func(cmd *cobra.Command, args []string) {
				wireguard.WGSocksStopCmd(cmd, con, args)
			},
			Args: cobra.ExactArgs(1), // 	a.Int("id", "forwarder id")
		}
		wgSocksCmd.AddCommand(wgSocksStopCmd)
		Flags("wg socks", wgSocksStopCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		sliver.AddCommand(wgSocksCmd)

		// [ Curse Commands ] ------------------------------------------------------------

		cursedCmd := &cobra.Command{
			Use:     consts.Cursed,
			Short:   "Chrome/electron post-exploitation tool kit (∩｀-´)⊃━☆ﾟ.*･｡ﾟ",
			Long:    help.GetHelpFor([]string{consts.Cursed}),
			GroupID: consts.ExecutionHelpGroup,
			RunE: func(cmd *cobra.Command, args []string) error {
				cursed.CursedCmd(cmd, con, args)
				return nil
			},
		}
		sliver.AddCommand(cursedCmd)
		Flags("", cursedCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		cursedRmCmd := &cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove a Curse from a process",
			Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedConsole}),
			Args:  cobra.ExactArgs(1), // 	a.Int("bind-port", "bind port of the Cursed process to stop")
			RunE: func(cmd *cobra.Command, args []string) error {
				cursed.CursedRmCmd(cmd, con, args)
				return nil
			},
		}
		cursedCmd.AddCommand(cursedRmCmd)
		Flags("", cursedRmCmd, func(f *pflag.FlagSet) {
			f.BoolP("kill", "k", false, "kill the process after removing the curse")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		cursedConsoleCmd := &cobra.Command{
			Use:   consts.CursedConsole,
			Short: "Start a JavaScript console connected to a debug target",
			Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedConsole}),
			RunE: func(cmd *cobra.Command, args []string) error {
				cursed.CursedConsoleCmd(cmd, con, args)
				return nil
			},
		}
		cursedCmd.AddCommand(cursedConsoleCmd)
		Flags("", cursedConsoleCmd, func(f *pflag.FlagSet) {
			f.IntP("remote-debugging-port", "r", 0, "remote debugging tcp port (0 = random)`")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		cursedChromeCmd := &cobra.Command{
			Use:   consts.CursedChrome,
			Short: "Automatically inject a Cursed Chrome payload into a remote Chrome extension",
			Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedChrome}),
			// 	a.StringList("args", "additional chrome cli arguments", grumble.Default([]string{}))
			RunE: func(cmd *cobra.Command, args []string) error {
				cursed.CursedChromeCmd(cmd, con, args)
				return nil
			},
		}
		cursedCmd.AddCommand(cursedChromeCmd)
		Flags("", cursedChromeCmd, func(f *pflag.FlagSet) {
			f.IntP("remote-debugging-port", "r", 0, "remote debugging tcp port (0 = random)")
			f.BoolP("restore", "R", true, "restore the user's session after process termination")
			f.StringP("exe", "e", "", "chrome/chromium browser executable path (blank string = auto)")
			f.StringP("user-data", "u", "", "user data directory (blank string = auto)")
			f.StringP("payload", "p", "", "cursed chrome payload file path (.js)")
			f.BoolP("keep-alive", "k", false, "keeps browser alive after last browser window closes")
			f.BoolP("headless", "H", false, "start browser process in headless mode")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		cursedEdgeCmd := &cobra.Command{
			Use:   consts.CursedEdge,
			Short: "Automatically inject a Cursed Chrome payload into a remote Edge extension",
			Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedEdge}),
			// 	a.StringList("args", "additional edge cli arguments", grumble.Default([]string{}))
			RunE: func(cmd *cobra.Command, args []string) error {
				cursed.CursedEdgeCmd(cmd, con, args)
				return nil
			},
		}
		cursedCmd.AddCommand(cursedEdgeCmd)
		Flags("", cursedEdgeCmd, func(f *pflag.FlagSet) {
			f.IntP("remote-debugging-port", "r", 0, "remote debugging tcp port (0 = random)")
			f.BoolP("restore", "R", true, "restore the user's session after process termination")
			f.StringP("exe", "e", "", "edge browser executable path (blank string = auto)")
			f.StringP("user-data", "u", "", "user data directory (blank string = auto)")
			f.StringP("payload", "p", "", "cursed chrome payload file path (.js)")
			f.BoolP("keep-alive", "k", false, "keeps browser alive after last browser window closes")
			f.BoolP("headless", "H", false, "start browser process in headless mode")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		cursedElectronCmd := &cobra.Command{
			Use:   consts.CursedElectron,
			Short: "Curse a remote Electron application",
			Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedElectron}),
			// 	a.StringList("args", "additional electron cli arguments", grumble.Default([]string{}))
			RunE: func(cmd *cobra.Command, args []string) error {
				cursed.CursedElectronCmd(cmd, con, args)
				return nil
			},
		}
		cursedCmd.AddCommand(cursedElectronCmd)
		Flags("", cursedElectronCmd, func(f *pflag.FlagSet) {
			f.StringP("exe", "e", "", "remote electron executable absolute path")
			f.IntP("remote-debugging-port", "r", 0, "remote debugging tcp port (0 = random)")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		CursedCookiesCmd := &cobra.Command{
			Use:   consts.CursedCookies,
			Short: "Dump all cookies from cursed process",
			Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedCookies}),
			RunE: func(cmd *cobra.Command, args []string) error {
				cursed.CursedCookiesCmd(cmd, con, args)
				return nil
			},
		}
		cursedCmd.AddCommand(CursedCookiesCmd)
		Flags("", CursedCookiesCmd, func(f *pflag.FlagSet) {
			f.StringP("save", "s", "", "save to file")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		cursedScreenshotCmd := &cobra.Command{
			Use:   consts.ScreenshotStr,
			Short: "Take a screenshot of a cursed process debug target",
			Long:  help.GetHelpFor([]string{consts.Cursed, consts.ScreenshotStr}),
			RunE: func(cmd *cobra.Command, args []string) error {
				cursed.CursedScreenshotCmd(cmd, con, args)
				return nil
			},
		}
		cursedCmd.AddCommand(cursedScreenshotCmd)
		Flags("", cursedScreenshotCmd, func(f *pflag.FlagSet) {
			f.Int64P("quality", "q", 100, "screenshot quality (1 - 100)")
			f.StringP("save", "s", "", "save to file")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		con.ExposeCommands()
		// if client.Client != nil {
		// 	client.Client.ExposeCommands()
		// }

		return sliver
	}

	return sliverCommands
}
