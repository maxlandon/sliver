package command

import (
	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/command/alias"
	"github.com/bishopfox/sliver/client/command/extensions"
	"github.com/bishopfox/sliver/client/command/help"
	"github.com/bishopfox/sliver/client/command/sessions"
	"github.com/bishopfox/sliver/client/console"
	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// SliverCommands returns all commands bound to the implant menu.
func SliverCommands() *cobra.Command {
	sliver := &cobra.Command{
		Short: "Implant commands",
	}

	groups := []*cobra.Group{
		{ID: consts.GenericHelpGroup, Title: consts.GenericHelpGroup},
		{ID: consts.SliverHelpGroup, Title: consts.SliverHelpGroup},
		{ID: consts.AliasHelpGroup, Title: consts.AliasHelpGroup},
		{ID: consts.ExtensionHelpGroup, Title: consts.ExtensionHelpGroup},
		{ID: consts.SliverWinHelpGroup, Title: consts.SliverWinHelpGroup},
	}
	sliver.AddGroup(groups...)

	// Load Aliases
	aliasManifests := assets.GetInstalledAliasManifests()
	n := 0
	for _, manifest := range aliasManifests {
		_, err := alias.LoadAlias(manifest, sliver)
		if err != nil {
			console.Client.PrintErrorf("Failed to load alias: %s\n", err)
			continue
		}
		n++
	}
	// if 0 < n {
	// 	if n == 1 {
	// 		log.Infof("Loaded %d alias from disk\n", n)
	// 	} else {
	// 		log.Infof("Loaded %d aliases from disk\n", n)
	// 	}
	// }

	// Load Extensions
	extensionManifests := assets.GetInstalledExtensionManifests()
	n = 0
	for _, manifest := range extensionManifests {
		ext, err := extensions.LoadExtensionManifest(manifest)
		// Absorb error in case there's no extensions manifest
		if err != nil {
			console.Client.PrintErrorf("Failed to load extension: %s\n", err)
			continue
		}
		extensions.ExtensionRegisterCommand(ext, sliver)
		n++
	}
	// if 0 < n {
	// 	log.Infof("Loaded %d extension(s) from disk\n", n)
	// }
	// .App.SetPrintHelp(help.HelpCmd(con)) // Responsible for display long-form help templates, etc.

	// [ Reconfig ] ---------------------------------------------------------------

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ReconfigStr,
		Short: "Reconfigure the active beacon/session",
		Long:  help.GetHelpFor([]string{consts.ReconfigStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("r", "reconnect-interval", "", "reconnect interval for implant")
		// 	f.String("i", "beacon-interval", "", "beacon callback interval")
		// 	f.String("j", "beacon-jitter", "", "beacon callback jitter (random up to)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	reconfig.ReconfigCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.RenameStr,
		Short: "Rename the active beacon/session",
		Long:  help.GetHelpFor([]string{consts.RenameStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("n", "name", "", "change implant name to")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	reconfig.RenameCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	// [ Sessions ] --------------------------------------------------------------

	// sessionsCmd := &cobra.Command{
	// 	Use:     consts.SessionsStr,
	// 	Short:     "Session management",
	// 	Long: help.GetHelpFor([]string{consts.SessionsStr}),
	// 	Flags: func(f *grumble.Flags) {
	// 		f.String("i", "interact", "", "interact with a session")
	// 		f.String("k", "kill", "", "kill the designated session")
	// 		f.Bool("K", "kill-all", false, "kill all the sessions")
	// 		f.Bool("C", "clean", false, "clean out any sessions marked as [DEAD]")
	// 		f.Bool("F", "force", false, "force session action without waiting for results")
	//
	// 		f.String("f", "filter", "", "filter sessions by substring")
	// 		f.String("e", "filter-re", "", "filter sessions by regular expression")
	//
	// 		f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
	// 	},
	// 	Run: func(ctx *grumble.Context) error {
	// 		con.Println()
	// 		sessions.SessionsCmd(ctx, con)
	// 		con.Println()
	// 		return nil
	// 	},
	// 	GroupID: consts.GenericHelpGroup,
	// }
	// sessionsCmd.AddCommand(&cobra.Command{
	// 	Use:     consts.PruneStr,
	// 	Short:     "Kill all stale/dead sessions",
	// 	Long: help.GetHelpFor([]string{consts.SessionsStr, consts.PruneStr}),
	// 	Flags: func(f *grumble.Flags) {
	// 		f.Bool("F", "force", false, "Force the killing of stale/dead sessions")
	//
	// 		f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
	// 	},
	// 	Run: func(ctx *grumble.Context) error {
	// 		con.Println()
	// 		sessions.SessionsPruneCmd(ctx, con)
	// 		con.Println()
	// 		return nil
	// 	},
	// 	GroupID: consts.SliverHelpGroup,
	// })
	// sliver.AddCommand(sessionsCmd)

	backgroundCmd := &cobra.Command{
		Use:     consts.BackgroundStr,
		Short:   "Background an active session",
		Long:    help.GetHelpFor([]string{consts.BackgroundStr}),
		Run:     sessions.BackgroundCmd,
		GroupID: consts.GenericHelpGroup,
	}
	Flags("use", backgroundCmd, func(f *pflag.FlagSet) {
		f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
	})
	sliver.AddCommand(backgroundCmd)

	sliver.AddCommand(&cobra.Command{
		Use:   consts.KillStr,
		Short: "Kill a session",
		Long:  help.GetHelpFor([]string{consts.KillStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	kill.KillCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("F", "force", false, "Force kill,  does not clean up")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		GroupID: consts.SliverHelpGroup,
	})

	openSessionCmd := &cobra.Command{
		Use:   consts.InteractiveStr,
		Short: "Task a beacon to open an interactive session (Beacon only)",
		Long:  help.GetHelpFor([]string{consts.InteractiveStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("m", "mtls", "", "mtls connection strings")
		// 	f.String("g", "wg", "", "wg connection strings")
		// 	f.String("b", "http", "", "http(s) connection strings")
		// 	f.String("n", "dns", "", "dns connection strings")
		// 	f.String("p", "named-pipe", "", "namedpipe connection strings")
		// 	f.String("i", "tcp-pivot", "", "tcppivot connection strings")
		//
		// 	f.String("d", "delay", "0s", "delay opening the session (after checkin) for a given period of time")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	sessions.InteractiveCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	}
	sliver.AddCommand(openSessionCmd)

	// [ Close ] --------------------------------------------------------------
	closeSessionCmd := &cobra.Command{
		Use:   consts.CloseStr,
		Short: "Close an interactive session without killing the remote process",
		Long:  help.GetHelpFor([]string{consts.CloseStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	sessions.CloseSessionCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.GenericHelpGroup,
	}
	sliver.AddCommand(closeSessionCmd)

	// [ Tasks ] --------------------------------------------------------------

	tasksCmd := &cobra.Command{
		Use:   consts.TasksStr,
		Short: "Beacon task management",
		Long:  help.GetHelpFor([]string{consts.TasksStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("O", "overflow", false, "overflow terminal width (display truncated rows)")
		// 	f.Int("S", "skip-pages", 0, "skip the first n page(s)")
		// 	f.String("f", "filter", "", "filter based on task type (case-insensitive prefix matching)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	tasks.TasksCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.GenericHelpGroup,
	}
	tasksCmd.AddCommand(&cobra.Command{
		Use:   consts.FetchStr,
		Short: "Fetch the details of a beacon task",
		Long:  help.GetHelpFor([]string{consts.TasksStr, consts.FetchStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("O", "overflow", false, "overflow terminal width (display truncated rows)")
		// 	f.Int("S", "skip-pages", 0, "skip the first n page(s)")
		// 	f.String("f", "filter", "", "filter based on task type (case-insensitive prefix matching)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("id", "beacon task ID", grumble.Default(""))
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	tasks.TasksFetchCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.GenericHelpGroup,
	})
	tasksCmd.AddCommand(&cobra.Command{
		Use:   consts.CancelStr,
		Short: "Cancel a pending beacon task",
		Long:  help.GetHelpFor([]string{consts.TasksStr, consts.CancelStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("O", "overflow", false, "overflow terminal width (display truncated rows)")
		// 	f.Int("S", "skip-pages", 0, "skip the first n page(s)")
		// 	f.String("f", "filter", "", "filter based on task type (case-insensitive prefix matching)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("id", "beacon task ID", grumble.Default(""))
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	tasks.TasksCancelCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.GenericHelpGroup,
	})
	sliver.AddCommand(tasksCmd)

	// [ Info ] --------------------------------------------------------------

	sliver.AddCommand(&cobra.Command{
		Use:   consts.InfoStr,
		Short: "Get info about session",
		Long:  help.GetHelpFor([]string{consts.InfoStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("session", "session ID", grumble.Default(""))
		// },
		// Completer: func(prefix string, args []string) []string {
		// 	return use.BeaconAndSessionIDCompleter(prefix, args, con)
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	info.InfoCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.PingStr,
		Short: "Send round trip message to implant (does not use ICMP)",
		Long:  help.GetHelpFor([]string{consts.PingStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	info.PingCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.GetPIDStr,
		Short: "Get session pid",
		Long:  help.GetHelpFor([]string{consts.GetPIDStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	info.PIDCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.GetUIDStr,
		Short: "Get session process UID",
		Long:  help.GetHelpFor([]string{consts.GetUIDStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	info.UIDCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.GetGIDStr,
		Short: "Get session process GID",
		Long:  help.GetHelpFor([]string{consts.GetGIDStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	info.GIDCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.WhoamiStr,
		Short: "Get session user execution context",
		Long:  help.GetHelpFor([]string{consts.WhoamiStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	info.WhoamiCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	// [ Shell ] --------------------------------------------------------------

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ShellStr,
		Short: "Start an interactive shell",
		Long:  help.GetHelpFor([]string{consts.ShellStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("y", "no-pty", false, "disable use of pty on macos/linux")
		// 	f.String("s", "shell-path", "", "path to shell interpreter")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	shell.ShellCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	// [ Exec ] --------------------------------------------------------------

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ExecuteStr,
		Short: "Execute a program on the remote system",
		Long:  help.GetHelpFor([]string{consts.ExecuteStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("T", "token", false, "execute command with current token (windows only)")
		// 	f.Bool("o", "output", false, "capture command output")
		// 	f.Bool("s", "save", false, "save output to a file")
		// 	f.Bool("X", "loot", false, "save output as loot")
		// 	f.Bool("S", "ignore-stderr", false, "don't print STDERR output")
		// 	f.String("O", "stdout", "", "remote path to redirect STDOUT to")
		// 	f.String("E", "stderr", "", "remote path to redirect STDERR to")
		// 	f.String("n", "name", "", "name to assign loot (optional)")
		// 	f.Uint("P", "ppid", 0, "parent process id (optional, Windows only)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("command", "command to execute")
		// 	a.StringList("arguments", "arguments to the command")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	exec.ExecuteCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ExecuteAssemblyStr,
		Short: "Loads and executes a .NET assembly in a child process (Windows Only)",
		Long:  help.GetHelpFor([]string{consts.ExecuteAssemblyStr}),
		// Args: func(a *grumble.Args) {
		// 	a.String("filepath", "path the assembly file")
		// 	a.StringList("arguments", "arguments to pass to the assembly entrypoint", grumble.Default([]string{}))
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.String("p", "process", "notepad.exe", "hosting process to inject into")
		// 	f.String("m", "method", "", "Optional method (a method is required for a .NET DLL)")
		// 	f.String("c", "class", "", "Optional class name (required for .NET DLL)")
		// 	f.String("d", "app-domain", "", "AppDomain name to create for .NET assembly. Generated randomly if not set.")
		// 	f.String("a", "arch", "x84", "Assembly target architecture: x86, x64, x84 (x86+x64)")
		// 	f.Bool("i", "in-process", false, "Run in the current sliver process")
		// 	f.String("r", "runtime", "", "Runtime to use for running the assembly (only supported when used with --in-process)")
		// 	f.Bool("s", "save", false, "save output to file")
		// 	f.Bool("X", "loot", false, "save output as loot")
		// 	f.String("n", "name", "", "name to assign loot (optional)")
		// 	f.Uint("P", "ppid", 0, "parent process id (optional)")
		// 	f.String("A", "process-arguments", "", "arguments to pass to the hosting process")
		// 	f.Bool("M", "amsi-bypass", false, "Bypass AMSI on Windows (only supported when used with --in-process)")
		// 	f.Bool("E", "etw-bypass", false, "Bypass ETW on Windows (only supported when used with --in-process)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	exec.ExecuteAssemblyCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverWinHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ExecuteShellcodeStr,
		Short: "Executes the given shellcode in the sliver process",
		Long:  help.GetHelpFor([]string{consts.ExecuteShellcodeStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	exec.ExecuteShellcodeCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("filepath", "path the shellcode file")
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("r", "rwx-pages", false, "Use RWX permissions for memory pages")
		// 	f.Uint("p", "pid", 0, "Pid of process to inject into (0 means injection into ourselves)")
		// 	f.String("n", "process", `c:\windows\system32\notepad.exe`, "Process to inject into when running in interactive mode")
		// 	f.Bool("i", "interactive", false, "Inject into a new process and interact with it")
		// 	f.Bool("S", "shikata-ga-nai", false, "encode shellcode using shikata ga nai prior to execution")
		// 	f.String("A", "architecture", "amd64", "architecture of the shellcode: 386, amd64 (used with --shikata-ga-nai flag)")
		// 	f.Int("I", "iterations", 1, "number of encoding iterations (used with --shikata-ga-nai flag)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.SideloadStr,
		Short: "Load and execute a shared object (shared library/DLL) in a remote process",
		Long:  help.GetHelpFor([]string{consts.SideloadStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("e", "entry-point", "", "Entrypoint for the DLL (Windows only)")
		// 	f.String("p", "process", `c:\windows\system32\notepad.exe`, "Path to process to host the shellcode")
		// 	f.Bool("w", "unicode", false, "Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)")
		// 	f.Bool("s", "save", false, "save output to file")
		// 	f.Bool("X", "loot", false, "save output as loot")
		// 	f.String("n", "name", "", "name to assign loot (optional)")
		// 	f.Bool("k", "keep-alive", false, "don't terminate host process once the execution completes")
		// 	f.Uint("P", "ppid", 0, "parent process id (optional)")
		// 	f.String("A", "process-arguments", "", "arguments to pass to the hosting process")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("filepath", "path the shared library file")
		// 	a.StringList("args", "arguments for the binary", grumble.Default([]string{}))
		// },
		GroupID: consts.SliverHelpGroup,
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	exec.SideloadCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.SpawnDllStr,
		Short: "Load and execute a Reflective DLL in a remote process",
		Long:  help.GetHelpFor([]string{consts.SpawnDllStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("p", "process", `c:\windows\system32\notepad.exe`, "Path to process to host the shellcode")
		// 	f.String("e", "export", "ReflectiveLoader", "Entrypoint of the Reflective DLL")
		// 	f.Bool("s", "save", false, "save output to file")
		// 	f.Bool("X", "loot", false, "save output as loot")
		// 	f.String("n", "name", "", "name to assign loot (optional)")
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.Bool("k", "keep-alive", false, "don't terminate host process once the execution completes")
		// 	f.Uint("P", "ppid", 0, "parent process id (optional)")
		// 	f.String("A", "process-arguments", "", "arguments to pass to the hosting process")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("filepath", "path the DLL file")
		// 	a.StringList("arguments", "arguments to pass to the DLL entrypoint", grumble.Default([]string{}))
		// },
		GroupID: consts.SliverWinHelpGroup,
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	exec.SpawnDllCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.MigrateStr,
		Short: "Migrate into a remote process",
		Long:  help.GetHelpFor([]string{consts.MigrateStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	exec.MigrateCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Args: func(a *grumble.Args) {
		// 	a.Uint("pid", "pid")
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("S", "disable-sgn", true, "disable shikata ga nai shellcode encoder")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		GroupID: consts.SliverWinHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.MsfStr,
		Short: "Execute an MSF payload in the current process",
		Long:  help.GetHelpFor([]string{consts.MsfStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("m", "payload", "meterpreter_reverse_https", "msf payload")
		// 	f.String("L", "lhost", "", "listen host")
		// 	f.Int("l", "lport", 4444, "listen port")
		// 	f.String("e", "encoder", "", "msf encoder")
		// 	f.Int("i", "iterations", 1, "iterations of the encoder")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	exec.MsfCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.MsfInjectStr,
		Short: "Inject an MSF payload into a process",
		Long:  help.GetHelpFor([]string{consts.MsfInjectStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("p", "pid", -1, "pid to inject into")
		// 	f.String("m", "payload", "meterpreter_reverse_https", "msf payload")
		// 	f.String("L", "lhost", "", "listen host")
		// 	f.Int("l", "lport", 4444, "listen port")
		// 	f.String("e", "encoder", "", "msf encoder")
		// 	f.Int("i", "iterations", 1, "iterations of the encoder")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	exec.MsfInjectCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.PsExecStr,
		Short: "Start a sliver service on a remote target",
		Long:  help.GetHelpFor([]string{consts.PsExecStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.String("s", "service-name", "Sliver", "name that will be used to register the service")
		// 	f.String("d", "service-description", "Sliver implant", "description of the service")
		// 	f.String("p", "profile", "", "profile to use for service binary")
		// 	f.String("b", "binpath", "c:\\windows\\temp", "directory to which the executable will be uploaded")
		// 	f.String("c", "custom-exe", "", "custom service executable to use instead of generating a new Sliver")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	exec.PsExecCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("hostname", "hostname")
		// },
		GroupID: consts.SliverWinHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.SSHStr,
		Short: "Run a SSH command on a remote host",
		Long:  help.GetHelpFor([]string{consts.SSHStr}),
		// Args: func(a *grumble.Args) {
		// 	a.String("hostname", "remote host to SSH to")
		// 	a.StringList("command", "command line with arguments")
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.Uint("p", "port", 22, "SSH port")
		// 	f.String("i", "private-key", "", "path to private key file")
		// 	f.String("P", "password", "", "SSH user password")
		// 	f.String("l", "login", "", "username to use to connect")
		// 	f.Bool("s", "skip-loot", false, "skip the prompt to use loot credentials")
		// 	f.String("c", "kerberos-config", "/etc/krb5.conf", "path to remote Kerberos config file")
		// 	f.String("k", "kerberos-keytab", "", "path to Kerberos keytab file")
		// 	f.String("r", "kerberos-realm", "", "Kerberos realm")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	exec.SSHCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	// [ Filesystem ] ---------------------------------------------

	sliver.AddCommand(&cobra.Command{
		Use:   consts.MvStr,
		Short: "Move or rename a file",
		Long:  help.GetHelpFor([]string{consts.MvStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("src", "path to source file")
		// 	a.String("dst", "path to dest file")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	err := filesystem.MvCmd(ctx, con)
		// 	return err
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.LsStr,
		Short: "List current directory",
		Long:  help.GetHelpFor([]string{consts.LsStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.Bool("r", "reverse", false, "reverse sort order")
		// 	f.Bool("m", "modified", false, "sort by modified time")
		// 	f.Bool("s", "size", false, "sort by size")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("path", "path to enumerate", grumble.Default("."))
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.LsCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.RmStr,
		Short: "Remove a file or directory",
		Long:  help.GetHelpFor([]string{consts.RmStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("r", "recursive", false, "recursively remove files")
		// 	f.Bool("F", "force", false, "ignore safety and forcefully remove files")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("path", "path to the file to remove")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.RmCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.MkdirStr,
		Short: "Make a directory",
		Long:  help.GetHelpFor([]string{consts.MkdirStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("path", "path to the directory to create")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.MkdirCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.CdStr,
		Short: "Change directory",
		Long:  help.GetHelpFor([]string{consts.CdStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("path", "path to the directory", grumble.Default("."))
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.CdCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.PwdStr,
		Short: "Print working directory",
		Long:  help.GetHelpFor([]string{consts.PwdStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.PwdCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.CatStr,
		Short: "Dump file to stdout",
		Long:  help.GetHelpFor([]string{consts.CatStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.Bool("c", "colorize-output", false, "colorize output")
		// 	f.Bool("x", "hex", false, "display as a hex dump")
		// 	f.Bool("X", "loot", false, "save output as loot")
		// 	f.String("n", "name", "", "name to assign loot (optional)")
		// 	f.String("T", "type", "", "force a specific loot type (file/cred) if looting (optional)")
		// 	f.String("F", "file-type", "", "force a specific file type (binary/text) if looting (optional)")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("path", "path to the file to print")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.CatCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.DownloadStr,
		Short: "Download a file",
		Long:  help.GetHelpFor([]string{consts.DownloadStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		//
		// 	f.Bool("X", "loot", false, "save output as loot")
		// 	f.String("T", "type", "", "force a specific loot type (file/cred) if looting")
		// 	f.String("F", "file-type", "", "force a specific file type (binary/text) if looting")
		// 	f.String("n", "name", "", "name to assign the download if looting")
		// 	f.Bool("r", "recurse", false, "recursively download all files in a directory")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("remote-path", "path to the file or directory to download")
		// 	a.String("local-path", "local path where the downloaded file will be saved", grumble.Default("."))
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.DownloadCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.UploadStr,
		Short: "Upload a file",
		Long:  help.GetHelpFor([]string{consts.UploadStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		//
		// 	f.Bool("i", "ioc", false, "track uploaded file as an ioc")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("local-path", "local path to the file to upload")
		// 	a.String("remote-path", "path to the file or directory to upload to", grumble.Default(""))
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.UploadCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	// [ Network ] ---------------------------------------------

	sliver.AddCommand(&cobra.Command{
		Use:   consts.IfconfigStr,
		Short: "View network interface configurations",
		Long:  help.GetHelpFor([]string{consts.IfconfigStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("A", "all", false, "show all network adapters (default only shows IPv4)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	network.IfconfigCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.NetstatStr,
		Short: "Print network connection information",
		Long:  help.GetHelpFor([]string{consts.NetstatStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	network.NetstatCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("T", "tcp", true, "display information about TCP sockets")
		// 	f.Bool("u", "udp", false, "display information about UDP sockets")
		// 	f.Bool("4", "ip4", true, "display information about IPv4 sockets")
		// 	f.Bool("6", "ip6", false, "display information about IPv6 sockets")
		// 	f.Bool("l", "listen", false, "display information about listening sockets")
		// 	f.Bool("n", "numeric", false, "display numeric addresses (disable hostname resolution)")
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		GroupID: consts.SliverHelpGroup,
	})

	// [ Processes ] ---------------------------------------------

	sliver.AddCommand(&cobra.Command{
		Use:   consts.PsStr,
		Short: "List remote processes",
		Long:  help.GetHelpFor([]string{consts.PsStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("p", "pid", -1, "filter based on pid")
		// 	f.String("e", "exe", "", "filter based on executable name")
		// 	f.String("o", "owner", "", "filter based on owner")
		// 	f.Bool("c", "print-cmdline", false, "print command line arguments")
		// 	f.Bool("O", "overflow", false, "overflow terminal width (display truncated rows)")
		// 	f.Int("S", "skip-pages", 0, "skip the first n page(s)")
		// 	f.Bool("T", "tree", false, "print process tree")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	processes.PsCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ProcdumpStr,
		Short: "Dump process memory",
		Long:  help.GetHelpFor([]string{consts.ProcdumpStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("p", "pid", -1, "target pid")
		// 	f.String("n", "name", "", "target process name")
		// 	f.String("s", "save", "", "save to file (will overwrite if exists)")
		// 	f.Bool("X", "loot", false, "save output as loot")
		// 	f.String("N", "loot-name", "", "name to assign when adding the memory dump to the loot store (optional)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	processes.ProcdumpCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.TerminateStr,
		Short: "Terminate a process on the remote system",
		Long:  help.GetHelpFor([]string{consts.TerminateStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	processes.TerminateCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Args: func(a *grumble.Args) {
		// 	a.Uint("pid", "pid")
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("F", "force", false, "disregard safety and kill the PID")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		GroupID: consts.SliverHelpGroup,
	})

	// [ Privileges ] ---------------------------------------------

	sliver.AddCommand(&cobra.Command{
		Use:   consts.RunAsStr,
		Short: "Run a new process in the context of the designated user (Windows Only)",
		Long:  help.GetHelpFor([]string{consts.RunAsStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("u", "username", "", "user to impersonate")
		// 	f.String("p", "process", "", "process to start")
		// 	f.String("a", "args", "", "arguments for the process")
		// 	f.String("d", "domain", "", "domain of the user")
		// 	f.String("P", "password", "", "password of the user")
		// 	f.Bool("s", "show-window", false, `
		// 	Log on, but use the specified credentials on the network only. The new process uses the same token as the caller, but the system creates a new logon session within LSA, and the process uses the specified credentials as the default credentials.`)
		// 	f.Bool("n", "net-only", false, "use ")
		// 	f.Int("t", "timeout", 30, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	privilege.RunAsCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverWinHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ImpersonateStr,
		Short: "Impersonate a logged in user.",
		Long:  help.GetHelpFor([]string{consts.ImpersonateStr}),
		// Args: func(a *grumble.Args) {
		// 	a.String("username", "name of the user account to impersonate")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	privilege.ImpersonateCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", 30, "command timeout in seconds")
		// },
		GroupID: consts.SliverWinHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.RevToSelfStr,
		Short: "Revert to self: lose stolen Windows token",
		Long:  help.GetHelpFor([]string{consts.RevToSelfStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	privilege.RevToSelfCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", 30, "command timeout in seconds")
		// },
		GroupID: consts.SliverWinHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.GetSystemStr,
		Short: "Spawns a new sliver session as the NT AUTHORITY\\SYSTEM user (Windows Only)",
		Long:  help.GetHelpFor([]string{consts.GetSystemStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("p", "process", "spoolsv.exe", "SYSTEM process to inject into")
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	privilege.GetSystemCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverWinHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.MakeTokenStr,
		Short: "Create a new Logon Session with the specified credentials",
		Long:  help.GetHelpFor([]string{consts.MakeTokenStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("u", "username", "", "username of the user to impersonate")
		// 	f.String("p", "password", "", "password of the user to impersonate")
		// 	f.String("d", "domain", "", "domain of the user to impersonate")
		// 	f.String("T", "logon-type", "LOGON_NEW_CREDENTIALS", "logon type to use")
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		GroupID: consts.SliverWinHelpGroup,
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	privilege.MakeTokenCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ChmodStr,
		Short: "Change permissions on a file or directory",
		Long:  help.GetHelpFor([]string{consts.ChmodStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("r", "recursive", false, "recursively change permissions on files")
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("path", "path to the file to remove")
		// 	a.String("mode", "file permissions in octal, e.g. 0644")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.ChmodCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ChownStr,
		Short: "Change owner on a file or directory",
		Long:  help.GetHelpFor([]string{consts.ChownStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Bool("r", "recursive", false, "recursively change permissions on files")
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("path", "path to the file to remove")
		// 	a.String("uid", "User, e.g. root")
		// 	a.String("gid", "Group, e.g. root")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.ChownCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ChtimesStr,
		Short: "Change access and modification times on a file (timestomp)",
		Long:  help.GetHelpFor([]string{consts.ChtimesStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("path", "path to the file to remove")
		// 	a.String("atime", "Last accessed time in DateTime format, i.e. 2006-01-02 15:04:05")
		// 	a.String("mtime", "Last modified time in DateTime format, i.e. 2006-01-02 15:04:05")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	filesystem.ChtimesCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	// [ Screenshot ] ---------------------------------------------

	sliver.AddCommand(&cobra.Command{
		Use:   consts.ScreenshotStr,
		Short: "Take a screenshot",
		Long:  help.GetHelpFor([]string{consts.ScreenshotStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("s", "save", "", "save to file (will overwrite if exists)")
		// 	f.Bool("X", "loot", false, "save output as loot")
		// 	f.String("n", "name", "", "name to assign loot (optional)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	screenshot.ScreenshotCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	})

	// [ Backdoor ] ---------------------------------------------

	sliver.AddCommand(&cobra.Command{
		Use:   consts.BackdoorStr,
		Short: "Infect a remote file with a sliver shellcode",
		Long:  help.GetHelpFor([]string{consts.BackdoorStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.String("p", "profile", "", "profile to use for service binary")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("remote-file", "path to the file to backdoor")
		// },
		GroupID: consts.SliverWinHelpGroup,
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	backdoor.BackdoorCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})

	// [ Environment ] ---------------------------------------------

	envCmd := &cobra.Command{
		Use:   consts.EnvStr,
		Short: "List environment variables",
		Long:  help.GetHelpFor([]string{consts.EnvStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("name", "environment variable to fetch", grumble.Default(""))
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	environment.EnvGetCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.GenericHelpGroup,
	}
	envCmd.AddCommand(&cobra.Command{
		Use:   consts.SetStr,
		Short: "Set environment variables",
		Long:  help.GetHelpFor([]string{consts.EnvStr, consts.SetStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("name", "environment variable name")
		// 	a.String("value", "value to assign")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	environment.EnvSetCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.GenericHelpGroup,
	})
	envCmd.AddCommand(&cobra.Command{
		Use:   consts.UnsetStr,
		Short: "Clear environment variables",
		Long:  help.GetHelpFor([]string{consts.EnvStr, consts.UnsetStr}),
		// Args: func(a *grumble.Args) {
		// 	a.String("name", "environment variable name")
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	environment.EnvUnsetCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.GenericHelpGroup,
	})
	sliver.AddCommand(envCmd)

	// [ Registry ] ---------------------------------------------

	registryCmd := &cobra.Command{
		Use:   consts.RegistryStr,
		Short: "Windows registry operations",
		Long:  help.GetHelpFor([]string{consts.RegistryStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	return nil
		// },
		GroupID: consts.SliverWinHelpGroup,
	}
	registryCmd.AddCommand(&cobra.Command{
		Use:   consts.RegistryReadStr,
		Short: "Read values from the Windows registry",
		Long:  help.GetHelpFor([]string{consts.RegistryReadStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	registry.RegReadCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("registry-path", "registry path")
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.String("H", "hive", "HKCU", "registry hive")
		// 	f.String("o", "hostname", "", "remote host to read values from")
		// },
		// GroupID: consts.SliverWinHelpGroup,
	})
	registryCmd.AddCommand(&cobra.Command{
		Use:   consts.RegistryWriteStr,
		Short: "Write values to the Windows registry",
		Long:  help.GetHelpFor([]string{consts.RegistryWriteStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	registry.RegWriteCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Args: func(a *grumble.Args) {
		// 	a.String("registry-path", "registry path")
		// 	a.String("value", "value to write")
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.String("H", "hive", "HKCU", "registry hive")
		// 	f.String("o", "hostname", "", "remote host to write values to")
		// 	f.String("T", "type", "string", "type of the value to write (string, dword, qword, binary). If binary, you must provide a path to a file with --path")
		// 	f.String("p", "path", "", "path to the binary file to write")
		// },
		// GroupID: consts.SliverWinHelpGroup,
	})
	registryCmd.AddCommand(&cobra.Command{
		Use:   consts.RegistryCreateKeyStr,
		Short: "Create a registry key",
		Long:  help.GetHelpFor([]string{consts.RegistryCreateKeyStr}),
		// Args: func(a *grumble.Args) {
		// 	a.String("registry-path", "registry path")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	registry.RegCreateKeyCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.String("H", "hive", "HKCU", "registry hive")
		// 	f.String("o", "hostname", "", "remote host to write values to")
		// },
	})
	registryCmd.AddCommand(&cobra.Command{
		Use:   consts.RegistryDeleteKeyStr,
		Short: "Remove a registry key",
		Long:  help.GetHelpFor([]string{consts.RegistryDeleteKeyStr}),
		// Args: func(a *grumble.Args) {
		// 	a.String("registry-path", "registry path")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	registry.RegDeleteKeyCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.String("H", "hive", "HKCU", "registry hive")
		// 	f.String("o", "hostname", "", "remote host to remove value from")
		// },
	})
	registryCmd.AddCommand(&cobra.Command{
		Use:   consts.RegistryListSubStr,
		Short: "List the sub keys under a registry key",
		Long:  help.GetHelpFor([]string{consts.RegistryListSubStr}),
		// Args: func(a *grumble.Args) {
		// 	a.String("registry-path", "registry path")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	registry.RegListSubKeysCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.String("H", "hive", "HKCU", "registry hive")
		// 	f.String("o", "hostname", "", "remote host to write values to")
		// },
	})

	registryCmd.AddCommand(&cobra.Command{
		Use:   consts.RegistryListValuesStr,
		Short: "List the values for a registry key",
		Long:  help.GetHelpFor([]string{consts.RegistryListValuesStr}),
		// Args: func(a *grumble.Args) {
		// 	a.String("registry-path", "registry path")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	registry.RegListValuesCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.String("H", "hive", "HKCU", "registry hive")
		// 	f.String("o", "hostname", "", "remote host to write values to")
		// },
	})
	sliver.AddCommand(registryCmd)

	// [ Reverse Port Forwarding ] --------------------------------------------------------------

	rportfwdCmd := &cobra.Command{
		Use:   consts.RportfwdStr,
		Short: "reverse port forwardings",
		Long:  help.GetHelpFor([]string{consts.RportfwdStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	rportfwd.RportFwdListenersCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	}
	rportfwdCmd.AddCommand(&cobra.Command{
		Use:   consts.AddStr,
		Short: "Add and start reverse port forwarding",
		Long:  help.GetHelpFor([]string{consts.RportfwdStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	rportfwd.StartRportFwdListenerCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.String("r", "remote", "", "remote address <ip>:<port> connection is forwarded to")
		// 	f.String("b", "bind", "", "bind address <ip>:<port> implants listen on")
		// },
		// GroupID: consts.SliverWinHelpGroup,
	})
	rportfwdCmd.AddCommand(&cobra.Command{
		Use:   consts.RmStr,
		Short: "Stop and remove reverse port forwarding",
		Long:  help.GetHelpFor([]string{consts.RportfwdStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	rportfwd.StopRportFwdListenerCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.Int("i", "id", 0, "id of portfwd to remove")
		// },
		// GroupID: consts.SliverWinHelpGroup,
	})

	sliver.AddCommand(rportfwdCmd)

	// [ Pivots ] --------------------------------------------------------------

	pivotsCmd := &cobra.Command{
		Use:   consts.PivotsStr,
		Short: "List pivots for active session",
		Long:  help.GetHelpFor([]string{consts.PivotsStr}),
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	pivots.PivotsCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// GroupID: consts.SliverHelpGroup,
	}
	sliver.AddCommand(pivotsCmd)

	pivotsCmd.AddCommand(&cobra.Command{
		Use:   consts.NamedPipeStr,
		Short: "Start a named pipe pivot listener",
		Long:  help.GetHelpFor([]string{consts.PivotsStr, consts.NamedPipeStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("b", "bind", "", "name of the named pipe to bind pivot listener")
		// 	f.Bool("a", "allow-all", false, "allow all users to connect")
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	pivots.StartNamedPipeListenerCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.SliverHelpGroup,
	})

	pivotsCmd.AddCommand(&cobra.Command{
		Use:   consts.TCPListenerStr,
		Short: "Start a TCP pivot listener",
		Long:  help.GetHelpFor([]string{consts.PivotsStr, consts.TCPListenerStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("b", "bind", "", "remote interface to bind pivot listener")
		// 	f.Int("l", "lport", generate.DefaultTCPPivotPort, "tcp pivot listener port")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	pivots.StartTCPListenerCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.SliverHelpGroup,
	})

	pivotsCmd.AddCommand(&cobra.Command{
		Use:   consts.StopStr,
		Short: "Stop a pivot listener",
		Long:  help.GetHelpFor([]string{consts.PivotsStr, consts.StopStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("i", "id", 0, "id of the pivot listener to stop")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	pivots.StopPivotListenerCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.SliverHelpGroup,
	})

	pivotsCmd.AddCommand(&cobra.Command{
		Use:   consts.DetailsStr,
		Short: "Get details of a pivot listener",
		Long:  help.GetHelpFor([]string{consts.PivotsStr, consts.StopStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("i", "id", 0, "id of the pivot listener to stop")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	pivots.PivotDetailsCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.SliverHelpGroup,
	})

	pivotsCmd.AddCommand(&cobra.Command{
		Use:   "graph",
		Short: "Get details of a pivot listener",
		Long:  help.GetHelpFor([]string{consts.PivotsStr, "graph"}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("i", "id", 0, "id of the pivot listener to stop")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	pivots.PivotsGraphCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.SliverHelpGroup,
	})

	// [ Portfwd ] --------------------------------------------------------------

	portfwdCmd := &cobra.Command{
		Use:   consts.PortfwdStr,
		Short: "In-band TCP port forwarding",
		Long:  help.GetHelpFor([]string{consts.PortfwdStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	portfwd.PortfwdCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	}
	portfwdCmd.AddCommand(&cobra.Command{
		Use:   "add",
		Short: "Create a new port forwarding tunnel",
		Long:  help.GetHelpFor([]string{consts.PortfwdStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.String("r", "remote", "", "remote target host:port (e.g., 10.0.0.1:445)")
		// 	f.String("b", "bind", "127.0.0.1:8080", "bind port forward to interface")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	portfwd.PortfwdAddCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.SliverHelpGroup,
	})
	portfwdCmd.AddCommand(&cobra.Command{
		Use:   "rm",
		Short: "Remove a port forwarding tunnel",
		Long:  help.GetHelpFor([]string{consts.PortfwdStr}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.Int("i", "id", 0, "id of portfwd to remove")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	portfwd.PortfwdRmCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.SliverHelpGroup,
	})
	sliver.AddCommand(portfwdCmd)

	// [ Socks ] --------------------------------------------------------------

	socksCmd := &cobra.Command{
		Use:   consts.Socks5Str,
		Short: "In-band SOCKS5 Proxy",
		Long:  help.GetHelpFor([]string{consts.Socks5Str}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "router timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	socks.SocksCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		GroupID: consts.SliverHelpGroup,
	}
	socksCmd.AddCommand(&cobra.Command{
		Use:   consts.StartStr,
		Short: "Start an in-band SOCKS5 proxy",
		Long:  help.GetHelpFor([]string{consts.Socks5Str}),
		// Flags: func(f *grumble.Flags) {
		// 	f.String("H", "host", "127.0.0.1", "Bind a Socks5 Host")
		// 	f.String("P", "port", "1081", "Bind a Socks5 Port")
		// 	f.String("u", "user", "", "socks5 auth username (will generate random password)")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	socks.SocksStartCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.SliverHelpGroup,
	})
	socksCmd.AddCommand(&cobra.Command{
		Use:   consts.StopStr,
		Short: "Stop a SOCKS5 proxy",
		Long:  help.GetHelpFor([]string{consts.Socks5Str}),
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "router timeout in seconds")
		// 	f.Uint64("i", "id", 0, "id of portfwd to remove")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	socks.SocksStopCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
		// GroupID: consts.SliverHelpGroup,
	})
	sliver.AddCommand(socksCmd)

	// [ Curse Commands ] ------------------------------------------------------------

	cursedCmd := &cobra.Command{
		Use:     consts.Cursed,
		Short:   "Chrome/electron post-exploitation tool kit (∩｀-´)⊃━☆ﾟ.*･｡ﾟ",
		Long:    help.GetHelpFor([]string{consts.Cursed}),
		GroupID: consts.GenericHelpGroup,
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	cursed.CursedCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	}
	cursedCmd.AddCommand(&cobra.Command{
		Use:   consts.RmStr,
		Short: "Remove a Curse from a process",
		Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedConsole}),
		// GroupID: consts.GenericHelpGroup,
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	f.Bool("k", "kill", false, "kill the process after removing the curse")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.Int("bind-port", "bind port of the Cursed process to stop")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	cursed.CursedRmCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})
	cursedCmd.AddCommand(&cobra.Command{
		Use:   consts.CursedConsole,
		Short: "Start a JavaScript console connected to a debug target",
		Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedConsole}),
		// GroupID: consts.GenericHelpGroup,
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("r", "remote-debugging-port", 0, "remote debugging tcp port (0 = random)`")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	cursed.CursedConsoleCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})
	cursedCmd.AddCommand(&cobra.Command{
		Use:   consts.CursedChrome,
		Short: "Automatically inject a Cursed Chrome payload into a remote Chrome extension",
		Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedChrome}),
		// GroupID: consts.GenericHelpGroup,
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("r", "remote-debugging-port", 0, "remote debugging tcp port (0 = random)")
		// 	f.Bool("R", "restore", true, "restore the user's session after process termination")
		// 	f.String("e", "exe", "", "chrome/chromium browser executable path (blank string = auto)")
		// 	f.String("u", "user-data", "", "user data directory (blank string = auto)")
		// 	f.String("p", "payload", "", "cursed chrome payload file path (.js)")
		// 	f.Bool("k", "keep-alive", false, "keeps browser alive after last browser window closes")
		// 	f.Bool("H", "headless", false, "start browser process in headless mode")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.StringList("args", "additional chrome cli arguments", grumble.Default([]string{}))
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	cursed.CursedChromeCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})
	cursedCmd.AddCommand(&cobra.Command{
		Use:   consts.CursedEdge,
		Short: "Automatically inject a Cursed Chrome payload into a remote Edge extension",
		Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedEdge}),
		// GroupID: consts.GenericHelpGroup,
		// Flags: func(f *grumble.Flags) {
		// 	f.Int("r", "remote-debugging-port", 0, "remote debugging tcp port (0 = random)")
		// 	f.Bool("R", "restore", true, "restore the user's session after process termination")
		// 	f.String("e", "exe", "", "edge browser executable path (blank string = auto)")
		// 	f.String("u", "user-data", "", "user data directory (blank string = auto)")
		// 	f.String("p", "payload", "", "cursed chrome payload file path (.js)")
		// 	f.Bool("k", "keep-alive", false, "keeps browser alive after last browser window closes")
		// 	f.Bool("H", "headless", false, "start browser process in headless mode")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.StringList("args", "additional edge cli arguments", grumble.Default([]string{}))
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	cursed.CursedEdgeCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})
	cursedCmd.AddCommand(&cobra.Command{
		Use:   consts.CursedElectron,
		Short: "Curse a remote Electron application",
		Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedElectron}),
		// GroupID: consts.GenericHelpGroup,
		// Flags: func(f *grumble.Flags) {
		// 	f.String("e", "exe", "", "remote electron executable absolute path")
		// 	f.Int("r", "remote-debugging-port", 0, "remote debugging tcp port (0 = random)")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Args: func(a *grumble.Args) {
		// 	a.StringList("args", "additional electron cli arguments", grumble.Default([]string{}))
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	cursed.CursedElectronCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})
	cursedCmd.AddCommand(&cobra.Command{
		Use:   consts.CursedCookies,
		Short: "Dump all cookies from cursed process",
		Long:  help.GetHelpFor([]string{consts.Cursed, consts.CursedCookies}),
		// GroupID: consts.GenericHelpGroup,
		// Flags: func(f *grumble.Flags) {
		// 	f.String("s", "save", "", "save to file")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	cursed.CursedCookiesCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})
	cursedCmd.AddCommand(&cobra.Command{
		Use:   consts.ScreenshotStr,
		Short: "Take a screenshot of a cursed process debug target",
		Long:  help.GetHelpFor([]string{consts.Cursed, consts.ScreenshotStr}),
		// GroupID: consts.GenericHelpGroup,
		// Flags: func(f *grumble.Flags) {
		// 	f.Int64("q", "quality", 100, "screenshot quality (1 - 100)")
		// 	f.String("s", "save", "", "save to file")
		//
		// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// },
		// Run: func(ctx *grumble.Context) error {
		// 	con.Println()
		// 	cursed.CursedScreenshotCmd(ctx, con)
		// 	con.Println()
		// 	return nil
		// },
	})
	sliver.AddCommand(cursedCmd)

	return sliver
}
