package command

import (
	"os"

	"github.com/bishopfox/sliver/client/command/alias"
	"github.com/bishopfox/sliver/client/command/armory"
	"github.com/bishopfox/sliver/client/command/generate"
	"github.com/bishopfox/sliver/client/command/help"
	"github.com/bishopfox/sliver/client/command/jobs"
	"github.com/bishopfox/sliver/client/command/operators"
	"github.com/bishopfox/sliver/client/command/reaction"
	"github.com/bishopfox/sliver/client/command/sessions"
	"github.com/bishopfox/sliver/client/command/update"
	"github.com/bishopfox/sliver/client/command/use"
	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/log"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/reeflective/console"
)

// ServerCommands returns all commands bound to the server menu, optionally
// accepting a function returning a list of additional (admin) commands.
func ServerCommands(serverCmds func() []*cobra.Command) console.Commands {
	serverCommands := func() *cobra.Command {
		server := &cobra.Command{
			Short: "Server commands",
		}

		// Load Reactions
		n, err := reaction.LoadReactions()
		if err != nil && !os.IsNotExist(err) {
			log.Errorf("Failed to load reactions: %s\n", err)
		} else if n > 0 {
			log.Infof("Loaded %d reaction(s) from disk\n", n)
		}

		// [ Groups ] ----------------------------------------------
		groups := []*cobra.Group{
			{ID: consts.GenericHelpGroup, Title: consts.GenericHelpGroup},
			{ID: consts.MultiplayerHelpGroup, Title: consts.MultiplayerHelpGroup},
			{ID: consts.SliverHelpGroup, Title: consts.SliverHelpGroup},
		}
		server.AddGroup(groups...)

		// [ Aliases ] ---------------------------------------------

		aliasCmd := &cobra.Command{
			Use:     consts.AliasesStr,
			Short:   "List current aliases",
			Long:    help.GetHelpFor([]string{consts.AliasesStr}),
			RunE:    alias.AliasesCmd,
			GroupID: consts.GenericHelpGroup,
		}
		server.AddCommand(aliasCmd)

		aliasLoadCmd := &cobra.Command{
			Use:   consts.LoadStr + " [ALIAS]",
			Short: "Load a command alias",
			Long:  help.GetHelpFor([]string{consts.AliasesStr, consts.LoadStr}),
			Args:  cobra.ExactArgs(1), // 	a.String("dir-path", "path to the alias directory")
			Run:   alias.AliasesLoadCmd,
		}
		carapace.Gen(aliasLoadCmd).PositionalCompletion(carapace.ActionDirectories().Tag("alias directory"))
		aliasCmd.AddCommand(aliasLoadCmd)

		aliasInstallCmd := &cobra.Command{
			Use:   consts.InstallStr + " [ALIAS]",
			Short: "Install a command alias",
			Long:  help.GetHelpFor([]string{consts.AliasesStr, consts.InstallStr}),
			Args:  cobra.ExactArgs(1),
			Run:   alias.AliasesInstallCmd,
		}
		carapace.Gen(aliasInstallCmd).PositionalCompletion(carapace.ActionFiles().Tag("alias file"))
		aliasCmd.AddCommand(aliasInstallCmd)

		aliasRemove := &cobra.Command{
			Use:   consts.RmStr + " [ALIAS]",
			Short: "Remove an alias",
			Long:  help.GetHelpFor([]string{consts.RmStr}),
			Args:  cobra.ExactArgs(1),
			Run:   alias.AliasesRemoveCmd,
		}
		carapace.Gen(aliasRemove).PositionalCompletion(alias.AliasCompleter())
		aliasCmd.AddCommand(aliasRemove)

		// [ Armory ] ---------------------------------------------

		armoryCmd := &cobra.Command{
			Use:     consts.ArmoryStr,
			Short:   "Automatically download and install extensions/aliases",
			Long:    help.GetHelpFor([]string{consts.ArmoryStr}),
			Run:     armory.ArmoryCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("armory", armoryCmd, func(f *pflag.FlagSet) {
			f.BoolP("insecure", "I", false, "skip tls certificate validation")
			f.StringP("proxy", "p", "", "specify a proxy url (e.g. http://localhost:8080)")
			f.BoolP("ignore-cache", "c", false, "ignore metadata cache, force refresh")
			f.StringP("timeout", "t", "15m", "download timeout")
		})
		server.AddCommand(armoryCmd)

		armoryInstallCmd := &cobra.Command{
			Use:   consts.InstallStr,
			Short: "Install an alias or extension",
			Long:  help.GetHelpFor([]string{consts.ArmoryStr, consts.InstallStr}),
			Args:  cobra.ExactArgs(1), // 	a.String("name", "name of the extension or alias to install")
			Run:   armory.ArmoryInstallCmd,
		}
		Flags("armory", armoryInstallCmd, func(f *pflag.FlagSet) {
			f.BoolP("insecure", "I", false, "skip tls certificate validation")
			f.StringP("proxy", "p", "", "specify a proxy url (e.g. http://localhost:8080)")
			f.BoolP("ignore-cache", "c", false, "ignore metadata cache, force refresh")
			f.StringP("timeout", "t", "15m", "download timeout")
		})
		carapace.Gen(armoryInstallCmd).PositionalCompletion(armory.AliasExtensionOrBundleCompleter())
		armoryCmd.AddCommand(armoryInstallCmd)

		armoryUpdateCmd := &cobra.Command{
			Use:   consts.UpdateStr,
			Short: "Update installed an aliases and extensions",
			Long:  help.GetHelpFor([]string{consts.ArmoryStr, consts.UpdateStr}),
			Run:   armory.ArmoryUpdateCmd,
		}
		Flags("armory", armoryInstallCmd, func(f *pflag.FlagSet) {
			f.BoolP("insecure", "I", false, "skip tls certificate validation")
			f.StringP("proxy", "p", "", "specify a proxy url (e.g. http://localhost:8080)")
			f.BoolP("ignore-cache", "c", false, "ignore metadata cache, force refresh")
			f.StringP("timeout", "t", "15m", "download timeout")
		})
		armoryCmd.AddCommand(armoryUpdateCmd)

		armorySearchCmd := &cobra.Command{
			Use:   consts.SearchStr,
			Short: "Search for aliases and extensions by name (regex)",
			Long:  help.GetHelpFor([]string{consts.ArmoryStr, consts.SearchStr}),
			Args:  cobra.ExactArgs(1), // 	a.String("name", "a name regular expression")
			Run:   armory.ArmorySearchCmd,
		}
		armoryCmd.AddCommand(armorySearchCmd)

		// [ Update ] --------------------------------------------------------------

		updateCmd := &cobra.Command{
			Use:     consts.UpdateStr,
			Short:   "Check for updates",
			Long:    help.GetHelpFor([]string{consts.UpdateStr}),
			Run:     update.UpdateCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("update", updateCmd, func(f *pflag.FlagSet) {
			f.BoolP("prereleases", "P", false, "include pre-released (unstable) versions")
			f.StringP("proxy", "p", "", "specify a proxy url (e.g. http://localhost:8080)")
			f.StringP("save", "s", "", "save downloaded files to specific directory (default user home dir)")
			f.BoolP("insecure", "I", false, "skip tls certificate validation")
			f.IntP("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		server.AddCommand(updateCmd)

		versionCmd := &cobra.Command{
			Use:     consts.VersionStr,
			Short:   "Display version information",
			Long:    help.GetHelpFor([]string{consts.VersionStr}),
			Run:     update.VerboseVersionsCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("update", versionCmd, func(f *pflag.FlagSet) {
			f.IntP("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		server.AddCommand(versionCmd)

		// [ Jobs ] -----------------------------------------------------------------

		jobsCmd := &cobra.Command{
			Use:     consts.JobsStr,
			Short:   "Job control",
			Long:    help.GetHelpFor([]string{consts.JobsStr}),
			Run:     jobs.JobsCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("jobs", jobsCmd, func(f *pflag.FlagSet) {
			f.Int32P("kill", "k", -1, "kill a background job")
			f.BoolP("kill-all", "K", false, "kill all jobs")
			f.IntP("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		FlagComps(jobsCmd, func(comp *carapace.ActionMap) {
			(*comp)["kill"] = jobs.JobsIDCompleter()
		})
		server.AddCommand(jobsCmd)

		mtlsCmd := &cobra.Command{
			Use:     consts.MtlsStr,
			Short:   "Start an mTLS listener",
			Long:    help.GetHelpFor([]string{consts.MtlsStr}),
			Run:     jobs.MTLSListenerCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("mTLS listener", mtlsCmd, func(f *pflag.FlagSet) {
			f.StringP("lhost", "L", "", "interface to bind server to")
			f.Uint32P("lport", "l", generate.DefaultMTLSLPort, "tcp listen port")
			f.IntP("timeout", "t", defaultTimeout, "command timeout in seconds")
			f.BoolP("persistent", "p", false, "make persistent across restarts")
		})
		server.AddCommand(mtlsCmd)

		wgCmd := &cobra.Command{
			Use:     consts.WGStr,
			Short:   "Start a WireGuard listener",
			Long:    help.GetHelpFor([]string{consts.WGStr}),
			Run:     jobs.WGListenerCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("WireGuardlistener", wgCmd, func(f *pflag.FlagSet) {
			f.StringP("lhost", "L", "", "interface to bind server to")
			f.Uint32P("lport", "l", generate.DefaultWGLPort, "udp listen port")
			f.Uint32P("nport", "n", generate.DefaultWGNPort, "virtual tun interface listen port")
			f.Uint32P("key-port", "x", generate.DefaultWGKeyExPort, "virtual tun interface key exchange port")
			f.BoolP("persistent", "p", false, "make persistent across restarts")
			f.IntP("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		server.AddCommand(wgCmd)

		dnsCmd := &cobra.Command{
			Use:     consts.DnsStr,
			Short:   "Start a DNS listener",
			Long:    help.GetHelpFor([]string{consts.DnsStr}),
			Run:     jobs.DNSListenerCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("DNS listener", dnsCmd, func(f *pflag.FlagSet) {
			f.StringP("domains", "d", "", "parent domain(s) to use for DNS c2")
			f.BoolP("no-canaries", "c", false, "disable dns canary detection")
			f.StringP("lhost", "L", "", "interface to bind server to")
			f.Uint32P("lport", "l", generate.DefaultDNSLPort, "udp listen port")
			f.BoolP("disable-otp", "D", false, "disable otp authentication")
			f.IntP("timeout", "t", defaultTimeout, "command timeout in seconds")
			f.BoolP("persistent", "p", false, "make persistent across restarts")
		})
		server.AddCommand(dnsCmd)

		httpCmd := &cobra.Command{
			Use:     consts.HttpStr,
			Short:   "Start an HTTP listener",
			Long:    help.GetHelpFor([]string{consts.HttpStr}),
			Run:     jobs.HTTPListenerCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("HTTP listener", httpCmd, func(f *pflag.FlagSet) {
			f.StringP("domain", "d", "", "limit responses to specific domain")
			f.StringP("website", "w", "", "website name (see websites cmd)")
			f.StringP("lhost", "L", "", "interface to bind server to")
			f.Uint32P("lport", "l", generate.DefaultHTTPLPort, "tcp listen port")
			f.BoolP("disable-otp", "D", false, "disable otp authentication")
			f.StringP("long-poll-timeout", "T", "1s", "server-side long poll timeout")
			f.StringP("long-poll-jitter", "J", "2s", "server-side long poll jitter")
			f.IntP("timeout", "t", defaultTimeout, "command timeout in seconds")
			f.BoolP("persistent", "p", false, "make persistent across restarts")
		})
		server.AddCommand(httpCmd)

		httpsCmd := &cobra.Command{
			Use:     consts.HttpsStr,
			Short:   "Start an HTTPS listener",
			Long:    help.GetHelpFor([]string{consts.HttpsStr}),
			Run:     jobs.HTTPSListenerCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("HTTPS listener", httpsCmd, func(f *pflag.FlagSet) {
			f.StringP("domain", "d", "", "limit responses to specific domain")
			f.StringP("website", "w", "", "website name (see websites cmd)")
			f.StringP("lhost", "L", "", "interface to bind server to")
			f.Uint32P("lport", "l", generate.DefaultHTTPSLPort, "tcp listen port")
			f.BoolP("disable-otp", "D", false, "disable otp authentication")
			f.StringP("long-poll-timeout", "T", "1s", "server-side long poll timeout")
			f.StringP("long-poll-jitter", "J", "2s", "server-side long poll jitter")

			f.StringP("cert", "c", "", "PEM encoded certificate file")
			f.StringP("key", "k", "", "PEM encoded private key file")
			f.BoolP("lets-encrypt", "e", false, "attempt to provision a let's encrypt certificate")
			f.BoolP("disable-randomized-jarm", "E", false, "disable randomized jarm fingerprints")

			f.IntP("timeout", "t", defaultTimeout, "command timeout in seconds")
			f.BoolP("persistent", "p", false, "make persistent across restarts")
		})
		server.AddCommand(httpsCmd)

		stageCmd := &cobra.Command{
			Use:     consts.StageListenerStr,
			Short:   "Start a stager listener",
			Long:    help.GetHelpFor([]string{consts.StageListenerStr}),
			Run:     jobs.StageListenerCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("stage listener", stageCmd, func(f *pflag.FlagSet) {
			f.StringP("profile", "p", "", "implant profile name to link with the listener")
			f.StringP("url", "u", "", "URL to which the stager will call back to")
			f.StringP("cert", "c", "", "path to PEM encoded certificate file (HTTPS only)")
			f.StringP("key", "k", "", "path to PEM encoded private key file (HTTPS only)")
			f.BoolP("lets-encrypt", "e", false, "attempt to provision a let's encrypt certificate (HTTPS only)")
			f.String("aes-encrypt-key", "", "encrypt stage with AES encryption key")
			f.String("aes-encrypt-iv", "", "encrypt stage with AES encryption iv")
			f.StringP("compress", "C", "none", "compress the stage before encrypting (zlib, gzip, deflate9, none)")
			f.BoolP("prepend-size", "P", false, "prepend the size of the stage to the payload (to use with MSF stagers)")
		})
		FlagComps(stageCmd, func(comp *carapace.ActionMap) {
			(*comp)["profile"] = generate.ProfileNameCompleter()
			(*comp)["cert"] = carapace.ActionFiles().Tag("certificate file")
			(*comp)["key"] = carapace.ActionFiles().Tag("key file")
			(*comp)["compress"] = carapace.ActionValues([]string{"zlib", "gzip", "deflate9", "none"}...).Tag("compression formats")
		})
		server.AddCommand(stageCmd)

		// [ Operators ] --------------------------------------------------------------

		operatorsCmd := &cobra.Command{
			Use:     consts.OperatorsStr,
			Short:   "Manage operators",
			Long:    help.GetHelpFor([]string{consts.OperatorsStr}),
			Run:     operators.OperatorsCmd,
			GroupID: consts.MultiplayerHelpGroup,
		}
		Flags("operators", operatorsCmd, func(f *pflag.FlagSet) {
			f.IntP("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		server.AddCommand(operatorsCmd)

		// Server-only commands.
		if serverCmds != nil {
			server.AddCommand(serverCmds()...)
		}

		// [ Sessions ] --------------------------------------------------------------

		sessionsCmd := &cobra.Command{
			Use:     consts.SessionsStr,
			Short:   "Session management",
			Long:    help.GetHelpFor([]string{consts.SessionsStr}),
			Run:     sessions.SessionsCmd,
			GroupID: consts.SliverHelpGroup,
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
			(*comp)["interact"] = use.BeaconAndSessionIDCompleter()
			(*comp)["kill"] = use.BeaconAndSessionIDCompleter()
		})
		server.AddCommand(sessionsCmd)

		sessionsPruneCmd := &cobra.Command{
			Use:   consts.PruneStr,
			Short: "Kill all stale/dead sessions",
			Long:  help.GetHelpFor([]string{consts.SessionsStr, consts.PruneStr}),
			Run:   sessions.SessionsPruneCmd,
		}
		Flags("prune", sessionsCmd, func(f *pflag.FlagSet) {
			f.BoolP("force", "F", false, "Force the killing of stale/dead sessions")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		sessionsCmd.AddCommand(sessionsPruneCmd)

		// [ Use ] --------------------------------------------------------------

		useCmd := &cobra.Command{
			Use:   consts.UseStr,
			Short: "Switch the active session or beacon",
			Long:  help.GetHelpFor([]string{consts.UseStr}),
			// Args: func(a *grumble.Args) {
			// 	a.String("id", "beacon or session ID", grumble.Default(""))
			// },
			Run:     use.UseCmd,
			GroupID: consts.SliverHelpGroup,
		}
		Flags("use", sessionsCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		carapace.Gen(useCmd).PositionalCompletion(use.BeaconAndSessionIDCompleter())
		server.AddCommand(useCmd)

		useSessionCmd := &cobra.Command{
			Use:   consts.SessionsStr,
			Short: "Switch the active session",
			Long:  help.GetHelpFor([]string{consts.UseStr, consts.SessionsStr}),
			Run:   use.UseSessionCmd,
		}
		Flags("use", useSessionCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		carapace.Gen(useSessionCmd).PositionalCompletion(use.SessionIDCompleter())
		useCmd.AddCommand(useSessionCmd)

		useBeaconCmd := &cobra.Command{
			Use:   consts.BeaconsStr,
			Short: "Switch the active beacon",
			Long:  help.GetHelpFor([]string{consts.UseStr, consts.BeaconsStr}),
			Run:   use.UseBeaconCmd,
		}
		Flags("use", useBeaconCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		carapace.Gen(useBeaconCmd).PositionalCompletion(use.BeaconIDCompleter())
		useCmd.AddCommand(useBeaconCmd)

		// [ Settings ] --------------------------------------------------------------

		settingsCmd := &cobra.Command{
			Use:   consts.SettingsStr,
			Short: "Manage client settings",
			Long:  help.GetHelpFor([]string{consts.SettingsStr}),
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	settings.SettingsCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		}
		settingsCmd.AddCommand(&cobra.Command{
			Use:   consts.SaveStr,
			Short: "Save the current settings to disk",
			Long:  help.GetHelpFor([]string{consts.SettingsStr, consts.SaveStr}),
			Run:   func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	settings.SettingsSaveCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		settingsCmd.AddCommand(&cobra.Command{
			Use:   consts.TablesStr,
			Short: "Modify tables setting (style)",
			Long:  help.GetHelpFor([]string{consts.SettingsStr, consts.TablesStr}),
			Run:   func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	settings.SettingsTablesCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		settingsCmd.AddCommand(&cobra.Command{
			Use:   "beacon-autoresults",
			Short: "Automatically display beacon task results when completed",
			Long:  help.GetHelpFor([]string{consts.SettingsStr, "beacon-autoresults"}),
			Run:   func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	settings.SettingsBeaconsAutoResultCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		settingsCmd.AddCommand(&cobra.Command{
			Use:   "autoadult",
			Short: "Automatically accept OPSEC warnings",
			Long:  help.GetHelpFor([]string{consts.SettingsStr, "autoadult"}),
			Run:   func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	settings.SettingsAutoAdultCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		settingsCmd.AddCommand(&cobra.Command{
			Use:   "always-overflow",
			Short: "Disable table pagination",
			Long:  help.GetHelpFor([]string{consts.SettingsStr, "always-overflow"}),
			Run:   func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	settings.SettingsAlwaysOverflow(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		settingsCmd.AddCommand(&cobra.Command{
			Use:   "small-terminal",
			Short: "Set the small terminal width",
			Long:  help.GetHelpFor([]string{consts.SettingsStr, "small-terminal"}),
			Run:   func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	settings.SettingsSmallTerm(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		server.AddCommand(settingsCmd)

		// [ Info ] --------------------------------------------------------------

		server.AddCommand(&cobra.Command{
			Use:   consts.InfoStr,
			Short: "Get info about session",
			Long:  help.GetHelpFor([]string{consts.InfoStr}),
			Run:   func(cmd *cobra.Command, args []string) {},
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

		// [ Shellcode Encoders ] --------------------------------------------------------------

		// server.AddCommand(&cobra.Command{
		// 	Use:     consts.ShikataGaNai,
		// 	Short:     "Polymorphic binary shellcode encoder (ノ ゜Д゜)ノ ︵ 仕方がない",
		// 	Long: help.GetHelpFor([]string{consts.ShikataGaNai}),
		// 	// Args: func(a *grumble.Args) {
		// 	// 	a.String("shellcode", "binary shellcode file path")
		// 	// },
		// 	// Flags: func(f *grumble.Flags) {
		// 	// 	f.String("s", "save", "", "save output to local file")
		// 	//
		// 	// 	f.String("a", "arch", "amd64", "architecture of shellcode")
		// 	// 	f.Int("i", "iterations", 1, "number of iterations")
		// 	// 	f.String("b", "bad-chars", "", "hex encoded bad characters to avoid (e.g. 0001)")
		// 	//
		// 	// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
		// 	// },
		// 	// Run: func(ctx *grumble.Context) error {
		// 	// 	con.Println()
		// 	// 	sgn.ShikataGaNaiCmd(ctx, con)
		// 	// 	con.Println()
		// 	// 	return nil
		// 	// },
		// 	GroupID: consts.SliverHelpGroup,
		// })

		// [ Generate ] --------------------------------------------------------------

		generateCmd := &cobra.Command{
			Use:     consts.GenerateStr,
			Short:   "Generate an implant binary",
			Long:    help.GetHelpFor([]string{consts.GenerateStr}),
			Run:     generate.GenerateCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("session", generateCmd, func(f *pflag.FlagSet) {
			f.StringP("os", "o", "windows", "operating system")
			f.StringP("arch", "a", "amd64", "cpu architecture")
			f.StringP("name", "N", "", "agent name")
			f.BoolP("debug", "d", false, "enable debug features")
			f.StringP("debug-file", "O", "", "path to debug output")
			f.BoolP("evasion", "e", false, "enable evasion features (e.g. overwrite user space hooks)")
			f.BoolP("skip-symbols", "l", false, "skip symbol obfuscation")
			f.StringP("template", "I", "sliver", "implant code template")
			f.BoolP("external-builder", "E", false, "use an external builder")
			f.BoolP("disable-sgn", "G", false, "disable shikata ga nai shellcode encoder")

			f.StringP("canary", "c", "", "canary domain(s)")

			f.StringP("mtls", "m", "", "mtls connection strings")
			f.StringP("wg", "g", "", "wg connection strings")
			f.StringP("http", "b", "", "http(s) connection strings")
			f.StringP("dns", "n", "", "dns connection strings")
			f.StringP("named-pipe", "p", "", "named-pipe connection strings")
			f.StringP("tcp-pivot", "i", "", "tcp-pivot connection strings")

			f.Uint32P("key-exchange", "X", generate.DefaultWGKeyExPort, "wg key-exchange port")
			f.Uint32P("tcp-comms", "T", generate.DefaultWGNPort, "wg c2 comms port")

			f.BoolP("run-at-load", "R", false, "run the implant entrypoint from DllMain/Constructor (shared library only)")

			f.StringP("strategy", "Z", "", "specify a connection strategy (r = random, rd = random domain, s = sequential)")
			f.Int64P("reconnect", "j", generate.DefaultReconnect, "attempt to reconnect every n second(s)")
			f.Int64P("poll-timeout", "P", generate.DefaultPollTimeout, "long poll request timeout")
			f.Uint32P("max-errors", "k", generate.DefaultMaxErrors, "max number of connection errors")

			f.StringP("limit-datetime", "w", "", "limit execution to before datetime")
			f.BoolP("limit-domainjoined", "x", false, "limit execution to domain joined machines")
			f.StringP("limit-username", "y", "", "limit execution to specified username")
			f.StringP("limit-hostname", "z", "", "limit execution to specified hostname")
			f.StringP("limit-fileexists", "F", "", "limit execution to hosts with this file in the filesystem")
			f.StringP("limit-locale", "L", "", "limit execution to hosts that match this locale")

			f.StringP("format", "f", "exe", "Specifies the output formats, valid values are: 'exe', 'shared' (for dynamic libraries), 'service' (see `psexec` for more info) and 'shellcode' (windows only)")
			f.StringP("save", "s", "", "directory/file to the binary to")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		FlagComps(generateCmd, func(comp *carapace.ActionMap) {
			(*comp)["os"] = generate.OSCompleter()
			(*comp)["arch"] = generate.ArchCompleter()

			// Todo: URL completer for C2s.
			// (*comp)["mtls"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["http"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["dns"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["tcp-pivot"] = use.BeaconAndSessionIDCompleter()

			(*comp)["strategy"] = carapace.ActionValuesDescribed([]string{"r", "random", "rd", "random domain", "s", "sequential"}...).Tag("C2 strategy")
			(*comp)["format"] = generate.FormatCompleter()
			(*comp)["save"] = carapace.ActionFiles().Tag("directory/file to save implant")
		})
		server.AddCommand(generateCmd)

		generateBeaconCmd := &cobra.Command{
			Use:   consts.BeaconStr,
			Short: "Generate a beacon binary",
			Long:  help.GetHelpFor([]string{consts.GenerateStr, consts.BeaconStr}),
			Run:   generate.GenerateBeaconCmd,
		}
		Flags("beacon", generateBeaconCmd, func(f *pflag.FlagSet) {
			f.Int64P("days", "D", 0, "beacon interval days")
			f.Int64P("hours", "H", 0, "beacon interval hours")
			f.Int64P("minutes", "M", 0, "beacon interval minutes")
			f.Int64P("seconds", "S", 60, "beacon interval seconds")
			f.Int64P("jitter", "J", 30, "beacon interval jitter in seconds")

			// Generate flags
			f.StringP("os", "o", "windows", "operating system")
			f.StringP("arch", "a", "amd64", "cpu architecture")
			f.StringP("name", "N", "", "agent name")
			f.BoolP("debug", "d", false, "enable debug features")
			f.StringP("debug-file", "O", "", "path to debug output")
			f.BoolP("evasion", "e", false, "enable evasion features  (e.g. overwrite user space hooks)")
			f.BoolP("skip-symbols", "l", false, "skip symbol obfuscation")
			f.StringP("template", "I", "sliver", "implant code template")
			f.BoolP("external-builder", "E", false, "use an external builder")
			f.BoolP("disable-sgn", "G", false, "disable shikata ga nai shellcode encoder")

			f.StringP("canary", "c", "", "canary domain(s)")

			f.StringP("mtls", "m", "", "mtls connection strings")
			f.StringP("wg", "g", "", "wg connection strings")
			f.StringP("http", "b", "", "http(s) connection strings")
			f.StringP("dns", "n", "", "dns connection strings")
			f.StringP("named-pipe", "p", "", "named-pipe connection strings")
			f.StringP("tcp-pivot", "i", "", "tcp-pivot connection strings")

			f.Uint32P("key-exchange", "X", generate.DefaultWGKeyExPort, "wg key-exchange port")
			f.Uint32P("tcp-comms", "T", generate.DefaultWGNPort, "wg c2 comms port")

			f.BoolP("run-at-load", "R", false, "run the implant entrypoint from DllMain/Constructor (shared library only)")

			f.StringP("strategy", "Z", "", "specify a connection strategy (r = random, rd = random domain, s = sequential)")
			f.Int64P("reconnect", "j", generate.DefaultReconnect, "attempt to reconnect every n second(s)")
			f.Int64P("poll-timeout", "P", generate.DefaultPollTimeout, "long poll request timeout")
			f.Uint32P("max-errors", "k", generate.DefaultMaxErrors, "max number of connection errors")

			f.StringP("limit-datetime", "w", "", "limit execution to before datetime")
			f.BoolP("limit-domainjoined", "x", false, "limit execution to domain joined machines")
			f.StringP("limit-username", "y", "", "limit execution to specified username")
			f.StringP("limit-hostname", "z", "", "limit execution to specified hostname")
			f.StringP("limit-fileexists", "F", "", "limit execution to hosts with this file in the filesystem")
			f.StringP("limit-locale", "L", "", "limit execution to hosts that match this locale")

			f.StringP("format", "f", "exe", "Specifies the output formats, valid values are: 'exe', 'shared' (for dynamic libraries), 'service' (see `psexec` for more info) and 'shellcode' (windows only)")
			f.StringP("save", "s", "", "directory/file to the binary to")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		FlagComps(generateBeaconCmd, func(comp *carapace.ActionMap) {
			(*comp)["os"] = generate.OSCompleter()
			(*comp)["arch"] = generate.ArchCompleter()

			// Todo: URL completer for C2s.
			// (*comp)["mtls"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["http"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["dns"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["tcp-pivot"] = use.BeaconAndSessionIDCompleter()

			(*comp)["strategy"] = carapace.ActionValuesDescribed([]string{"r", "random", "rd", "random domain", "s", "sequential"}...).Tag("C2 strategy")
			(*comp)["format"] = generate.FormatCompleter()
			(*comp)["save"] = carapace.ActionFiles().Tag("directory/file to save implant")
		})
		generateCmd.AddCommand(generateBeaconCmd)

		generateStagerCmd := &cobra.Command{
			Use:   consts.StagerStr,
			Short: "Generate a stager using Metasploit (requires local Metasploit installation)",
			Long:  help.GetHelpFor([]string{consts.StagerStr}),
			Run:   generate.GenerateStagerCmd,
		}
		Flags("stager", generateStagerCmd, func(f *pflag.FlagSet) {
			f.StringP("os", "o", "windows", "operating system")
			f.StringP("arch", "a", "amd64", "cpu architecture")
			f.StringP("lhost", "L", "", "Listening host")
			f.Uint32P("lport", "l", 8443, "Listening port")
			f.StringP("protocol", "r", "tcp", "Staging protocol (tcp/http/https)")
			f.StringP("format", "f", "raw", "Output format (msfvenom formats, see `help generate stager` for the list)")
			f.StringP("badchars", "b", "", "bytes to exclude from stage shellcode")
			f.StringP("save", "s", "", "directory to save the generated stager to")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		generateCmd.AddCommand(generateStagerCmd)

		generateInfoCmd := &cobra.Command{
			Use:   consts.CompilerInfoStr,
			Short: "Get information about the server's compiler",
			Long:  help.GetHelpFor([]string{consts.CompilerInfoStr}),
			Run:   generate.GenerateInfoCmd,
		}
		Flags("stager", generateStagerCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		generateCmd.AddCommand(generateInfoCmd)

		regenerateCmd := &cobra.Command{
			Use:     consts.RegenerateStr,
			Short:   "Regenerate an implant",
			Long:    help.GetHelpFor([]string{consts.RegenerateStr}),
			Args:    cobra.ExactArgs(1), // 	a.String("implant-name", "name of the implant")
			Run:     generate.RegenerateCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("regenerate", regenerateCmd, func(f *pflag.FlagSet) {
			f.StringP("save", "s", "", "directory/file to the binary to")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		FlagComps(regenerateCmd, func(comp *carapace.ActionMap) {
			(*comp)["save"] = carapace.ActionFiles().Tag("directory/file to save implant")
		})
		server.AddCommand(regenerateCmd)

		profilesCmd := &cobra.Command{
			Use:     consts.ProfilesStr,
			Short:   "List existing profiles",
			Long:    help.GetHelpFor([]string{consts.ProfilesStr}),
			Run:     generate.ProfilesCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("profiles", profilesCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		server.AddCommand(profilesCmd)

		profilesGenerateCmd := &cobra.Command{
			Use:   consts.GenerateStr,
			Short: "Generate implant from a profile",
			Long:  help.GetHelpFor([]string{consts.ProfilesStr, consts.GenerateStr}),
			Args:  cobra.ExactArgs(1), // 	a.String("name", "name of the profile", grumble.Default(""))
			Run:   generate.ProfilesGenerateCmd,
		}
		Flags("profiles", profilesGenerateCmd, func(f *pflag.FlagSet) {
			f.StringP("save", "s", "", "directory/file to the binary to")
			f.BoolP("disable-sgn", "G", false, "disable shikata ga nai shellcode encoder")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		FlagComps(profilesGenerateCmd, func(comp *carapace.ActionMap) {
			(*comp)["save"] = carapace.ActionFiles().Tag("directory/file to save implant")
		})
		carapace.Gen(profilesGenerateCmd).PositionalCompletion(generate.ProfileNameCompleter())
		profilesCmd.AddCommand(profilesGenerateCmd)

		profilesNewCmd := &cobra.Command{
			Use:   consts.NewStr,
			Short: "Create a new implant profile (interactive session)",
			Long:  help.GetHelpFor([]string{consts.ProfilesStr, consts.NewStr}),
			// Args: cobra.ExactArgs(1), // 	a.String("name", "name of the profile", grumble.Default(""))
			Run: generate.ProfilesNewCmd,
		}
		Flags("session", profilesNewCmd, func(f *pflag.FlagSet) {
			f.StringP("os", "o", "windows", "operating system")
			f.StringP("arch", "a", "amd64", "cpu architecture")

			f.BoolP("debug", "d", false, "enable debug features")
			f.StringP("debug-file", "O", "", "path to debug output")
			f.BoolP("evasion", "e", false, "enable evasion features (e.g. overwrite user space hooks)")
			f.BoolP("skip-symbols", "l", false, "skip symbol obfuscation")
			f.BoolP("disable-sgn", "G", false, "disable shikata ga nai shellcode encoder")

			f.StringP("canary", "c", "", "canary domain(s)")

			f.StringP("name", "N", "", "agent name")
			f.StringP("mtls", "m", "", "mtls connection strings")
			f.StringP("wg", "g", "", "wg connection strings")
			f.StringP("http", "b", "", "http(s) connection strings")
			f.StringP("dns", "n", "", "dns connection strings")
			f.StringP("named-pipe", "p", "", "named-pipe connection strings")
			f.StringP("tcp-pivot", "i", "", "tcp-pivot connection strings")

			f.Uint32P("key-exchange", "X", generate.DefaultWGKeyExPort, "wg key-exchange port")
			f.Uint32P("tcp-comms", "T", generate.DefaultWGNPort, "wg c2 comms port")

			f.BoolP("run-at-load", "R", false, "run the implant entrypoint from DllMain/Constructor (shared library only)")
			f.StringP("strategy", "Z", "", "specify a connection strategy (r = random, rd = random domain, s = sequential)")

			f.StringP("template", "I", "sliver", "implant code template")

			f.Int64P("reconnect", "j", generate.DefaultReconnect, "attempt to reconnect every n second(s)")
			f.Int64P("poll-timeout", "P", generate.DefaultPollTimeout, "long poll request timeout")
			f.Uint32P("max-errors", "k", generate.DefaultMaxErrors, "max number of connection errors")

			f.StringP("limit-datetime", "w", "", "limit execution to before datetime")
			f.BoolP("limit-domainjoined", "x", false, "limit execution to domain joined machines")
			f.StringP("limit-username", "y", "", "limit execution to specified username")
			f.StringP("limit-hostname", "z", "", "limit execution to specified hostname")
			f.StringP("limit-fileexists", "F", "", "limit execution to hosts with this file in the filesystem")
			f.StringP("limit-locale", "L", "", "limit execution to hosts that match this locale")

			f.StringP("format", "f", "exe", "Specifies the output formats, valid values are: 'exe', 'shared' (for dynamic libraries), 'service' (see `psexec` for more info) and 'shellcode' (windows only)")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		FlagComps(profilesNewCmd, func(comp *carapace.ActionMap) {
			(*comp)["os"] = generate.OSCompleter()
			(*comp)["arch"] = generate.ArchCompleter()

			// Todo: URL completer for C2s.
			// (*comp)["mtls"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["http"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["dns"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["tcp-pivot"] = use.BeaconAndSessionIDCompleter()

			(*comp)["strategy"] = carapace.ActionValuesDescribed([]string{"r", "random", "rd", "random domain", "s", "sequential"}...).Tag("C2 strategy")
			(*comp)["format"] = generate.FormatCompleter()
			(*comp)["save"] = carapace.ActionFiles().Tag("directory/file to save implant")
		})
		profilesCmd.AddCommand(profilesNewCmd)

		// New Beacon Profile Command
		profilesNewBeaconCmd := &cobra.Command{
			Use:   consts.BeaconStr,
			Short: "Create a new implant profile (beacon)",
			Long:  help.GetHelpFor([]string{consts.ProfilesStr, consts.NewStr, consts.BeaconStr}),
			// Args: cobra.ExactArgs(1), // 	a.String("name", "name of the profile", grumble.Default(""))
			Run: generate.ProfilesNewBeaconCmd,
		}
		Flags("beacon", profilesNewBeaconCmd, func(f *pflag.FlagSet) {
			f.Int64P("days", "D", 0, "beacon interval days")
			f.Int64P("hours", "H", 0, "beacon interval hours")
			f.Int64P("minutes", "M", 0, "beacon interval minutes")
			f.Int64P("seconds", "S", 60, "beacon interval seconds")
			f.Int64P("jitter", "J", 30, "beacon interval jitter in seconds")
			f.BoolP("disable-sgn", "G", false, "disable shikata ga nai shellcode encoder")

			// Generate flags
			f.StringP("os", "o", "windows", "operating system")
			f.StringP("arch", "a", "amd64", "cpu architecture")

			f.BoolP("debug", "d", false, "enable debug features")
			f.StringP("debug-file", "O", "", "path to debug output")
			f.BoolP("evasion", "e", false, "enable evasion features  (e.g. overwrite user space hooks)")
			f.BoolP("skip-symbols", "l", false, "skip symbol obfuscation")

			f.StringP("canary", "c", "", "canary domain(s)")

			f.StringP("name", "N", "", "agent name")
			f.StringP("mtls", "m", "", "mtls connection strings")
			f.StringP("wg", "g", "", "wg connection strings")
			f.StringP("http", "b", "", "http(s) connection strings")
			f.StringP("dns", "n", "", "dns connection strings")
			f.StringP("named-pipe", "p", "", "named-pipe connection strings")
			f.StringP("tcp-pivot", "i", "", "tcp-pivot connection strings")
			f.StringP("strategy", "Z", "", "specify a connection strategy (r = random, rd = random domain, s = sequential)")

			f.Uint32P("key-exchange", "X", generate.DefaultWGKeyExPort, "wg key-exchange port")
			f.Uint32P("tcp-comms", "T", generate.DefaultWGNPort, "wg c2 comms port")

			f.BoolP("run-at-load", "R", false, "run the implant entrypoint from DllMain/Constructor (shared library only)")

			f.StringP("template", "I", "sliver", "implant code template")

			f.Int64P("reconnect", "j", generate.DefaultReconnect, "attempt to reconnect every n second(s)")
			f.Int64P("poll-timeout", "P", generate.DefaultPollTimeout, "long poll request timeout")
			f.Uint32P("max-errors", "k", generate.DefaultMaxErrors, "max number of connection errors")

			f.StringP("limit-datetime", "w", "", "limit execution to before datetime")
			f.BoolP("limit-domainjoined", "x", false, "limit execution to domain joined machines")
			f.StringP("limit-username", "y", "", "limit execution to specified username")
			f.StringP("limit-hostname", "z", "", "limit execution to specified hostname")
			f.StringP("limit-fileexists", "F", "", "limit execution to hosts with this file in the filesystem")
			f.StringP("limit-locale", "L", "", "limit execution to hosts that match this locale")

			f.StringP("format", "f", "exe", "Specifies the output formats, valid values are: 'exe', 'shared' (for dynamic libraries), 'service' (see `psexec` for more info) and 'shellcode' (windows only)")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		FlagComps(profilesNewBeaconCmd, func(comp *carapace.ActionMap) {
			(*comp)["os"] = generate.OSCompleter()
			(*comp)["arch"] = generate.ArchCompleter()

			// Todo: URL completer for C2s.
			// (*comp)["mtls"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["http"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["dns"] = use.BeaconAndSessionIDCompleter()
			// (*comp)["tcp-pivot"] = use.BeaconAndSessionIDCompleter()

			(*comp)["strategy"] = carapace.ActionValuesDescribed([]string{"r", "random", "rd", "random domain", "s", "sequential"}...).Tag("C2 strategy")
			(*comp)["format"] = generate.FormatCompleter()
			(*comp)["save"] = carapace.ActionFiles().Tag("directory/file to save implant")
		})
		profilesNewCmd.AddCommand(profilesNewBeaconCmd)

		profilesRmCmd := &cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove a profile",
			Long:  help.GetHelpFor([]string{consts.ProfilesStr, consts.RmStr}),
			Args:  cobra.ExactArgs(1), // 	a.String("name", "name of the profile", grumble.Default(""))
			Run:   generate.ProfilesRmCmd,
		}
		Flags("profiles", profilesRmCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		carapace.Gen(profilesRmCmd).PositionalCompletion(generate.ProfileNameCompleter())
		profilesCmd.AddCommand(profilesRmCmd)

		implantBuildsCmd := &cobra.Command{
			Use:     consts.ImplantBuildsStr,
			Short:   "List implant builds",
			Long:    help.GetHelpFor([]string{consts.ImplantBuildsStr}),
			Run:     generate.ImplantsCmd,
			GroupID: consts.GenericHelpGroup,
		}
		Flags("implants", implantBuildsCmd, func(f *pflag.FlagSet) {
			f.StringP("os", "o", "", "filter builds by operating system")
			f.StringP("arch", "a", "", "filter builds by cpu architecture")
			f.StringP("format", "f", "", "filter builds by artifact format")
			f.BoolP("only-sessions", "s", false, "filter interactive sessions")
			f.BoolP("only-beacons", "b", false, "filter beacons")
			f.BoolP("no-debug", "d", false, "filter builds by debug flag")

			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		FlagComps(profilesNewBeaconCmd, func(comp *carapace.ActionMap) {
			(*comp)["os"] = generate.OSCompleter()
			(*comp)["arch"] = generate.ArchCompleter()
			(*comp)["format"] = generate.FormatCompleter()
		})
		server.AddCommand(implantBuildsCmd)

		implantsRmCmd := &cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove implant build",
			Long:  help.GetHelpFor([]string{consts.ImplantBuildsStr, consts.RmStr}),
			Args:  cobra.ExactArgs(1), // 	a.String("name", "implant name", grumble.Default(""))
			Run:   generate.ImplantsRmCmd,
		}
		Flags("implants", implantsRmCmd, func(f *pflag.FlagSet) {
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})
		carapace.Gen(implantsRmCmd).PositionalCompletion(generate.ImplantBuildNameCompleter())
		implantBuildsCmd.AddCommand(implantsRmCmd)

		canariesCmd := &cobra.Command{
			Use:     consts.CanariesStr,
			Short:   "List previously generated canaries",
			Long:    help.GetHelpFor([]string{consts.CanariesStr}),
			Run:     generate.CanariesCmd,
			GroupID: consts.SliverHelpGroup,
		}
		Flags("canaries", canariesCmd, func(f *pflag.FlagSet) {
			f.BoolP("burned", "b", false, "show only triggered/burned canaries")
			f.Int64P("timeout", "t", defaultTimeout, "command timeout in seconds")
		})

		// [ Websites ] ---------------------------------------------

		websitesCmd := &cobra.Command{
			Use:   consts.WebsitesStr,
			Short: "Host static content (used with HTTP C2)",
			Long:  help.GetHelpFor([]string{consts.WebsitesStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	websites.WebsitesCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("name", "website name", grumble.Default(""))
			// },
			GroupID: consts.GenericHelpGroup,
		}
		websitesCmd.AddCommand(&cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove an entire website and all of its contents",
			Long:  help.GetHelpFor([]string{consts.WebsitesStr, consts.RmStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	websites.WebsiteRmCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("name", "website name", grumble.Default(""))
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		websitesCmd.AddCommand(&cobra.Command{
			Use:   consts.RmWebContentStr,
			Short: "Remove specific content from a website",
			Long:  help.GetHelpFor([]string{consts.WebsitesStr, consts.RmWebContentStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Bool("r", "recursive", false, "recursively add/rm content")
			// 	f.String("w", "website", "", "website name")
			// 	f.String("p", "web-path", "", "http path to host file at")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	websites.WebsitesRmContent(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		websitesCmd.AddCommand(&cobra.Command{
			Use:   consts.AddWebContentStr,
			Short: "Add content to a website",
			Long:  help.GetHelpFor([]string{consts.WebsitesStr, consts.RmWebContentStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("w", "website", "", "website name")
			// 	f.String("m", "content-type", "", "mime content-type (if blank use file ext.)")
			// 	f.String("p", "web-path", "/", "http path to host file at")
			// 	f.String("c", "content", "", "local file path/dir (must use --recursive for dir)")
			// 	f.Bool("r", "recursive", false, "recursively add/rm content")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	websites.WebsitesAddContentCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		websitesCmd.AddCommand(&cobra.Command{
			Use:   consts.WebContentTypeStr,
			Short: "Update a path's content-type",
			Long:  help.GetHelpFor([]string{consts.WebsitesStr, consts.WebContentTypeStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("w", "website", "", "website name")
			// 	f.String("m", "content-type", "", "mime content-type (if blank use file ext.)")
			// 	f.String("p", "web-path", "/", "http path to host file at")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	websites.WebsitesUpdateContentCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		server.AddCommand(websitesCmd)

		// [ Beacons ] ---------------------------------------------

		beaconsCmd := &cobra.Command{
			Use:   consts.BeaconsStr,
			Short: "Manage beacons",
			Long:  help.GetHelpFor([]string{consts.BeaconsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("k", "kill", "", "kill a beacon")
			// 	f.Bool("K", "kill-all", false, "kill all beacons")
			// 	f.Bool("F", "force", false, "force killing of the beacon")
			// 	f.String("f", "filter", "", "filter beacons by substring")
			// 	f.String("e", "filter-re", "", "filter beacons by regular expression")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			GroupID: consts.SliverHelpGroup,
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	beacons.BeaconsCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
		}
		beaconsCmd.AddCommand(&cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove a beacon",
			Long:  help.GetHelpFor([]string{consts.BeaconsStr, consts.RmStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// GroupID: consts.SliverWinHelpGroup,
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	beacons.BeaconsRmCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
		})
		beaconsCmd.AddCommand(&cobra.Command{
			Use:   consts.WatchStr,
			Short: "Watch your beacons",
			Long:  help.GetHelpFor([]string{consts.BeaconsStr, consts.WatchStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// GroupID: consts.SliverWinHelpGroup,
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	beacons.BeaconsWatchCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
		})
		beaconsCmd.AddCommand(&cobra.Command{
			Use:   consts.PruneStr,
			Short: "Prune stale beacons automatically",
			Long:  help.GetHelpFor([]string{consts.BeaconsStr, consts.PruneStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("d", "duration", "1h", "duration to prune beacons that have missed their last checkin")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// GroupID: consts.SliverWinHelpGroup,
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	beacons.BeaconsPruneCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
		})
		server.AddCommand(beaconsCmd)

		// [ Licenses ] ---------------------------------------------

		server.AddCommand(&cobra.Command{
			Use:   consts.LicensesStr,
			Short: "Open source licenses",
			Long:  help.GetHelpFor([]string{consts.LicensesStr}),
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	con.Println(licenses.All)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		// [ WireGuard ] --------------------------------------------------------------

		server.AddCommand(&cobra.Command{
			Use:   consts.WgConfigStr,
			Short: "Generate a new WireGuard client config",
			Long:  help.GetHelpFor([]string{consts.WgConfigStr}),
			// 	Flags: func(f *grumble.Flags) {
			// 		f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// 		f.String("s", "save", "", "save configuration to file (.conf)")
			// 	},
			// 	Run: func(ctx *grumble.Context) error {
			// 		con.Println()
			// 		wireguard.WGConfigCmd(ctx, con)
			// 		con.Println()
			// 		return nil
			// 	},
			GroupID: consts.GenericHelpGroup,
		})

		wgPortFwdCmd := &cobra.Command{
			Use:   consts.WgPortFwdStr,
			Short: "List ports forwarded by the WireGuard tun interface",
			Long:  help.GetHelpFor([]string{consts.WgPortFwdStr}),
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	wireguard.WGPortFwdListCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			GroupID: consts.GenericHelpGroup,
		}
		wgPortFwdCmd.AddCommand(&cobra.Command{
			Use:   consts.AddStr,
			Short: "Add a port forward from the WireGuard tun interface to a host on the target network",
			Long:  help.GetHelpFor([]string{consts.WgPortFwdStr, consts.AddStr}),
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	wireguard.WGPortFwdAddCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// 	f.Int("b", "bind", 1080, "port to listen on the WireGuard tun interface")
			// 	f.String("r", "remote", "", "remote target host:port (e.g., 10.0.0.1:445)")
			// },
		})
		wgPortFwdCmd.AddCommand(&cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove a port forward from the WireGuard tun interface",
			Long:  help.GetHelpFor([]string{consts.WgPortFwdStr, consts.RmStr}),
			// Args: func(a *grumble.Args) {
			// 	a.Int("id", "forwarder id")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	wireguard.WGPortFwdRmCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
		})
		server.AddCommand(wgPortFwdCmd)

		wgSocksCmd := &cobra.Command{
			Use:   consts.WgSocksStr,
			Short: "List socks servers listening on the WireGuard tun interface",
			Long:  help.GetHelpFor([]string{consts.WgSocksStr}),
			// 	Run: func(ctx *grumble.Context) error {
			// 		con.Println()
			// 		wireguard.WGSocksListCmd(ctx, con)
			// 		con.Println()
			// 		return nil
			// 	},
			// 	Flags: func(f *grumble.Flags) {
			// 		f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// 	},
			GroupID: consts.GenericHelpGroup,
		}
		wgSocksCmd.AddCommand(&cobra.Command{
			Use:   consts.StartStr,
			Short: "Start a socks5 listener on the WireGuard tun interface",
			Long:  help.GetHelpFor([]string{consts.WgSocksStr, consts.StartStr}),
			// 	Run: func(ctx *grumble.Context) error {
			// 		con.Println()
			// 		wireguard.WGSocksStartCmd(ctx, con)
			// 		con.Println()
			// 		return nil
			// 	},
			// 	Flags: func(f *grumble.Flags) {
			// 		f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// 		f.Int("b", "bind", 3090, "port to listen on the WireGuard tun interface")
			// 	},
		})
		wgSocksCmd.AddCommand(&cobra.Command{
			Use:   consts.StopStr,
			Short: "Stop a socks5 listener on the WireGuard tun interface",
			Long:  help.GetHelpFor([]string{consts.WgSocksStr, consts.StopStr}),
			// Args: func(a *grumble.Args) {
			// 	a.Int("id", "forwarder id")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	wireguard.WGSocksStopCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
		})
		server.AddCommand(wgSocksCmd)

		// [ Monitor ] --------------------------------------------------------------

		monitorCmd := &cobra.Command{
			Use:     consts.MonitorStr,
			Short:   "Monitor threat intel platforms for Sliver implants",
			GroupID: consts.GenericHelpGroup,
		}
		monitorCmd.AddCommand(&cobra.Command{
			Use:   "start",
			Short: "Start the monitoring loops",
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	monitor.MonitorStartCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
		})
		monitorCmd.AddCommand(&cobra.Command{
			Use:   "stop",
			Short: "Stop the monitoring loops",
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	monitor.MonitorStopCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
		})
		server.AddCommand(monitorCmd)

		// [ Loot ] --------------------------------------------------------------

		lootCmd := &cobra.Command{
			Use:   consts.LootStr,
			Short: "Manage the server's loot store",
			Long:  help.GetHelpFor([]string{consts.LootStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("f", "filter", "", "filter based on loot type")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	loot.LootCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		}
		lootCmd.AddCommand(&cobra.Command{
			Use:   consts.LootLocalStr,
			Short: "Add a local file to the server's loot store",
			Long:  help.GetHelpFor([]string{consts.LootStr, consts.LootLocalStr}),
			// Args: func(a *grumble.Args) {
			// 	a.String("path", "The local file path to the loot")
			// },
			// Flags: func(f *grumble.Flags) {
			// 	f.String("n", "name", "", "name of this piece of loot")
			// 	f.String("T", "type", "", "force a specific loot type (file/cred)")
			// 	f.String("F", "file-type", "", "force a specific file type (binary/text)")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	loot.LootAddLocalCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		lootCmd.AddCommand(&cobra.Command{
			Use:   consts.LootRemoteStr,
			Short: "Add a remote file from the current session to the server's loot store",
			Long:  help.GetHelpFor([]string{consts.LootStr, consts.LootRemoteStr}),
			// Args: func(a *grumble.Args) {
			// 	a.String("path", "The file path on the remote host to the loot")
			// },
			// Flags: func(f *grumble.Flags) {
			// 	f.String("n", "name", "", "name of this piece of loot")
			// 	f.String("T", "type", "", "force a specific loot type (file/cred)")
			// 	f.String("F", "file-type", "", "force a specific file type (binary/text)")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	loot.LootAddRemoteCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		lootCmd.AddCommand(&cobra.Command{
			Use:   consts.LootCredsStr,
			Short: "Add credentials to the server's loot store",
			Long:  help.GetHelpFor([]string{consts.LootStr, consts.LootCredsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("n", "name", "", "name of this piece of loot")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	loot.LootAddCredentialCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		lootCmd.AddCommand(&cobra.Command{
			Use:   consts.RenameStr,
			Short: "Re-name a piece of existing loot",
			Long:  help.GetHelpFor([]string{consts.LootStr, consts.RenameStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	loot.LootRenameCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		lootCmd.AddCommand(&cobra.Command{
			Use:   consts.FetchStr,
			Short: "Fetch a piece of loot from the server's loot store",
			Long:  help.GetHelpFor([]string{consts.LootStr, consts.FetchStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("s", "save", "", "save loot to a local file")
			// 	f.String("f", "filter", "", "filter based on loot type")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	loot.LootFetchCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		lootCmd.AddCommand(&cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove a piece of loot from the server's loot store",
			Long:  help.GetHelpFor([]string{consts.LootStr, consts.RmStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("f", "filter", "", "filter based on loot type")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	loot.LootRmCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		server.AddCommand(lootCmd)

		// [ Hosts ] --------------------------------------------------------------
		hostsCmd := &cobra.Command{
			Use:   consts.HostsStr,
			Short: "Manage the database of hosts",
			Long:  help.GetHelpFor([]string{consts.HostsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	hosts.HostsCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		}
		hostsCmd.AddCommand(&cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove a host from the database",
			Long:  help.GetHelpFor([]string{consts.HostsStr, consts.RmStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	hosts.HostsRmCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		iocCmd := &cobra.Command{
			Use:   consts.IOCStr,
			Short: "Manage tracked IOCs on a given host",
			Long:  help.GetHelpFor([]string{consts.HostsStr, consts.IOCStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	hosts.HostsIOCCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		}
		iocCmd.AddCommand(&cobra.Command{
			Use:   consts.RmStr,
			Short: "Delete IOCs from the database",
			Long:  help.GetHelpFor([]string{consts.HostsStr, consts.IOCStr, consts.RmStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	hosts.HostsIOCRmCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		hostsCmd.AddCommand(iocCmd)
		server.AddCommand(hostsCmd)

		// [ Reactions ] -----------------------------------------------------------------

		reactionCmd := &cobra.Command{
			Use:   consts.ReactionStr,
			Short: "Manage automatic reactions to events",
			Long:  help.GetHelpFor([]string{consts.ReactionStr}),
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	reaction.ReactionCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.SliverHelpGroup,
		}
		reactionCmd.AddCommand(&cobra.Command{
			Use:   consts.SetStr,
			Short: "Set a reaction to an event",
			Long:  help.GetHelpFor([]string{consts.ReactionStr, consts.SetStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("e", "event", "", "specify the event type to react to")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	reaction.ReactionSetCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		reactionCmd.AddCommand(&cobra.Command{
			Use:   consts.UnsetStr,
			Short: "Unset an existing reaction",
			Long:  help.GetHelpFor([]string{consts.ReactionStr, consts.UnsetStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("i", "id", 0, "the id of the reaction to remove")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	reaction.ReactionUnsetCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		reactionCmd.AddCommand(&cobra.Command{
			Use:   consts.SaveStr,
			Short: "Save current reactions to disk",
			Long:  help.GetHelpFor([]string{consts.ReactionStr, consts.SaveStr}),
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	reaction.ReactionSaveCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		reactionCmd.AddCommand(&cobra.Command{
			Use:   consts.ReloadStr,
			Short: "Reload reactions from disk, replaces the running configuration",
			Long:  help.GetHelpFor([]string{consts.ReactionStr, consts.ReloadStr}),
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	reaction.ReactionReloadCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		server.AddCommand(reactionCmd)

		// [ Prelude's Operator ] ------------------------------------------------------------
		operatorCmd := &cobra.Command{
			Use:     consts.PreludeOperatorStr,
			Short:   "Manage connection to Prelude's Operator",
			Long:    help.GetHelpFor([]string{consts.PreludeOperatorStr}),
			GroupID: consts.GenericHelpGroup,
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	operator.OperatorCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
		}
		operatorCmd.AddCommand(&cobra.Command{
			Use:   consts.ConnectStr,
			Short: "Connect with Prelude's Operator",
			Long:  help.GetHelpFor([]string{consts.PreludeOperatorStr, consts.ConnectStr}),
			// GroupID: consts.GenericHelpGroup,
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	operator.ConnectCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("connection-string", "connection string to the Operator Host (e.g. 127.0.0.1:1234)")
			// },
			// Flags: func(f *grumble.Flags) {
			// 	f.Bool("s", "skip-existing", false, "Do not add existing sessions as Operator Agents")
			// 	f.String("a", "aes-key", "abcdefghijklmnopqrstuvwxyz012345", "AES key for communication encryption")
			// 	f.String("r", "range", "sliver", "Agents range")
			// },
		})
		server.AddCommand(operatorCmd)

		// [ Builders ] ---------------------------------------------

		buildersCmd := &cobra.Command{
			Use:     consts.BuildersStr,
			Short:   "List external builders",
			Long:    help.GetHelpFor([]string{consts.BuildersStr}),
			GroupID: consts.GenericHelpGroup,
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	builders.BuildersCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
		}
		server.AddCommand(buildersCmd)

		return server
	}

	return serverCommands
}
