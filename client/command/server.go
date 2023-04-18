package command

import (
	"github.com/bishopfox/sliver/client/command/alias"
	"github.com/bishopfox/sliver/client/command/help"
	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"

	"github.com/reeflective/console"
)

// ServerCommands returns all commands bound to the server menu, optionally
// accepting a function returning a list of additional (admin) commands.
func ServerCommands(serverCmds func() []*cobra.Command) console.Commands {
	// serverCommands returns all commands bound to the server menu.
	serverCommands := func() *cobra.Command {
		server := &cobra.Command{
			Short: "Server commands",
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
			Run:   func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	alias.AliasesLoadCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("dir-path", "path to the alias directory")
			// },
		}
		carapace.Gen(aliasLoadCmd).PositionalCompletion(carapace.ActionFiles().Tag("alias file"))
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
			Use:   consts.ArmoryStr,
			Short: "Automatically download and install extensions/aliases",
			Long:  help.GetHelpFor([]string{consts.ArmoryStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Bool("I", "insecure", false, "skip tls certificate validation")
			// 	f.String("p", "proxy", "", "specify a proxy url (e.g. http://localhost:8080)")
			// 	f.Bool("c", "ignore-cache", false, "ignore metadata cache, force refresh")
			// 	f.String("t", "timeout", "15m", "download timeout")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	armory.ArmoryCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		}
		server.AddCommand(armoryCmd)

		armoryCmd.AddCommand(&cobra.Command{
			Use:   consts.InstallStr,
			Short: "Install an alias or extension",
			Long:  help.GetHelpFor([]string{consts.ArmoryStr, consts.InstallStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Bool("I", "insecure", false, "skip tls certificate validation")
			// 	f.String("p", "proxy", "", "specify a proxy url (e.g. http://localhost:8080)")
			// 	f.Bool("c", "ignore-cache", false, "ignore metadata cache, force refresh")
			// 	f.String("t", "timeout", "15m", "download timeout")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	armory.ArmoryInstallCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("name", "name of the extension or alias to install")
			// },
			// Completer: func(prefix string, args []string) []string {
			// 	return armory.AliasExtensionOrBundleCompleter(prefix, args, con)
			// },
			// GroupID: consts.GenericHelpGroup,
		})

		armoryCmd.AddCommand(&cobra.Command{
			Use:   consts.UpdateStr,
			Short: "Update installed an aliases and extensions",
			Long:  help.GetHelpFor([]string{consts.ArmoryStr, consts.UpdateStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Bool("I", "insecure", false, "skip tls certificate validation")
			// 	f.String("p", "proxy", "", "specify a proxy url (e.g. http://localhost:8080)")
			// 	f.Bool("c", "ignore-cache", false, "ignore metadata cache, force refresh")
			// 	f.String("t", "timeout", "15m", "download timeout")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	armory.ArmoryUpdateCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})

		armoryCmd.AddCommand(&cobra.Command{
			Use:   consts.SearchStr,
			Short: "Search for aliases and extensions by name (regex)",
			Long:  help.GetHelpFor([]string{consts.ArmoryStr, consts.SearchStr}),
			// Args: func(a *grumble.Args) {
			// 	a.String("name", "a name regular expression")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	armory.ArmorySearchCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})

		// [ Update ] --------------------------------------------------------------

		server.AddCommand(&cobra.Command{
			Use:   consts.UpdateStr,
			Short: "Check for updates",
			Long:  help.GetHelpFor([]string{consts.UpdateStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Bool("P", "prereleases", false, "include pre-released (unstable) versions")
			// 	f.String("p", "proxy", "", "specify a proxy url (e.g. http://localhost:8080)")
			// 	f.String("s", "save", "", "save downloaded files to specific directory (default user home dir)")
			// 	f.Bool("I", "insecure", false, "skip tls certificate validation")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	update.UpdateCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		server.AddCommand(&cobra.Command{
			Use:   consts.VersionStr,
			Short: "Display version information",
			Long:  help.GetHelpFor([]string{consts.VersionStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	update.VerboseVersionsCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		// [ Jobs ] -----------------------------------------------------------------

		server.AddCommand(&cobra.Command{
			Use:   consts.JobsStr,
			Short: "Job control",
			Long:  help.GetHelpFor([]string{consts.JobsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("k", "kill", -1, "kill a background job")
			// 	f.Bool("K", "kill-all", false, "kill all jobs")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	jobs.JobsCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		server.AddCommand(&cobra.Command{
			Use:   consts.MtlsStr,
			Short: "Start an mTLS listener",
			Long:  help.GetHelpFor([]string{consts.MtlsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("L", "lhost", "", "interface to bind server to")
			// 	f.Int("l", "lport", generate.DefaultMTLSLPort, "tcp listen port")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// 	f.Bool("p", "persistent", false, "make persistent across restarts")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	jobs.MTLSListenerCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		server.AddCommand(&cobra.Command{
			Use:   consts.WGStr,
			Short: "Start a WireGuard listener",
			Long:  help.GetHelpFor([]string{consts.WGStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("L", "lhost", "", "interface to bind server to")
			// 	f.Int("l", "lport", generate.DefaultWGLPort, "udp listen port")
			// 	f.Int("n", "nport", generate.DefaultWGNPort, "virtual tun interface listen port")
			// 	f.Int("x", "key-port", generate.DefaultWGKeyExPort, "virtual tun interface key exchange port")
			// 	f.Bool("p", "persistent", false, "make persistent across restarts")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	jobs.WGListenerCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		server.AddCommand(&cobra.Command{
			Use:   consts.DnsStr,
			Short: "Start a DNS listener",
			Long:  help.GetHelpFor([]string{consts.DnsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("d", "domains", "", "parent domain(s) to use for DNS c2")
			// 	f.Bool("c", "no-canaries", false, "disable dns canary detection")
			// 	f.String("L", "lhost", "", "interface to bind server to")
			// 	f.Int("l", "lport", generate.DefaultDNSLPort, "udp listen port")
			// 	f.Bool("D", "disable-otp", false, "disable otp authentication")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// 	f.Bool("p", "persistent", false, "make persistent across restarts")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	jobs.DNSListenerCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		server.AddCommand(&cobra.Command{
			Use:   consts.HttpStr,
			Short: "Start an HTTP listener",
			Long:  help.GetHelpFor([]string{consts.HttpStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("d", "domain", "", "limit responses to specific domain")
			// 	f.String("w", "website", "", "website name (see websites cmd)")
			// 	f.String("L", "lhost", "", "interface to bind server to")
			// 	f.Int("l", "lport", generate.DefaultHTTPLPort, "tcp listen port")
			// 	f.Bool("D", "disable-otp", false, "disable otp authentication")
			// 	f.String("T", "long-poll-timeout", "1s", "server-side long poll timeout")
			// 	f.String("J", "long-poll-jitter", "2s", "server-side long poll jitter")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// 	f.Bool("p", "persistent", false, "make persistent across restarts")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	jobs.HTTPListenerCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		server.AddCommand(&cobra.Command{
			Use:   consts.HttpsStr,
			Short: "Start an HTTPS listener",
			Long:  help.GetHelpFor([]string{consts.HttpsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("d", "domain", "", "limit responses to specific domain")
			// 	f.String("w", "website", "", "website name (see websites cmd)")
			// 	f.String("L", "lhost", "", "interface to bind server to")
			// 	f.Int("l", "lport", generate.DefaultHTTPSLPort, "tcp listen port")
			// 	f.Bool("D", "disable-otp", false, "disable otp authentication")
			// 	f.String("T", "long-poll-timeout", "1s", "server-side long poll timeout")
			// 	f.String("J", "long-poll-jitter", "2s", "server-side long poll jitter")
			//
			// 	f.String("c", "cert", "", "PEM encoded certificate file")
			// 	f.String("k", "key", "", "PEM encoded private key file")
			// 	f.Bool("e", "lets-encrypt", false, "attempt to provision a let's encrypt certificate")
			// 	f.Bool("E", "disable-randomized-jarm", false, "disable randomized jarm fingerprints")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// 	f.Bool("p", "persistent", false, "make persistent across restarts")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	jobs.HTTPSListenerCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		server.AddCommand(&cobra.Command{
			Use:   consts.StageListenerStr,
			Short: "Start a stager listener",
			Long:  help.GetHelpFor([]string{consts.StageListenerStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("p", "profile", "", "implant profile name to link with the listener")
			// 	f.String("u", "url", "", "URL to which the stager will call back to")
			// 	f.String("c", "cert", "", "path to PEM encoded certificate file (HTTPS only)")
			// 	f.String("k", "key", "", "path to PEM encoded private key file (HTTPS only)")
			// 	f.Bool("e", "lets-encrypt", false, "attempt to provision a let's encrypt certificate (HTTPS only)")
			// 	f.StringL("aes-encrypt-key", "", "encrypt stage with AES encryption key")
			// 	f.StringL("aes-encrypt-iv", "", "encrypt stage with AES encryption iv")
			// 	f.String("C", "compress", "none", "compress the stage before encrypting (zlib, gzip, deflate9, none)")
			// 	f.Bool("P", "prepend-size", false, "prepend the size of the stage to the payload (to use with MSF stagers)")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	jobs.StageListenerCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		// [ Operators ] --------------------------------------------------------------

		server.AddCommand(&cobra.Command{
			Use:   consts.OperatorsStr,
			Short: "Manage operators",
			Long:  help.GetHelpFor([]string{consts.OperatorsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	operators.OperatorsCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.MultiplayerHelpGroup,
		})

		// Server-only commands.
		if serverCmds != nil {
			server.AddCommand(serverCmds()...)
		}

		// [ Sessions ] --------------------------------------------------------------

		sessionsCmd := &cobra.Command{
			Use:   consts.SessionsStr,
			Short: "Session management",
			Long:  help.GetHelpFor([]string{consts.SessionsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("i", "interact", "", "interact with a session")
			// 	f.String("k", "kill", "", "kill the designated session")
			// 	f.Bool("K", "kill-all", false, "kill all the sessions")
			// 	f.Bool("C", "clean", false, "clean out any sessions marked as [DEAD]")
			// 	f.Bool("F", "force", false, "force session action without waiting for results")
			//
			// 	f.String("f", "filter", "", "filter sessions by substring")
			// 	f.String("e", "filter-re", "", "filter sessions by regular expression")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	sessions.SessionsCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.SliverHelpGroup,
		}
		sessionsCmd.AddCommand(&cobra.Command{
			Use:   consts.PruneStr,
			Short: "Kill all stale/dead sessions",
			Long:  help.GetHelpFor([]string{consts.SessionsStr, consts.PruneStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Bool("F", "force", false, "Force the killing of stale/dead sessions")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	sessions.SessionsPruneCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.SliverHelpGroup,
		})
		server.AddCommand(sessionsCmd)

		// [ Use ] --------------------------------------------------------------

		useCmd := &cobra.Command{
			Use:   consts.UseStr,
			Short: "Switch the active session or beacon",
			Long:  help.GetHelpFor([]string{consts.UseStr}),
			Run:   func(cmd *cobra.Command, args []string) {},
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("id", "beacon or session ID", grumble.Default(""))
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	use.UseCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// Completer: func(prefix string, args []string) []string {
			// 	return use.BeaconAndSessionIDCompleter(prefix, args, con)
			// },
			GroupID: consts.SliverHelpGroup,
		}
		useCmd.AddCommand(&cobra.Command{
			Use:   consts.SessionsStr,
			Short: "Switch the active session",
			Long:  help.GetHelpFor([]string{consts.UseStr, consts.SessionsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Args: func(a *grumble.Args) {
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	use.UseSessionCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		useCmd.AddCommand(&cobra.Command{
			Use:   consts.BeaconsStr,
			Short: "Switch the active beacon",
			Long:  help.GetHelpFor([]string{consts.UseStr, consts.BeaconsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Args: func(a *grumble.Args) {
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	use.UseBeaconCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		server.AddCommand(useCmd)

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
			Use:   consts.GenerateStr,
			Short: "Generate an implant binary",
			Long:  help.GetHelpFor([]string{consts.GenerateStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("o", "os", "windows", "operating system")
			// 	f.String("a", "arch", "amd64", "cpu architecture")
			// 	f.String("N", "name", "", "agent name")
			// 	f.Bool("d", "debug", false, "enable debug features")
			// 	f.String("O", "debug-file", "", "path to debug output")
			// 	f.Bool("e", "evasion", false, "enable evasion features (e.g. overwrite user space hooks)")
			// 	f.Bool("l", "skip-symbols", false, "skip symbol obfuscation")
			// 	f.String("I", "template", "sliver", "implant code template")
			// 	f.Bool("E", "external-builder", false, "use an external builder")
			// 	f.Bool("G", "disable-sgn", false, "disable shikata ga nai shellcode encoder")
			//
			// 	f.String("c", "canary", "", "canary domain(s)")
			//
			// 	f.String("m", "mtls", "", "mtls connection strings")
			// 	f.String("g", "wg", "", "wg connection strings")
			// 	f.String("b", "http", "", "http(s) connection strings")
			// 	f.String("n", "dns", "", "dns connection strings")
			// 	f.String("p", "named-pipe", "", "named-pipe connection strings")
			// 	f.String("i", "tcp-pivot", "", "tcp-pivot connection strings")
			//
			// 	f.Int("X", "key-exchange", generate.DefaultWGKeyExPort, "wg key-exchange port")
			// 	f.Int("T", "tcp-comms", generate.DefaultWGNPort, "wg c2 comms port")
			//
			// 	f.Bool("R", "run-at-load", false, "run the implant entrypoint from DllMain/Constructor (shared library only)")
			//
			// 	f.String("Z", "strategy", "", "specify a connection strategy (r = random, rd = random domain, s = sequential)")
			// 	f.Int("j", "reconnect", generate.DefaultReconnect, "attempt to reconnect every n second(s)")
			// 	f.Int("P", "poll-timeout", generate.DefaultPollTimeout, "long poll request timeout")
			// 	f.Int("k", "max-errors", generate.DefaultMaxErrors, "max number of connection errors")
			//
			// 	f.String("w", "limit-datetime", "", "limit execution to before datetime")
			// 	f.Bool("x", "limit-domainjoined", false, "limit execution to domain joined machines")
			// 	f.String("y", "limit-username", "", "limit execution to specified username")
			// 	f.String("z", "limit-hostname", "", "limit execution to specified hostname")
			// 	f.String("F", "limit-fileexists", "", "limit execution to hosts with this file in the filesystem")
			// 	f.String("L", "limit-locale", "", "limit execution to hosts that match this locale")
			//
			// 	f.String("f", "format", "exe", "Specifies the output formats, valid values are: 'exe', 'shared' (for dynamic libraries), 'service' (see `psexec` for more info) and 'shellcode' (windows only)")
			// 	f.String("s", "save", "", "directory/file to the binary to")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.GenerateCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		}
		generateCmd.AddCommand(&cobra.Command{
			Use:   consts.BeaconStr,
			Short: "Generate a beacon binary",
			Long:  help.GetHelpFor([]string{consts.GenerateStr, consts.BeaconStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int64("D", "days", 0, "beacon interval days")
			// 	f.Int64("H", "hours", 0, "beacon interval hours")
			// 	f.Int64("M", "minutes", 0, "beacon interval minutes")
			// 	f.Int64("S", "seconds", 60, "beacon interval seconds")
			// 	f.Int64("J", "jitter", 30, "beacon interval jitter in seconds")
			//
			// 	// Generate flags
			// 	f.String("o", "os", "windows", "operating system")
			// 	f.String("a", "arch", "amd64", "cpu architecture")
			// 	f.String("N", "name", "", "agent name")
			// 	f.Bool("d", "debug", false, "enable debug features")
			// 	f.String("O", "debug-file", "", "path to debug output")
			// 	f.Bool("e", "evasion", false, "enable evasion features  (e.g. overwrite user space hooks)")
			// 	f.Bool("l", "skip-symbols", false, "skip symbol obfuscation")
			// 	f.String("I", "template", "sliver", "implant code template")
			// 	f.Bool("E", "external-builder", false, "use an external builder")
			// 	f.Bool("G", "disable-sgn", false, "disable shikata ga nai shellcode encoder")
			//
			// 	f.String("c", "canary", "", "canary domain(s)")
			//
			// 	f.String("m", "mtls", "", "mtls connection strings")
			// 	f.String("g", "wg", "", "wg connection strings")
			// 	f.String("b", "http", "", "http(s) connection strings")
			// 	f.String("n", "dns", "", "dns connection strings")
			// 	f.String("p", "named-pipe", "", "named-pipe connection strings")
			// 	f.String("i", "tcp-pivot", "", "tcp-pivot connection strings")
			//
			// 	f.Int("X", "key-exchange", generate.DefaultWGKeyExPort, "wg key-exchange port")
			// 	f.Int("T", "tcp-comms", generate.DefaultWGNPort, "wg c2 comms port")
			//
			// 	f.Bool("R", "run-at-load", false, "run the implant entrypoint from DllMain/Constructor (shared library only)")
			//
			// 	f.String("Z", "strategy", "", "specify a connection strategy (r = random, rd = random domain, s = sequential)")
			// 	f.Int("j", "reconnect", generate.DefaultReconnect, "attempt to reconnect every n second(s)")
			// 	f.Int("P", "poll-timeout", generate.DefaultPollTimeout, "long poll request timeout")
			// 	f.Int("k", "max-errors", generate.DefaultMaxErrors, "max number of connection errors")
			//
			// 	f.String("w", "limit-datetime", "", "limit execution to before datetime")
			// 	f.Bool("x", "limit-domainjoined", false, "limit execution to domain joined machines")
			// 	f.String("y", "limit-username", "", "limit execution to specified username")
			// 	f.String("z", "limit-hostname", "", "limit execution to specified hostname")
			// 	f.String("F", "limit-fileexists", "", "limit execution to hosts with this file in the filesystem")
			// 	f.String("L", "limit-locale", "", "limit execution to hosts that match this locale")
			//
			// 	f.String("f", "format", "exe", "Specifies the output formats, valid values are: 'exe', 'shared' (for dynamic libraries), 'service' (see `psexec` for more info) and 'shellcode' (windows only)")
			// 	f.String("s", "save", "", "directory/file to the binary to")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.GenerateBeaconCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
		})
		generateCmd.AddCommand(&cobra.Command{
			Use:   consts.StagerStr,
			Short: "Generate a stager using Metasploit (requires local Metasploit installation)",
			Long:  help.GetHelpFor([]string{consts.StagerStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("o", "os", "windows", "operating system")
			// 	f.String("a", "arch", "amd64", "cpu architecture")
			// 	f.String("L", "lhost", "", "Listening host")
			// 	f.Int("l", "lport", 8443, "Listening port")
			// 	f.String("r", "protocol", "tcp", "Staging protocol (tcp/http/https)")
			// 	f.String("f", "format", "raw", "Output format (msfvenom formats, see `help generate stager` for the list)")
			// 	f.String("b", "badchars", "", "bytes to exclude from stage shellcode")
			// 	f.String("s", "save", "", "directory to save the generated stager to")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.GenerateStagerCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		generateCmd.AddCommand(&cobra.Command{
			Use:   consts.CompilerInfoStr,
			Short: "Get information about the server's compiler",
			Long:  help.GetHelpFor([]string{consts.CompilerInfoStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.GenerateInfoCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		server.AddCommand(generateCmd)

		server.AddCommand(&cobra.Command{
			Use:   consts.RegenerateStr,
			Short: "Regenerate an implant",
			Long:  help.GetHelpFor([]string{consts.RegenerateStr}),
			// Args: func(a *grumble.Args) {
			// 	a.String("implant-name", "name of the implant")
			// },
			// Flags: func(f *grumble.Flags) {
			// 	f.String("s", "save", "", "directory/file to the binary to")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.RegenerateCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		})

		profilesCmd := &cobra.Command{
			Use:   consts.ProfilesStr,
			Short: "List existing profiles",
			Long:  help.GetHelpFor([]string{consts.ProfilesStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.ProfilesCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		}
		profilesCmd.AddCommand(&cobra.Command{
			Use:   consts.GenerateStr,
			Short: "Generate implant from a profile",
			Long:  help.GetHelpFor([]string{consts.ProfilesStr, consts.GenerateStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("s", "save", "", "directory/file to the binary to")
			// 	f.Bool("G", "disable-sgn", false, "disable shikata ga nai shellcode encoder")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("name", "name of the profile", grumble.Default(""))
			// },
			// Completer: func(prefix string, args []string) []string {
			// 	return generate.ProfileNameCompleter(prefix, args, con)
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.ProfilesGenerateCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		profilesNewCmd := &cobra.Command{
			Use:   consts.NewStr,
			Short: "Create a new implant profile (interactive session)",
			Long:  help.GetHelpFor([]string{consts.ProfilesStr, consts.NewStr}),
			// Flags: func(f *grumble.Flags) {
			// 	// Generate flags
			// 	f.String("o", "os", "windows", "operating system")
			// 	f.String("a", "arch", "amd64", "cpu architecture")
			//
			// 	f.Bool("d", "debug", false, "enable debug features")
			// 	f.String("O", "debug-file", "", "path to debug output")
			// 	f.Bool("e", "evasion", false, "enable evasion features")
			// 	f.Bool("l", "skip-symbols", false, "skip symbol obfuscation")
			// 	f.Bool("G", "disable-sgn", false, "disable shikata ga nai shellcode encoder")
			//
			// 	f.String("c", "canary", "", "canary domain(s)")
			//
			// 	f.String("N", "name", "", "implant name")
			// 	f.String("m", "mtls", "", "mtls connection strings")
			// 	f.String("g", "wg", "", "wg connection strings")
			// 	f.String("b", "http", "", "http(s) connection strings")
			// 	f.String("n", "dns", "", "dns connection strings")
			// 	f.String("p", "named-pipe", "", "named-pipe connection strings")
			// 	f.String("i", "tcp-pivot", "", "tcp-pivot connection strings")
			//
			// 	f.Int("X", "key-exchange", generate.DefaultWGKeyExPort, "wg key-exchange port")
			// 	f.Int("T", "tcp-comms", generate.DefaultWGNPort, "wg c2 comms port")
			//
			// 	f.Bool("R", "run-at-load", false, "run the implant entrypoint from DllMain/Constructor (shared library only)")
			// 	f.String("Z", "strategy", "", "specify a connection strategy (r = random, rd = random domain, s = sequential)")
			//
			// 	f.String("I", "template", "sliver", "implant code template")
			//
			// 	f.Int("j", "reconnect", generate.DefaultReconnect, "attempt to reconnect every n second(s)")
			// 	f.Int("P", "poll-timeout", generate.DefaultPollTimeout, "long poll request timeout")
			// 	f.Int("k", "max-errors", generate.DefaultMaxErrors, "max number of connection errors")
			//
			// 	f.String("w", "limit-datetime", "", "limit execution to before datetime")
			// 	f.Bool("x", "limit-domainjoined", false, "limit execution to domain joined machines")
			// 	f.String("y", "limit-username", "", "limit execution to specified username")
			// 	f.String("z", "limit-hostname", "", "limit execution to specified hostname")
			// 	f.String("F", "limit-fileexists", "", "limit execution to hosts with this file in the filesystem")
			// 	f.String("L", "limit-locale", "", "limit execution to hosts that match this locale")
			//
			// 	f.String("f", "format", "exe", "Specifies the output formats, valid values are: 'exe', 'shared' (for dynamic libraries), 'service' (see `psexec` for more info) and 'shellcode' (windows only)")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("name", "name of the profile", grumble.Default(""))
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.ProfilesNewCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		}
		profilesCmd.AddCommand(profilesNewCmd)

		// New Beacon Profile Command
		profilesNewCmd.AddCommand(&cobra.Command{
			Use:   consts.BeaconStr,
			Short: "Create a new implant profile (beacon)",
			Long:  help.GetHelpFor([]string{consts.ProfilesStr, consts.NewStr, consts.BeaconStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int64("D", "days", 0, "beacon interval days")
			// 	f.Int64("H", "hours", 0, "beacon interval hours")
			// 	f.Int64("M", "minutes", 0, "beacon interval minutes")
			// 	f.Int64("S", "seconds", 60, "beacon interval seconds")
			// 	f.Int64("J", "jitter", 30, "beacon interval jitter in seconds")
			// 	f.Bool("G", "disable-sgn", false, "disable shikata ga nai shellcode encoder")
			//
			// 	// Generate flags
			// 	f.String("o", "os", "windows", "operating system")
			// 	f.String("a", "arch", "amd64", "cpu architecture")
			//
			// 	f.Bool("d", "debug", false, "enable debug features")
			// 	f.String("O", "debug-file", "", "path to debug output")
			// 	f.Bool("e", "evasion", false, "enable evasion features")
			// 	f.Bool("l", "skip-symbols", false, "skip symbol obfuscation")
			//
			// 	f.String("c", "canary", "", "canary domain(s)")
			//
			// 	f.String("N", "name", "", "implant name")
			// 	f.String("m", "mtls", "", "mtls connection strings")
			// 	f.String("g", "wg", "", "wg connection strings")
			// 	f.String("b", "http", "", "http(s) connection strings")
			// 	f.String("n", "dns", "", "dns connection strings")
			// 	f.String("p", "named-pipe", "", "named-pipe connection strings")
			// 	f.String("i", "tcp-pivot", "", "tcp-pivot connection strings")
			// 	f.String("Z", "strategy", "", "specify a connection strategy (r = random, rd = random domain, s = sequential)")
			//
			// 	f.Int("X", "key-exchange", generate.DefaultWGKeyExPort, "wg key-exchange port")
			// 	f.Int("T", "tcp-comms", generate.DefaultWGNPort, "wg c2 comms port")
			//
			// 	f.Bool("R", "run-at-load", false, "run the implant entrypoint from DllMain/Constructor (shared library only)")
			//
			// 	f.String("I", "template", "sliver", "implant code template")
			//
			// 	f.Int("j", "reconnect", generate.DefaultReconnect, "attempt to reconnect every n second(s)")
			// 	f.Int("P", "poll-timeout", generate.DefaultPollTimeout, "long poll request timeout")
			// 	f.Int("k", "max-errors", generate.DefaultMaxErrors, "max number of connection errors")
			//
			// 	f.String("w", "limit-datetime", "", "limit execution to before datetime")
			// 	f.Bool("x", "limit-domainjoined", false, "limit execution to domain joined machines")
			// 	f.String("y", "limit-username", "", "limit execution to specified username")
			// 	f.String("z", "limit-hostname", "", "limit execution to specified hostname")
			// 	f.String("F", "limit-fileexists", "", "limit execution to hosts with this file in the filesystem")
			// 	f.String("L", "limit-locale", "", "limit execution to hosts that match this locale")
			//
			// 	f.String("f", "format", "exe", "Specifies the output formats, valid values are: 'exe', 'shared' (for dynamic libraries), 'service' (see `psexec` for more info) and 'shellcode' (windows only)")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("name", "name of the profile", grumble.Default(""))
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.ProfilesNewBeaconCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})

		profilesCmd.AddCommand(&cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove a profile",
			Long:  help.GetHelpFor([]string{consts.ProfilesStr, consts.RmStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("name", "name of the profile", grumble.Default(""))
			// },
			// Completer: func(prefix string, args []string) []string {
			// 	return generate.ProfileNameCompleter(prefix, args, con)
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.ProfilesRmCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		server.AddCommand(profilesCmd)

		implantBuildsCmd := &cobra.Command{
			Use:   consts.ImplantBuildsStr,
			Short: "List implant builds",
			Long:  help.GetHelpFor([]string{consts.ImplantBuildsStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.String("o", "os", "", "filter builds by operating system")
			// 	f.String("a", "arch", "", "filter builds by cpu architecture")
			// 	f.String("f", "format", "", "filter builds by artifact format")
			// 	f.Bool("s", "only-sessions", false, "filter interactive sessions")
			// 	f.Bool("b", "only-beacons", false, "filter beacons")
			// 	f.Bool("d", "no-debug", false, "filter builds by debug flag")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.ImplantsCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.GenericHelpGroup,
		}
		implantBuildsCmd.AddCommand(&cobra.Command{
			Use:   consts.RmStr,
			Short: "Remove implant build",
			Long:  help.GetHelpFor([]string{consts.ImplantBuildsStr, consts.RmStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			// Args: func(a *grumble.Args) {
			// 	a.String("name", "implant name", grumble.Default(""))
			// },
			// Completer: func(prefix string, args []string) []string {
			// 	return generate.ImplantBuildNameCompleter(prefix, args, generate.ImplantBuildFilter{}, con)
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.ImplantsRmCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			// GroupID: consts.GenericHelpGroup,
		})
		server.AddCommand(implantBuildsCmd)

		server.AddCommand(&cobra.Command{
			Use:   consts.CanariesStr,
			Short: "List previously generated canaries",
			Long:  help.GetHelpFor([]string{consts.CanariesStr}),
			// Flags: func(f *grumble.Flags) {
			// 	f.Bool("b", "burned", false, "show only triggered/burned canaries")
			//
			// 	f.Int("t", "timeout", defaultTimeout, "command timeout in seconds")
			// },
			Run: func(cmd *cobra.Command, args []string) {},
			// Run: func(ctx *grumble.Context) error {
			// 	con.Println()
			// 	generate.CanariesCmd(ctx, con)
			// 	con.Println()
			// 	return nil
			// },
			GroupID: consts.SliverHelpGroup,
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
