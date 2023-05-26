package cli

import (
	"errors"

	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/bishopfox/sliver/client/command"
	"github.com/bishopfox/sliver/client/command/use"
	"github.com/bishopfox/sliver/client/console"
)

func implantCmd(con *console.SliverConsole) *cobra.Command {
	makeCommands := command.SliverCommands(con)
	cmd := makeCommands()
	cmd.Use = "implant"

	// Flags
	command.Flags("sessions", false, cmd, func(f *pflag.FlagSet) {
		f.StringP("use", "s", "", "interact with a session")
	})

	// Prerunners (console setup, connection, etc)
	cmd.PersistentPreRunE, cmd.PersistentPostRunE = makeRunners(cmd, con)

	// Completions
	makeCompleters(cmd, con)

	return cmd
}

func makeRunners(implantCmd *cobra.Command, con *console.SliverConsole) (pre, post func(cmd *cobra.Command, args []string) error) {
	startConsole, closeConsole := consoleRunnerCmd(con, false)

	// The pre-run function connects to the server and sets up a "fake" console,
	// so we can have access to active sessions/beacons, and other stuff needed.
	pre = func(_ *cobra.Command, args []string) error {
		startConsole(implantCmd, args)

		// Set the active target.
		target, _ := implantCmd.Flags().GetString("use")
		if target == "" {
			return errors.New("no target implant to run command on")
		}

		session := con.GetSession(target)
		if session != nil {
			con.ActiveTarget.Set(session, nil)
		}

		return nil
	}

	return pre, closeConsole
}

func makeCompleters(cmd *cobra.Command, con *console.SliverConsole) {
	carapace.Gen(cmd)

	// Bind completers to flags (wrap them to use the same pre-runners)
	command.FlagComps(cmd, func(comp *carapace.ActionMap) {
		(*comp)["use"] = carapace.ActionCallback(func(c carapace.Context) carapace.Action {
			cmd.PersistentPreRunE(cmd, c.Args)
			return use.SessionIDCompleter(con)
		})
	})
}
