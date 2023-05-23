package cli

import (
	"errors"
	"fmt"

	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/command"
	"github.com/bishopfox/sliver/client/command/use"
	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

func implantCmd() *cobra.Command {
	// Implant command tree
	makeCommands := command.SliverCommands()
	cmd := makeCommands()
	cmd.Use = "implant"

	// Flags
	command.Flags("sessions", cmd, func(f *pflag.FlagSet) {
		f.StringP("use", "s", "", "interact with a session")
	})

	// Prerunners (console setup, connection, etc)
	cmd.PersistentPreRunE, cmd.PersistentPostRunE = makeRunners(cmd)

	// Completions
	makeCompleters(cmd)

	return cmd
}

func makeRunners(implantCmd *cobra.Command) (pre, post func(cmd *cobra.Command, args []string) error) {
	var rpc rpcpb.SliverRPCClient
	var ln *grpc.ClientConn
	var err error

	// The pre-run function connects to the server and sets up a "fake" console,
	// so we can have access to active sessions/beacons, and other stuff needed.
	pre = func(cmd *cobra.Command, args []string) error {
		configs := assets.GetConfigs()
		if len(configs) == 0 {
			fmt.Printf("No config files found at %s (see --help)\n", assets.GetConfigDir())
			return nil
		}
		config := selectConfig()
		if config == nil {
			return nil
		}

		rpc, ln, err = transport.MTLSConnect(config)
		if err != nil {
			fmt.Printf("Connection to server failed %s", err)
			return nil
		}

		// Create and setup the console application, without starting it.
		console.NewClient(rpc, nil, command.SliverCommands(), false)

		// Set the active target.
		target, _ := implantCmd.Flags().GetString("use")
		if target == "" {
			return errors.New("no target implant to run command on")
		}

		session := console.Client.GetSession(target)
		if session != nil {
			console.Client.ActiveTarget.Set(session, nil)
			console.Client.ExposeCommands()
		}

		return nil
	}

	// Close the server RPC connection once done.
	post = func(cmd *cobra.Command, args []string) error {
		return ln.Close()
	}

	return
}

func makeCompleters(cmd *cobra.Command) {
	carapace.Gen(cmd)

	// Bind completers to flags (wrap them to use the same pre-runners)
	command.FlagComps(cmd, func(comp *carapace.ActionMap) {
		(*comp)["use"] = carapace.ActionCallback(func(c carapace.Context) carapace.Action {
			cmd.PersistentPreRunE(nil, c.Args)
			return use.SessionIDCompleter()
		})
	})
}
