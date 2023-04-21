package cli

import (
	"errors"
	"fmt"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/command"
	"github.com/bishopfox/sliver/client/command/use"
	client "github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
)

func implantCmd() *cobra.Command {
	// Generate the implant command tree
	cmd := command.SliverCommands()
	cmd.Use = "implant"

	// Make flags
	command.Flags("sessions", cmd, func(f *pflag.FlagSet) {
		f.StringP("use", "s", "", "interact with a session")
	})

	// Make the various runners (console setup, connection, etc)
	cmd.PersistentPreRunE, cmd.PersistentPostRunE = makeRunners(cmd)

	// Generate command and flags' argument completions
	makeCompleters(cmd)

	return cmd
}

func makeRunners(implantCmd *cobra.Command) (pre, post func(cmd *cobra.Command, args []string) error) {
	var rpc rpcpb.SliverRPCClient
	var ln *grpc.ClientConn
	var err error

	// The pre-run function connects to the server and sets up a "fake" console.
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

		// Initialize the console application and bind commands first, and init log.
		app := client.NewConsole(nil, command.SliverCommands)
		log.Init(nil)

		// Finish setup, and fake the console start.
		client.StartCLI(app, rpc, false)

		// Set the active target.
		target, _ := implantCmd.Flags().GetString("use")
		if target == "" {
			return errors.New("no target implant to run command on")
		}

		session := client.Client.GetSession(target)
		if session != nil {
			client.Client.ActiveTarget.Set(session, nil)
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
