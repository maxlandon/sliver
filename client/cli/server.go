package cli

import (
	"fmt"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/command"
	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
)

// serverCmd adds the tree of commands which only apply to either
// the client and/or server, and which do not require a target implant.
func serverCmd(con *console.SliverConsoleClient) *cobra.Command {
	con.IsCLI = true

	makeCommands := command.ServerCommands(con, nil)
	cmd := makeCommands()
	cmd.Use = "server"

	// Pre-post runners (console setup, connection, etc)
	cmd.PersistentPreRunE, cmd.PersistentPostRunE = consoleRunnerCmd(con, false)

	initServerCompletion(cmd, con)

	return cmd
}

// implantRootCompleters performs additional/specific completion setup for the server command tree in CLI mode.
func initServerCompletion(cmd *cobra.Command, con *console.SliverConsoleClient) {
	comps := carapace.Gen(cmd)

	comps.PreRun(func(ccmd *cobra.Command, args []string) {
		appDir := assets.GetRootAppDir()
		logFile := initLogging(appDir)
		defer logFile.Close()

		configs := assets.GetConfigs()
		if len(configs) == 0 {
			return
		}
		config := selectConfig()
		if config == nil {
			return
		}

		var rpc rpcpb.SliverRPCClient
		var err error

		rpc, _, err = transport.MTLSConnect(config)
		if err != nil {
			fmt.Printf("Connection to server failed %s", err)
			return
		}
		// cmd.PersistentPreRunE(nil, args)
		con.Rpc = rpc
	})
}
