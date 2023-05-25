package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/command"
	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/transport"
)

func consoleCmd(con *console.SliverConsole) *cobra.Command {
	return &cobra.Command{
		Use:   "console",
		Short: "Start the sliver client console",
		RunE:  consoleRunnerCmd(con, true),
	}
}

func consoleRunnerCmd(con *console.SliverConsole, run bool) func(cmd *cobra.Command, args []string) error {
	return func(_ *cobra.Command, _ []string) error {
		appDir := assets.GetRootAppDir()
		logFile := initLogging(appDir)
		defer logFile.Close()

		configs := assets.GetConfigs()
		if len(configs) == 0 {
			fmt.Printf("No config files found at %s (see --help)\n", assets.GetConfigDir())
			return nil
		}
		config := selectConfig()
		if config == nil {
			return nil
		}

		// Don't clobber output when running a command from system shell.
		if run {
			fmt.Printf("Connecting to %s:%d ...\n", config.LHost, config.LPort)
		}

		rpc, _, err := transport.MTLSConnect(config)
		if err != nil {
			fmt.Printf("Connection to server failed %s", err)
			return nil
		}
		// defer ln.Close()

		return console.StartClient(con, rpc, command.ServerCommands(con, nil), command.SliverCommands(con), run)
	}
}
