package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/command"
	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/transport"
)

var cmdConsole = &cobra.Command{
	Use:   "console",
	Short: "Start the sliver client console",
	Long:  ``,
	RunE:  startConsole,
}

func startConsole(_ *cobra.Command, _ []string) error {
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

	fmt.Printf("Connecting to %s:%d ...\n", config.LHost, config.LPort)
	rpc, ln, err := transport.MTLSConnect(config)
	if err != nil {
		fmt.Printf("Connection to server failed %s", err)
		return nil
	}
	defer ln.Close()

	// Create and setup the console application, without starting it.
	console.NewClient(rpc, command.ServerCommands(nil), command.SliverCommands(), false)

	err = console.Client.App.Run()
	if err != nil {
		log.Printf("Run loop returned error: %v", err)
	}
	return err
}
