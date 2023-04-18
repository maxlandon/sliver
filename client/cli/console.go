package cli

import (
	"fmt"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/command"
	client "github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/spf13/cobra"
)

var cmdConsole = &cobra.Command{
	Use:   "console",
	Short: "Start the sliver client console",
	Long:  ``,
	RunE:  startConsole,
}

func startConsole(cmd *cobra.Command, args []string) error {
	appDir := assets.GetRootAppDir()
	logFile := initLogging(appDir)
	defer logFile.Close()

	return Start()
}

func Start() error {
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

	// Initialize the console application and bind commands first.
	client.Setup(command.ServerCommands(nil), command.SliverCommands)

	return client.StartReadline(rpc, false)
}
