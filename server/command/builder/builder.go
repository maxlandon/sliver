package builder

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"

	"github.com/reeflective/team/client"
	"github.com/reeflective/team/client/commands"
	"github.com/reeflective/team/server"

	"github.com/bishopfox/sliver/client/command/completers"
	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/version"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/server/assets"
	"github.com/bishopfox/sliver/server/builder"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/generate"
	"github.com/bishopfox/sliver/server/log"
)

var builderLog = log.NamedLogger("cli", "builder")

const (
	nameFlagStr = "name"

	enableTargetFlagStr  = "enable-target"
	disableTargetFlagStr = "disable-target"

	operatorConfigFlagStr    = "config"
	operatorConfigDirFlagStr = "config-dir"
	quietFlagStr             = "quiet"
	logLevelFlagStr          = "log-level"
)

// A list of different builders which can run concurrently.
var builders []*builder.Builder

// Commands returns all commands for using Sliver as a builder backend.
func Commands(con *console.SliverClient, team *server.Server) []*cobra.Command {
	builderCmd := &cobra.Command{
		Use:   "builder",
		Short: "Start the process as an external builder",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			runBuilderCmd(cmd, args, team, con)
		},
	}

	builderCmd.Flags().StringP(nameFlagStr, "n", "", "Name of the builder (blank = hostname)")
	builderCmd.Flags().IntP(logLevelFlagStr, "L", 4, "Logging level: 1/fatal, 2/error, 3/warn, 4/info, 5/debug, 6/trace")
	builderCmd.Flags().StringP(operatorConfigFlagStr, "c", "", "operator config file path")
	builderCmd.Flags().StringP(operatorConfigDirFlagStr, "d", "", "operator config directory path")
	builderCmd.Flags().BoolP(quietFlagStr, "q", false, "do not write any content to stdout")

	// Artifact configuration options
	builderCmd.Flags().StringSlice(enableTargetFlagStr, []string{}, "force enable a target: format:goos/goarch")
	builderCmd.Flags().StringSlice(disableTargetFlagStr, []string{}, "force disable target arch: format:goos/goarch")

	completers.NewFlagCompsFor(builderCmd, func(comp *carapace.ActionMap) {
		(*comp)["enable-target"] = builderFormatsCompleter()
		(*comp)["disable-target"] = builderFormatsCompleter()
		(*comp)["config"] = commands.ConfigsAppCompleter(con.Teamclient, "detected Sliver configs")
	})

	return []*cobra.Command{builderCmd}
}

func runBuilderCmd(cmd *cobra.Command, args []string, team *server.Server, con *console.SliverClient) error {
	configPath, err := cmd.Flags().GetString(operatorConfigFlagStr)
	if err != nil {
		builderLog.Errorf("Failed to parse --%s flag %s\n", operatorConfigFlagStr, err)
		return err
	}

	configDir, err := cmd.Flags().GetString(operatorConfigDirFlagStr)
	if err != nil {
		builderLog.Errorf("Failed to parse --%s flag %s\n", operatorConfigDirFlagStr, err)
		return err
	}
	if configPath == "" && configDir == "" {
		builderLog.Errorf("Missing --%s or --%s flags\n", operatorConfigFlagStr, operatorConfigDirFlagStr)
		return err
	}

	quiet, err := cmd.Flags().GetBool(quietFlagStr)
	if err != nil {
		builderLog.Errorf("Failed to parse --%s flag %s\n", quietFlagStr, err)
	}
	if !quiet {
		log.RootLogger.AddHook(log.NewStdoutHook(log.RootLoggerName))
	}
	builderLog.Infof("Initializing Sliver external builder - %s", version.FullVersion())

	level, err := cmd.Flags().GetInt(logLevelFlagStr)
	if err != nil {
		builderLog.Errorf("Failed to parse --%s flag %s\n", logLevelFlagStr, err)
		return nil
	}
	log.RootLogger.SetLevel(log.LevelFrom(level))

	// Catch code crashes if everything fails no matter where.
	defer func() {
		if r := recover(); r != nil {
			builderLog.Printf("panic:\n%s", debug.Stack())
			builderLog.Fatalf("stacktrace from panic: \n" + string(debug.Stack()))
			os.Exit(99)
		}
	}()

	// Setup and configure builders.
	assets.Setup(true, false)
	c2.SetupDefaultC2Profiles()

	config := configPath
	multipleBuilders := (configPath == "" && configDir != "")
	if multipleBuilders {
		config = configDir
	}

	// Start all builders, non-blocking no matter how many builders.
	startBuilders(cmd, config, multipleBuilders, team, con)

	// Handle SIGHUP to reload builders
	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	// Handle interupt to stop all builders and exit
	sigInt := make(chan os.Signal, 1)
	signal.Notify(sigInt, os.Interrupt)
	for {
		select {
		case <-sigHup:
			builderLog.Info("Received SIGHUP, reloading builders")
			reloadBuilders(cmd, config, multipleBuilders, team, con)
		case <-sigInt:
			builderLog.Info("Received SIGINT, stopping all builders")
			for _, builderInst := range builders {
				builderInst.Stop()
			}
		}
	}
	// load the client configuration from the filesystem
	// return startBuilderClient(externalBuilder, configPath, team, con)

	return con.WaitSignal()
}

// Start all builders if multpile is true or a single builder otherwise.
func startBuilders(cmd *cobra.Command, config string, multpile bool, team *server.Server, con *console.SliverClient) {
	// We're passing a mutex to each builder to prevent concurrent builds.
	// Concurrent build should be fine in theory, but may cause resource
	// exhaustion on the server.
	// For single builders, this should have no impact.
	// Single builder
	if !multpile {
		err := startBuilderClientAlt(cmd, config, team, con)
		// singleBuilder, err := createBuilder(cmd, config, mutex)
		if err != nil {
			builderLog.Errorf("Failed to create builder: %s", err)
			os.Exit(-1)
		}
	} else {
		// Multiple builders
		builderLog.Infof("Reading config dir: %s", config)
		err := filepath.Walk(config, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				builderLog.Errorf("Failed to walk config dir: %s", err)
				return err
			}
			if info.IsDir() {
				return nil
			}
			go func() {
				builderLog.Infof("Starting builder with config file: %s", path)
				err := startBuilderClientAlt(cmd, path, team, con)
				// builderInst, err := createBuilder(cmd, path, mutex)
				if err != nil {
					builderLog.Errorf("Failed to create builder: %s", err)
					return
				}
				// builders = append(builders, builderInst)
				// builderInst.Start()
			}()
			return nil
		})
		if err != nil {
			builderLog.Errorf("Failed to walk config dir: %s", err)
			return
		}
	}
}

func reloadBuilders(cmd *cobra.Command, config string, multiple bool, team *server.Server, con *console.SliverClient) {
	builderLog.Infof("Reloading builders")
	for _, builderInst := range builders {
		builderInst.Stop()
	}
	builders = nil
	startBuilders(cmd, config, multiple, team, con)
}

//	func createBuilder(cmd *cobra.Command, configPath string, mutex *sync.Mutex) (*builder.Builder, error) {
//		externalBuilder := parseBuilderConfigFlags(cmd)
//		externalBuilder.Templates = []string{"sliver"}
//
//		// load the client configuration from the filesystem
//		config, err := clientAssets.ReadConfig(configPath)
//		if err != nil {
//			builderLog.Fatalf("Invalid config file: %s", err)
//			return nil, err
//		}
//		if externalBuilder.Name == "" {
//			builderLog.Infof("No builder name was specified, attempting to use hostname")
//			externalBuilder.Name, err = os.Hostname()
//			if err != nil {
//				builderLog.Errorf("Failed to get hostname: %s", err)
//				externalBuilder.Name = fmt.Sprintf("%s's %s builder", config.Operator, runtime.GOOS)
//			}
//		}
//		builderLog.Infof("Hello my name is: %s", externalBuilder.Name)
//
//		// connect to the server
//		builderLog.Infof("Connecting to %s@%s:%d ...", config.Operator, config.LHost, config.LPort)
//		rpc, ln, err := transport.MTLSConnect(config)
//		if err != nil {
//			builderLog.Errorf("Failed to connect to server %s@%s:%d: %s", config.Operator, config.LHost, config.LPort, err)
//			return nil, err
//		}
//
//		return builder.NewBuilder(externalBuilder, mutex, rpc, ln), nil
//	}
func parseBuilderConfigFlags(cmd *cobra.Command) *clientpb.Builder {
	externalBuilder := &clientpb.Builder{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}

	externalBuilder.CrossCompilers = generate.GetCrossCompilers()
	builderLog.Infof("Found %d cross-compilers", len(externalBuilder.CrossCompilers))
	for _, crossCompiler := range externalBuilder.CrossCompilers {
		builderLog.Debugf("Found cross-compiler: cc = '%s' cxx = '%s'", crossCompiler.GetCCPath(), crossCompiler.GetCXXPath())
	}

	externalBuilder.Targets = generate.GetCompilerTargets()
	builderLog.Infof("This machine has %d compiler targets", len(externalBuilder.Targets))
	for _, target := range externalBuilder.Targets {
		builderLog.Infof("[compiler target] %v", target)
	}

	parseForceEnableTargets(cmd, externalBuilder)
	parseForceDisableTargets(cmd, externalBuilder)

	name, err := cmd.Flags().GetString(nameFlagStr)
	if err != nil {
		builderLog.Errorf("Failed to parse --%s flag %s\n", nameFlagStr, err)
	}
	if name != "" {
		externalBuilder.Name = name
	}

	return externalBuilder
}

func parseForceEnableTargets(cmd *cobra.Command, externalBuilder *clientpb.Builder) {
	enableTargets, err := cmd.Flags().GetStringSlice(enableTargetFlagStr)
	if err != nil {
		builderLog.Errorf("Failed to parse --%s flag %s\n", enableTargetFlagStr, err)
		return
	}

	for _, target := range enableTargets {
		parts1 := strings.Split(target, ":")
		if len(parts1) != 2 {
			builderLog.Errorf("Invalid target format: %s", target)
			continue
		}
		parts2 := strings.Split(parts1[1], "/")
		if len(parts2) != 2 {
			builderLog.Errorf("Invalid target format: %s", target)
			continue
		}
		format := parts1[0]
		goos := parts2[0]
		goarch := parts2[1]
		target := &clientpb.CompilerTarget{
			GOOS:   goos,
			GOARCH: goarch,
		}
		switch strings.ToLower(format) {

		case "executable", "exe", "exec", "pe":
			target.Format = clientpb.OutputFormat_EXECUTABLE

		case "shared-lib", "sharedlib", "dll", "so", "dylib":
			target.Format = clientpb.OutputFormat_SHARED_LIB

		case "service", "svc":
			target.Format = clientpb.OutputFormat_SERVICE

		case "shellcode", "shell", "sc":
			target.Format = clientpb.OutputFormat_SHELLCODE

		default:
			builderLog.Warnf("Invalid format '%s' defaulting to executable", format)
			target.Format = clientpb.OutputFormat_EXECUTABLE
		}

		builderLog.Infof("Force enable target %s:%s/%s", target.Format, goos, goarch)
		externalBuilder.Targets = append(externalBuilder.Targets, target)
	}
}

func parseForceDisableTargets(cmd *cobra.Command, externalBuilder *clientpb.Builder) {
	disableTargets, err := cmd.Flags().GetStringSlice(disableTargetFlagStr)
	if err != nil {
		builderLog.Errorf("Failed to parse --%s flag %s\n", disableTargetFlagStr, err)
		return
	}

	for _, target := range disableTargets {
		parts1 := strings.Split(target, ":")
		if len(parts1) != 2 {
			builderLog.Errorf("Invalid target format: %s", target)
			continue
		}
		parts2 := strings.Split(parts1[1], "/")
		if len(parts2) != 2 {
			builderLog.Errorf("Invalid target format: %s", target)
			continue
		}

		var format clientpb.OutputFormat
		switch strings.ToLower(parts1[0]) {

		case "executable", "exe", "exec", "pe":
			format = clientpb.OutputFormat_EXECUTABLE

		case "shared-lib", "sharedlib", "dll", "so", "dylib":
			format = clientpb.OutputFormat_SHARED_LIB

		case "service", "svc":
			format = clientpb.OutputFormat_SERVICE

		case "shellcode", "shell", "sc":
			format = clientpb.OutputFormat_SHELLCODE

		default:
			builderLog.Warnf("Invalid format '%s' defaulting to executable", parts1[0])
			format = clientpb.OutputFormat_EXECUTABLE
		}

		goos := parts2[0]
		goarch := parts2[1]

		builderLog.Infof("Force disable target %s:%s/%s", format, goos, goarch)
		for i, t := range externalBuilder.Targets {
			if t.GOOS == goos && t.GOARCH == goarch && t.Format == format {
				externalBuilder.Targets = append(externalBuilder.Targets[:i], externalBuilder.Targets[i+1:]...)
				break
			}
		}
	}
}

func startBuilderClientAlt(cmd *cobra.Command, configPath string, team *server.Server, con *console.SliverClient) error {
	cfg := parseBuilderConfigFlags(cmd)
	cfg.Templates = []string{"sliver"}

	// Simply use our transport+RPC backend.
	cli := transport.NewClient()

	teamclient := team.Self(client.WithDialer(cli))

	// Now use our teamclient to fetch the configuration.
	config, err := teamclient.ReadConfig(configPath)
	if err != nil {
		builderLog.Fatalf("Invalid config file: %s", err)
		os.Exit(-1)
	}

	if cfg.Name == "" {
		builderLog.Infof("No builder name was specified, attempting to use hostname")
		cfg.Name, err = os.Hostname()
		if err != nil {
			builderLog.Errorf("Failed to get hostname: %s", err)
			cfg.Name = fmt.Sprintf("%s's %s builder", config.User, runtime.GOOS)
		}
	}
	builderLog.Infof("Hello my name is: %s", cfg.Name)
	builderLog.Infof("Connecting to %s@%s:%d ...", config.User, config.Host, config.Port)

	// And immediately connect to it.
	err = teamclient.Connect(client.WithConfig(config))
	if err != nil {
		return err
	}

	buildr := builder.NewBuilder(cfg, con.Rpc, cli.Conn)
	defer teamclient.Disconnect()

	return buildr.Start()
}

// func startBuilderClient(externalBuilder *clientpb.Builder, configPath string, team *server.Server, con *console.SliverClient) error {
// 	// Simply use our transport+RPC backend.
// 	cli := transport.NewClient()
//
// 	teamclient := team.Self(client.WithDialer(cli))
//
// 	// Now use our teamclient to fetch the configuration.
// 	config, err := teamclient.ReadConfig(configPath)
// 	if err != nil {
// 		builderLog.Fatalf("Invalid config file: %s", err)
// 		os.Exit(-1)
// 	}
//
// 	if externalBuilder.Name == "" {
// 		builderLog.Infof("No builder name was specified, attempting to use hostname")
// 		externalBuilder.Name, err = os.Hostname()
// 		if err != nil {
// 			builderLog.Errorf("Failed to get hostname: %s", err)
// 			externalBuilder.Name = fmt.Sprintf("%s's %s builder", config.User, runtime.GOOS)
// 		}
// 	}
// 	builderLog.Infof("Hello my name is: %s", externalBuilder.Name)
//
// 	builderLog.Infof("Connecting to %s@%s:%d ...", config.User, config.Host, config.Port)
//
// 	// And immediately connect to it.
// 	err = teamclient.Connect(client.WithConfig(config))
// 	if err != nil {
// 		return err
// 	}
//
// 	rpc := rpcpb.NewSliverRPCClient(cli.Conn)
//
// 	defer teamclient.Disconnect()
//
// 	// Let the builder do its work, blocking.
// 	return builder.StartBuilder(externalBuilder, rpc, con)
// }

// builderFormatsCompleter completes supported builders architectures.
func builderFormatsCompleter() carapace.Action {
	return carapace.ActionCallback(func(_ carapace.Context) carapace.Action {
		return carapace.ActionMultiParts(":", func(c carapace.Context) carapace.Action {
			var results []string

			switch len(c.Parts) {

			// Binary targets
			case 1:
				for _, target := range generate.GetCompilerTargets() {
					results = append(results, fmt.Sprintf("%s/%s", target.GOOS, target.GOARCH))
				}

				for _, target := range generate.GetUnsupportedTargets() {
					results = append(results, fmt.Sprintf("%s/%s", target.GOOS, target.GOARCH))
				}

				return carapace.ActionValues(results...).Tag("architectures")

				// Binary formats
			case 0:
				for _, fmt := range []string{"executable", "exe", "exec", "pe"} {
					results = append(results, fmt, clientpb.OutputFormat_EXECUTABLE.String())
				}

				for _, fmt := range []string{"shared-lib", "sharedlib", "dll", "so", "dylib"} {
					results = append(results, fmt, clientpb.OutputFormat_SHARED_LIB.String())
				}

				for _, fmt := range []string{"service", "svc"} {
					results = append(results, fmt, clientpb.OutputFormat_SERVICE.String())
				}

				for _, fmt := range []string{"shellcode", "shell", "sc"} {
					results = append(results, fmt, clientpb.OutputFormat_SHELLCODE.String())
				}

				return carapace.ActionValuesDescribed(results...).Tag("formats").Suffix(":")
			}

			return carapace.ActionValues()
		})
		// Our flags --enable-target/--disable-targets are list,
		// so users can coma-separate their values for a single flag.
	}).UniqueList(",")
}
