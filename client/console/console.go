package console

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

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
	"context"
	"fmt"
	"log"
	insecureRand "math/rand"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/maxlandon/gonsole"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/command"
	cmd "github.com/bishopfox/sliver/client/command/server/update"
	"github.com/bishopfox/sliver/client/completion"
	"github.com/bishopfox/sliver/client/constants"
	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	clientLog "github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/version"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

const (
	// ANSI Colors
	normal    = "\033[0m"
	black     = "\033[30m"
	red       = "\033[31m"
	green     = "\033[32m"
	orange    = "\033[33m"
	blue      = "\033[34m"
	purple    = "\033[35m"
	cyan      = "\033[36m"
	gray      = "\033[37m"
	bold      = "\033[1m"
	clearln   = "\r\x1b[2K"
	upN       = "\033[%dA"
	downN     = "\033[%dB"
	underline = "\033[4m"

	// Info - Display colorful information
	Info = bold + cyan + "[*] " + normal
	// Debug - Display debug information
	Debug = bold + purple + "[-] " + normal
	// Error - Notify error to a user
	Error = bold + red + "[!] " + normal
	// Warning - Notify important information, not an error
	Warning = bold + orange + "[!] " + normal
	// Woot - Display success
	Woot = bold + green + "[$] " + normal

	// ensure that nothing remains when we refresh the prompt
	seqClearScreenBelow = "\x1b[0J"
)

// ExtraCmds - Bind extra commands to the app object
type ExtraCmds func(menu *gonsole.Menu)

func init() {
	insecureRand.Seed(time.Now().Unix())
}

// Start - Console entrypoint
func Start(rpc rpcpb.SliverRPCClient, extraCmds ExtraCmds, config *assets.ClientConfig) error {

	// Keep the config reference
	serverConfig = config

	// As well, pass the RPC client to the transport package .
	// This will be needed by many packages in the client/ directory.
	transport.RPC = rpc

	// Start monitoring tunnels
	go core.TunnelLoop(rpc)

	// Create and setup the client console
	err := setup(rpc, extraCmds)
	if err != nil {
		return fmt.Errorf("Console setup failed: %s", err)
	}

	// Start monitoring incoming events
	go eventLoop(rpc)

	// Print banner and version information. (checks last updates)
	printSliverBanner(rpc)

	// Run the console. All errors are handled internally.
	core.Console.Run()

	return nil
}

// setup - Sets everything directly related to the client "part". This includes the full
// console configuration, setup, history loading, menu contexts, command registration, etc..
func setup(rpc rpcpb.SliverRPCClient, extraCmds ExtraCmds) (err error) {

	console := core.Console

	// Declare server and sliver contexts (menus).
	server := console.NewMenu(consts.ServerMenu)
	sliver := console.NewMenu(consts.SliverMenu)

	// The current one is the server
	console.SwitchMenu(consts.ServerMenu)

	// Get the user's console configuration from the server, and load it in the console.
	config, err := loadConsoleConfig(rpc)
	if err != nil {
		fmt.Printf(Warning + "Failed to load console configuration from server.\n")
		fmt.Printf(Info + "Defaulting to builtin values.\n")
	}
	console.LoadConfig(config)

	// Do the same for Sliver-specific settings
	settings, err := loadSliverSettings(rpc)
	if err != nil {
		fmt.Printf(Warning + "Failed to load Sliver-specific settings from server.\n")
		fmt.Printf(Info + "Defaulting to builtin values.\n")
	}
	assets.UserClientSettings = settings

	// Set prompts callback functions for both contexts
	server.Prompt.Callbacks = serverCallbacks
	sliver.Prompt.Callbacks = sliverCallbacks

	// Set history sources for both contexts
	setHistorySources()

	// Setup parser details
	console.SetParserOptions(flags.IgnoreUnknown | flags.HelpFlag)

	// Now that most things are set up in the console, pass it to the core
	// package, so that commands bound below can use it correctly.
	// Do the same for the completion package, which is needed by commands.
	core.Console = console
	completion.Console = console

	// Start monitoring all logs from the server and the client.
	err = clientLog.Init(console, rpc)
	if err != nil {
		return fmt.Errorf("Failed to start log monitor (%s)", err.Error())
	}

	// Bind admin commands if we are the server binary.
	if extraCmds != nil {
		extraCmds(server)
	}

	// Bind commands. In this function we also add some gonsole-provided
	// default commands, for help and console configuration management.
	command.BindCommands()

	return nil
}

// setHistorySources - Both contexts have different history sources available to the user.
func setHistorySources() {

	console := core.Console

	// Server context
	server := console.GetMenu(constants.ServerMenu)
	server.SetHistoryCtrlR("user-wise history", UserHist)
	server.SetHistoryAltR("client history", ClientHist)

	// Request a copy of the user history to the server
	getUserHistory()

	// We pass a function to the core package, which will
	// allow to refresh the session history as soon as we
	// interact with it.
	core.UserHistoryFunc = getUserHistory

	// Sliver context
	sliver := console.GetMenu(constants.SliverMenu)
	sliver.SetHistoryCtrlR("session history", SessionHist)
	sliver.SetHistoryAltR("user-wise history", UserHist)

	// We pass a function to the core package, which will
	// allow to refresh the session history as soon as we
	// interact with it.
	core.SessionHistoryFunc = SessionHist.RefreshLines
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func printVersionInfo(rpc rpcpb.SliverRPCClient) {
	serverVer, err := rpc.GetVersion(context.Background(), &commonpb.Empty{})
	if err != nil {
		panic(err.Error())
	}
	dirty := ""
	if serverVer.Dirty {
		dirty = fmt.Sprintf(" - %sDirty%s", bold, normal)
	}
	serverSemVer := fmt.Sprintf("%d.%d.%d", serverVer.Major, serverVer.Minor, serverVer.Patch)

	fmt.Println("All hackers gain " + abilities[insecureRand.Intn(len(abilities))])
	fmt.Printf(Info+"Server v%s - %s%s\n", serverSemVer, serverVer.Commit, dirty)
	if version.GitCommit != serverVer.Commit {
		fmt.Printf(Info+"Client %s\n", version.FullVersion())
	}
	fmt.Println(Info + "Welcome to the sliver shell, please type 'help' for options")
	if serverVer.Major != int32(version.SemanticVersion()[0]) {
		fmt.Printf(Warning + "Warning: Client and server may be running incompatible versions.\n")
	}
	checkLastUpdate()

}

func printLogo(rpc rpcpb.SliverRPCClient) {

	insecureRand.Seed(time.Now().Unix())
	logo := asciiLogos[insecureRand.Intn(len(asciiLogos))]
	fmt.Println(logo)
}

func checkLastUpdate() {
	now := time.Now()
	lastUpdate := cmd.GetLastUpdateCheck()
	compiledAt, err := version.Compiled()
	if err != nil {
		log.Printf("Failed to parse compiled at timestamp %s", err)
		return
	}

	day := 24 * time.Hour
	if compiledAt.Add(30 * day).Before(now) {
		if lastUpdate == nil || lastUpdate.Add(30*day).Before(now) {
			fmt.Printf(Info + "Check for updates with the 'update' command\n\n")
		}
	}
}

var abilities = []string{
	"first strike",
	"vigilance",
	"haste",
	"indestructible",
	"hexproof",
	"deathtouch",
	"fear",
	"epic",
	"ninjitsu",
	"recover",
	"persist",
	"conspire",
	"reinforce",
	"exalted",
	"annihilator",
	"infect",
	"undying",
	"living weapon",
	"miracle",
	"scavenge",
	"cipher",
	"evolve",
	"dethrone",
	"hidden agenda",
	"prowess",
	"dash",
	"exploit",
	"renown",
	"skulk",
	"improvise",
	"assist",
	"jump-start",
}

var asciiLogos = []string{
	red + `
 	  ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
	▒██    ▒ ▓██▒    ▓██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
	░ ▓██▄   ▒██░    ▒██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
	  ▒   ██▒▒██░    ░██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄
	▒██████▒▒░██████▒░██░   ▒▀█░  ░▒████▒░██▓ ▒██▒
	▒ ▒▓▒ ▒ ░░ ▒░▓  ░░▓     ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
	░ ░▒  ░ ░░ ░ ▒  ░ ▒ ░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░
	░  ░  ░    ░ ░    ▒ ░     ░░     ░     ░░   ░
		  ░      ░  ░ ░        ░     ░  ░   ░
` + normal,

	green + `
    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
` + normal,

	bold + gray + `
.------..------..------..------..------..------.
|S.--. ||L.--. ||I.--. ||V.--. ||E.--. ||R.--. |
| :/\: || :/\: || (\/) || :(): || (\/) || :(): |
| :\/: || (__) || :\/: || ()() || :\/: || ()() |
| '--'S|| '--'L|| '--'I|| '--'V|| '--'E|| '--'R|
` + "`------'`------'`------'`------'`------'`------'" + `
` + normal,
}
