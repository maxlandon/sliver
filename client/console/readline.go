package console

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	insecureRand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/reeflective/console"

	"github.com/bishopfox/sliver/client/assets"
	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/spin"
	"github.com/bishopfox/sliver/client/version"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

// Console is the client console
var Console *console.Console

var Client *SliverConsole

// Setup creates the console application, its menus and related settings
// (prompts, interrupt handlers, etc), and binds all required commands to each.
func Setup(serverCmds, sliverCmds console.Commands) {
	Console = console.New()

	// Server menu.
	server := Console.CurrentMenu()
	server.AddHistorySourceFile("server history", filepath.Join(assets.GetRootAppDir(), "history"))

	server.Short = "Server commands"
	server.SetCommands(serverCmds)

	// Implant menu.
	sliver := Console.NewMenu("implant")

	sliver.Short = "Implant commands"
	sliver.SetCommands(sliverCmds)
}

// StartReadline wraps the last client settings and starts the console.
func StartReadline(rpc rpcpb.SliverRPCClient, isServer bool) error {
	assets.Setup(false, false)
	settings, _ := assets.LoadSettings()

	con := &SliverConsole{
		App: Console,
		Rpc: rpc,
		ActiveTarget: &ActiveTarget{
			observers:  map[int]Observer{},
			observerID: 0,
		},
		EventListeners:           &sync.Map{},
		BeaconTaskCallbacks:      map[string]BeaconTaskCallback{},
		BeaconTaskCallbacksMutex: &sync.Mutex{},
		IsServer:                 isServer,
		Settings:                 settings,
	}

	Client = con

	// con.App.SetPrintASCIILogo(func(_ *grumble.App) {
	con.PrintLogo()
	// })

	// go con.startEventLoop()
	go core.TunnelLoop(rpc)

	err := con.App.Run()
	if err != nil {
		log.Printf("Run loop returned error: %v", err)
	}
	return err
}

type SliverConsole struct {
	App                      *console.Console
	Rpc                      rpcpb.SliverRPCClient
	ActiveTarget             *ActiveTarget
	EventListeners           *sync.Map
	BeaconTaskCallbacks      map[string]BeaconTaskCallback
	BeaconTaskCallbacksMutex *sync.Mutex
	IsServer                 bool
	Settings                 *assets.ClientSettings
}

func (con *SliverConsole) GetPrompt() string {
	prompt := Underline + "sliver" + Normal
	if con.IsServer {
		prompt = Bold + "[server] " + Normal + Underline + "sliver" + Normal
	}
	if con.ActiveTarget.GetSession() != nil {
		prompt += fmt.Sprintf(Bold+Red+" (%s)%s", con.ActiveTarget.GetSession().Name, Normal)
	} else if con.ActiveTarget.GetBeacon() != nil {
		prompt += fmt.Sprintf(Bold+Blue+" (%s)%s", con.ActiveTarget.GetBeacon().Name, Normal)
	}
	prompt += " > "
	return Clearln + prompt
}

func (con *SliverConsole) PrintLogo() {
	serverVer, err := con.Rpc.GetVersion(context.Background(), &commonpb.Empty{})
	if err != nil {
		panic(err.Error())
	}
	dirty := ""
	if serverVer.Dirty {
		dirty = fmt.Sprintf(" - %sDirty%s", Bold, Normal)
	}
	serverSemVer := fmt.Sprintf("%d.%d.%d", serverVer.Major, serverVer.Minor, serverVer.Patch)

	logo := asciiLogos[insecureRand.Intn(len(asciiLogos))]
	con.Println(logo)
	con.Println("All hackers gain " + abilities[insecureRand.Intn(len(abilities))])
	con.Printf(Info+"Server v%s - %s%s\n", serverSemVer, serverVer.Commit, dirty)
	if version.GitCommit != serverVer.Commit {
		con.Printf(Info+"Client %s\n", version.FullVersion())
	}
	con.Println(Info + "Welcome to the sliver shell, please type 'help' for options")
	con.Println()
	if serverVer.Major != int32(version.SemanticVersion()[0]) {
		con.Printf(Warn + "Warning: Client and server may be running incompatible versions.\n")
	}
	con.CheckLastUpdate()
}

func (con *SliverConsole) CheckLastUpdate() {
	now := time.Now()
	lastUpdate := getLastUpdateCheck()
	compiledAt, err := version.Compiled()
	if err != nil {
		log.Printf("Failed to parse compiled at timestamp %s", err)
		return
	}

	day := 24 * time.Hour
	if compiledAt.Add(30 * day).Before(now) {
		if lastUpdate == nil || lastUpdate.Add(30*day).Before(now) {
			con.Printf(Info + "Check for updates with the 'update' command\n\n")
		}
	}
}

func getLastUpdateCheck() *time.Time {
	appDir := assets.GetRootAppDir()
	lastUpdateCheckPath := filepath.Join(appDir, consts.LastUpdateCheckFileName)
	data, err := ioutil.ReadFile(lastUpdateCheckPath)
	if err != nil {
		log.Printf("Failed to read last update check %s", err)
		return nil
	}
	unixTime, err := strconv.Atoi(string(data))
	if err != nil {
		log.Printf("Failed to parse last update check %s", err)
		return nil
	}
	lastUpdate := time.Unix(int64(unixTime), 0)
	return &lastUpdate
}

func (con *SliverConsole) Printf(format string, args ...interface{}) {
	// return fmt.Fprintf(con.App.Stdout(), format, args...)
	con.App.LogTransient(format, args)
}

func (con *SliverConsole) Println(args ...interface{}) {
	// return fmt.Fprintln(con.App.Stdout(), args...)
	// con.App.LogTransient(args...)
}

func (con *SliverConsole) PrintInfof(format string, args ...interface{}) {
	// return fmt.Fprintf(con.App.Stdout(), Clearln+Info+format, args...)
	con.App.LogTransient(Clearln+Info+format, args...)
}

func (con *SliverConsole) PrintSuccessf(format string, args ...interface{}) {
	// return fmt.Fprintf(con.App.Stdout(), Clearln+Success+format, args...)
	con.App.LogTransient(Clearln+Success+format, args...)
}

func (con *SliverConsole) PrintWarnf(format string, args ...interface{}) {
	// return fmt.Fprintf(con.App.Stdout(), Clearln+"⚠️  "+Normal+format, args...)
	con.App.LogTransient(Clearln+"⚠️  "+Normal+format, args...)
}

func (con *SliverConsole) PrintErrorf(format string, args ...interface{}) {
	// return fmt.Fprintf(con.App.Stderr(), Clearln+Warn+format, args...)
	con.App.LogTransient(Clearln+Warn+format, args...)
}

func (con *SliverConsole) PrintEventInfof(format string, args ...interface{}) {
	// return fmt.Fprintf(con.App.Stdout(), Clearln+Info+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
	con.App.LogTransient(Clearln+Info+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func (con *SliverConsole) PrintEventErrorf(format string, args ...interface{}) {
	// return fmt.Fprintf(con.App.Stderr(), Clearln+Warn+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
	con.App.LogTransient(Clearln+Warn+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func (con *SliverConsole) PrintEventSuccessf(format string, args ...interface{}) {
	// return fmt.Fprintf(con.App.Stdout(), Clearln+Success+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
	con.App.LogTransient(Clearln+Success+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func (con *SliverConsole) SpinUntil(message string, ctrl chan bool) {
	go spin.Until(os.Stdout, message, ctrl)
}
