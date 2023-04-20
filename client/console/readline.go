package console

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	insecureRand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/jandedobbeleer/oh-my-posh/src/engine"
	"github.com/reeflective/console"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/client/assets"
	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/prelude"
	"github.com/bishopfox/sliver/client/spin"
	"github.com/bishopfox/sliver/client/version"
	"github.com/bishopfox/sliver/protobuf/clientpb"
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

	// Prompt stuff
	prompt := con.App.Menu("implant").Prompt()
	prompt.LoadConfig("/home/user/sliver-test/prompt.omp.json")
	prompt.Env.Flags().Shell = "sliver"

	session := &SliverSession{con: con, Session: con.ActiveTarget.session}
	beacon := &SliverBeacon{con: con, Beacon: con.ActiveTarget.beacon}

	engine.Segments[engine.SegmentType("sliverSession")] = func() engine.SegmentWriter { return session }
	engine.Segments[engine.SegmentType("sliverBeacon")] = func() engine.SegmentWriter { return beacon }

	con.ActiveTarget.SessionPrompt = session
	con.ActiveTarget.BeaconPrompt = beacon

	// con.App.SetPrintASCIILogo(func(_ *grumble.App) {
	con.PrintLogo()
	// })

	go con.startEventLoop()
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

func (con *SliverConsole) startEventLoop() {
	eventStream, err := con.Rpc.Events(context.Background(), &commonpb.Empty{})
	if err != nil {
		fmt.Printf(Warn+"%s\n", err)
		return
	}
	for {
		event, err := eventStream.Recv()
		if err == io.EOF || event == nil {
			return
		}

		go con.triggerEventListeners(event)

		// Trigger event based on type
		echoed := false // Only echo the event once
		switch event.EventType {

		case consts.CanaryEvent:
			eventMsg := fmt.Sprintf(Bold+"WARNING: %s%s has been burned (DNS Canary)\n", Normal, event.Session.Name)
			sessions := con.GetSessionsByName(event.Session.Name)
			for _, session := range sessions {
				shortID := strings.Split(session.ID, "-")[0]
				con.PrintEventErrorf(eventMsg+"\n"+Clearln+"\t🔥 Session %s is affected\n", shortID)
			}
			echoed = true

		case consts.WatchtowerEvent:
			msg := string(event.Data)
			eventMsg := fmt.Sprintf(Bold+"WARNING: %s%s has been burned (seen on %s)\n", Normal, event.Session.Name, msg)
			sessions := con.GetSessionsByName(event.Session.Name)
			for _, session := range sessions {
				shortID := strings.Split(session.ID, "-")[0]
				con.PrintEventErrorf(eventMsg+"\n"+Clearln+"\t🔥 Session %s is affected", shortID)
			}
			echoed = true

		case consts.JoinedEvent:
			con.PrintEventInfof("%s has joined the game", event.Client.Operator.Name)
			echoed = true
		case consts.LeftEvent:
			con.PrintEventInfof("%s left the game", event.Client.Operator.Name)
			echoed = true

		case consts.JobStoppedEvent:
			job := event.Job
			con.PrintEventErrorf("Job #%d stopped (%s/%s)", job.ID, job.Protocol, job.Name)
			echoed = true

		case consts.SessionOpenedEvent:
			session := event.Session
			currentTime := time.Now().Format(time.RFC1123)
			shortID := strings.Split(session.ID, "-")[0]
			con.PrintEventInfof("Session %s %s - %s (%s) - %s/%s - %v",
				shortID, session.Name, session.RemoteAddress, session.Hostname, session.OS, session.Arch, currentTime)

			// Prelude Operator
			if prelude.ImplantMapper != nil {
				err = prelude.ImplantMapper.AddImplant(session, nil)
				if err != nil {
					con.PrintEventErrorf("Could not add session to Operator: %s", err)
				}
			}
			echoed = true

		case consts.SessionUpdateEvent:
			session := event.Session
			currentTime := time.Now().Format(time.RFC1123)
			shortID := strings.Split(session.ID, "-")[0]
			con.PrintEventInfof("Session %s has been updated - %v", shortID, currentTime)
			echoed = true

		case consts.SessionClosedEvent:
			session := event.Session
			currentTime := time.Now().Format(time.RFC1123)
			shortID := strings.Split(session.ID, "-")[0]
			con.PrintEventErrorf("Lost session %s %s - %s (%s) - %s/%s - %v",
				shortID, session.Name, session.RemoteAddress, session.Hostname, session.OS, session.Arch, currentTime)
			activeSession := con.ActiveTarget.GetSession()
			core.GetTunnels().CloseForSession(session.ID)
			core.CloseCursedProcesses(session.ID)
			if activeSession != nil && activeSession.ID == session.ID {
				con.ActiveTarget.Set(nil, nil)
				con.PrintEventErrorf("Active session disconnected")
				// con.App.SetPrompt(con.GetPrompt())
			}
			if prelude.ImplantMapper != nil {
				err = prelude.ImplantMapper.RemoveImplant(session)
				if err != nil {
					con.PrintEventErrorf("Could not remove session from Operator: %s", err)
				}
				con.PrintEventInfof("Removed session %s from Operator", session.Name)
			}
			echoed = true

		case consts.BeaconRegisteredEvent:
			beacon := &clientpb.Beacon{}
			proto.Unmarshal(event.Data, beacon)
			currentTime := time.Now().Format(time.RFC1123)
			shortID := strings.Split(beacon.ID, "-")[0]
			con.PrintEventInfof("Beacon %s %s - %s (%s) - %s/%s - %v",
				shortID, beacon.Name, beacon.RemoteAddress, beacon.Hostname, beacon.OS, beacon.Arch, currentTime)

			// Prelude Operator
			if prelude.ImplantMapper != nil {
				err = prelude.ImplantMapper.AddImplant(beacon, func(taskID string, cb func(*clientpb.BeaconTask)) {
					con.AddBeaconCallback(taskID, cb)
				})
				if err != nil {
					con.PrintEventErrorf("Could not add beacon to Operator: %s", err)
				}
			}
			echoed = true

		case consts.BeaconTaskResultEvent:
			con.triggerBeaconTaskCallback(event.Data)
			echoed = true

		}

		con.triggerReactions(event)

		// Only render if we echoed the event
		if echoed {
			// con.Printf(Clearln + con.GetPrompt())
			// bufio.NewWriter(con.App.Stdout()).Flush()
		}
	}
}

func (con *SliverConsole) CreateEventListener() (string, <-chan *clientpb.Event) {
	listener := make(chan *clientpb.Event, 100)
	listenerID, _ := uuid.NewV4()
	con.EventListeners.Store(listenerID.String(), listener)
	return listenerID.String(), listener
}

func (con *SliverConsole) RemoveEventListener(listenerID string) {
	value, ok := con.EventListeners.LoadAndDelete(listenerID)
	if ok {
		close(value.(chan *clientpb.Event))
	}
}

func (con *SliverConsole) triggerEventListeners(event *clientpb.Event) {
	con.EventListeners.Range(func(key, value interface{}) bool {
		listener := value.(chan *clientpb.Event)
		listener <- event // Do not block while sending the event to the listener
		return true
	})
}

func (con *SliverConsole) triggerReactions(event *clientpb.Event) {
	reactions := core.Reactions.On(event.EventType)
	if len(reactions) == 0 {
		return
	}

	// We need some special handling for SessionOpenedEvent to
	// set the new session as the active session
	currentActiveSession, currentActiveBeacon := con.ActiveTarget.Get()
	defer func() {
		con.ActiveTarget.Set(currentActiveSession, currentActiveBeacon)
	}()

	con.ActiveTarget.Set(nil, nil)
	if event.EventType == consts.SessionOpenedEvent {
		con.ActiveTarget.Set(event.Session, nil)
	} else if event.EventType == consts.BeaconRegisteredEvent {
		beacon := &clientpb.Beacon{}
		proto.Unmarshal(event.Data, beacon)
		con.ActiveTarget.Set(nil, beacon)
	}

	for _, reaction := range reactions {
		for _, line := range reaction.Commands {
			con.PrintInfof("Execute reaction: '%s'\n", line)
			// args, err := shlex.Split(line, true)
			// if err != nil {
			// 	con.PrintErrorf("Reaction command has invalid args: %s\n", err)
			// 	continue
			// }
			// err = con.App.RunCommand(args)
			// if err != nil {
			// 	con.PrintErrorf("Reaction command error: %s\n", err)
			// }
		}
	}
}

// triggerBeaconTaskCallback - Triggers the callback for a beacon task
func (con *SliverConsole) triggerBeaconTaskCallback(data []byte) {
	task := &clientpb.BeaconTask{}
	err := proto.Unmarshal(data, task)
	if err != nil {
		con.PrintErrorf("\rCould not unmarshal beacon task: %s\n", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	beacon, _ := con.Rpc.GetBeacon(ctx, &clientpb.Beacon{ID: task.BeaconID})

	// If the callback is not in our map then we don't do anything, the beacon task
	// was either issued by another operator in multiplayer mode or the client process
	// was restarted between the time the task was created and when the server got the result
	con.BeaconTaskCallbacksMutex.Lock()
	defer con.BeaconTaskCallbacksMutex.Unlock()
	if callback, ok := con.BeaconTaskCallbacks[task.ID]; ok {
		if con.Settings.BeaconAutoResults {
			if beacon != nil {
				con.PrintEventSuccessf("%s completed task %s", beacon.Name, strings.Split(task.ID, "-")[0])
			}
			task, err = con.Rpc.GetBeaconTaskContent(ctx, &clientpb.BeaconTask{
				ID: task.ID,
			})
			con.Printf(Clearln + "\r")
			if err == nil {
				callback(task)
			} else {
				con.PrintErrorf("Could not get beacon task content: %s\n", err)
			}
			con.Println()
		}
		delete(con.BeaconTaskCallbacks, task.ID)
	}
}

func (con *SliverConsole) AddBeaconCallback(taskID string, callback BeaconTaskCallback) {
	con.BeaconTaskCallbacksMutex.Lock()
	defer con.BeaconTaskCallbacksMutex.Unlock()
	con.BeaconTaskCallbacks[taskID] = callback
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

func (con *SliverConsole) GetSession(arg string) *clientpb.Session {
	sessions, err := con.Rpc.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		con.PrintWarnf("%s\n", err)
		return nil
	}
	for _, session := range sessions.GetSessions() {
		if session.Name == arg || strings.HasPrefix(session.ID, arg) {
			return session
		}
	}
	return nil
}

// GetSessionsByName - Return all sessions for an Implant by name
func (con *SliverConsole) GetSessionsByName(name string) []*clientpb.Session {
	sessions, err := con.Rpc.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		fmt.Printf(Warn+"%s\n", err)
		return nil
	}
	matched := []*clientpb.Session{}
	for _, session := range sessions.GetSessions() {
		if session.Name == name {
			matched = append(matched, session)
		}
	}
	return matched
}

// GetActiveSessionConfig - Get the active sessions's config
// TODO: Switch to query config based on ConfigID
func (con *SliverConsole) GetActiveSessionConfig() *clientpb.ImplantConfig {
	session := con.ActiveTarget.GetSession()
	if session == nil {
		return nil
	}
	c2s := []*clientpb.ImplantC2{}
	c2s = append(c2s, &clientpb.ImplantC2{
		URL:      session.GetActiveC2(),
		Priority: uint32(0),
	})
	config := &clientpb.ImplantConfig{
		Name:    session.GetName(),
		GOOS:    session.GetOS(),
		GOARCH:  session.GetArch(),
		Debug:   true,
		Evasion: session.GetEvasion(),

		MaxConnectionErrors: uint32(1000),
		ReconnectInterval:   int64(60),
		Format:              clientpb.OutputFormat_SHELLCODE,
		IsSharedLib:         true,
		C2:                  c2s,
	}
	return config
}

// PrintAsyncResponse - Print the generic async response information
func (con *SliverConsole) PrintAsyncResponse(resp *commonpb.Response) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	beacon, err := con.Rpc.GetBeacon(ctx, &clientpb.Beacon{ID: resp.BeaconID})
	if err != nil {
		fmt.Printf(Warn+"%s\n", err)
		return
	}
	con.PrintInfof("Tasked beacon %s (%s)\n", beacon.Name, strings.Split(resp.TaskID, "-")[0])
}

func (con *SliverConsole) Printf(format string, args ...any) {
	// return fmt.Fprintf(con.App.Stdout(), format, args...)
	con.App.LogTransient(format, args...)
}

func (con *SliverConsole) Println(args ...any) {
	// return fmt.Fprintln(con.App.Stdout(), args...)
	format := strings.Repeat("%s", len(args))
	con.App.LogTransient(format+"\n", args...)
}

func (con *SliverConsole) PrintInfof(format string, args ...any) {
	// return fmt.Fprintf(con.App.Stdout(), Clearln+Info+format, args...)
	con.App.LogTransient(Clearln+Info+format, args...)
}

func (con *SliverConsole) PrintSuccessf(format string, args ...any) {
	// return fmt.Fprintf(con.App.Stdout(), Clearln+Success+format, args...)
	con.App.LogTransient(Clearln+Success+format, args...)
}

func (con *SliverConsole) PrintWarnf(format string, args ...any) {
	// return fmt.Fprintf(con.App.Stdout(), Clearln+"⚠️  "+Normal+format, args...)
	con.App.LogTransient(Clearln+"⚠️  "+Normal+format, args...)
}

func (con *SliverConsole) PrintErrorf(format string, args ...any) {
	// return fmt.Fprintf(con.App.Stderr(), Clearln+Warn+format, args...)
	con.App.LogTransient(Clearln+Warn+format, args...)
}

func (con *SliverConsole) PrintEventInfof(format string, args ...any) {
	// return fmt.Fprintf(con.App.Stdout(), Clearln+Info+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
	con.App.LogTransient(Clearln+Info+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func (con *SliverConsole) PrintEventErrorf(format string, args ...any) {
	// return fmt.Fprintf(con.App.Stderr(), Clearln+Warn+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
	con.App.LogTransient(Clearln+Warn+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func (con *SliverConsole) PrintEventSuccessf(format string, args ...any) {
	// return fmt.Fprintf(con.App.Stdout(), Clearln+Success+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
	con.App.LogTransient(Clearln+Success+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func (con *SliverConsole) SpinUntil(message string, ctrl chan bool) {
	go spin.Until(os.Stdout, message, ctrl)
}

// FormatDateDelta - Generate formatted date string of the time delta between then and now
func (con *SliverConsole) FormatDateDelta(t time.Time, includeDate bool, color bool) string {
	nextTime := t.Format(time.UnixDate)

	var interval string

	if t.Before(time.Now()) {
		if includeDate {
			interval = fmt.Sprintf("%s (%s ago)", nextTime, time.Since(t).Round(time.Second))
		} else {
			interval = time.Since(t).Round(time.Second).String()
		}
		if color {
			interval = fmt.Sprintf("%s%s%s", Bold+Red, interval, Normal)
		}
	} else {
		if includeDate {
			interval = fmt.Sprintf("%s (in %s)", nextTime, time.Until(t).Round(time.Second))
		} else {
			interval = time.Until(t).Round(time.Second).String()
		}
		if color {
			interval = fmt.Sprintf("%s%s%s", Bold+Green, interval, Normal)
		}
	}
	return interval
}

//
// -------------------------- [ Active Target ] --------------------------
//

type ActiveTarget struct {
	session    *clientpb.Session
	beacon     *clientpb.Beacon
	observers  map[int]Observer
	observerID int

	// Prompts
	SessionPrompt *SliverSession
	BeaconPrompt  *SliverBeacon
}

// GetSessionInteractive - Get the active target(s)
func (s *ActiveTarget) GetInteractive() (*clientpb.Session, *clientpb.Beacon) {
	if s.session == nil && s.beacon == nil {
		fmt.Printf(Warn + "Please select a session or beacon via `use`\n")
		return nil, nil
	}
	return s.session, s.beacon
}

// GetSessionInteractive - Get the active target(s)
func (s *ActiveTarget) Get() (*clientpb.Session, *clientpb.Beacon) {
	return s.session, s.beacon
}

// GetSessionInteractive - GetSessionInteractive the active session
func (s *ActiveTarget) GetSessionInteractive() *clientpb.Session {
	if s.session == nil {
		fmt.Printf(Warn + "Please select a session via `use`\n")
		return nil
	}
	return s.session
}

// GetSession - Same as GetSession() but doesn't print a warning
func (s *ActiveTarget) GetSession() *clientpb.Session {
	return s.session
}

// GetBeaconInteractive - Get beacon interactive the active session
func (s *ActiveTarget) GetBeaconInteractive() *clientpb.Beacon {
	if s.beacon == nil {
		fmt.Printf(Warn + "Please select a beacon via `use`\n")
		return nil
	}
	return s.beacon
}

// GetBeacon - Same as GetBeacon() but doesn't print a warning
func (s *ActiveTarget) GetBeacon() *clientpb.Beacon {
	return s.beacon
}

// IsSession - Is the current target a session?
func (s *ActiveTarget) IsSession() bool {
	return s.session != nil
}

func (s *ActiveTarget) Request(cmd *cobra.Command) *commonpb.Request {
	if s.session == nil && s.beacon == nil {
		return nil
	}

	timeOutF := 120
	if cmd != nil {
		timeOutF, _ = cmd.Flags().GetInt("timeout")
	}

	timeout := int(time.Second) * timeOutF
	req := &commonpb.Request{}
	req.Timeout = int64(timeout)
	if s.session != nil {
		req.Async = false
		req.SessionID = s.session.ID
	}
	if s.beacon != nil {
		req.Async = true
		req.BeaconID = s.beacon.ID
	}
	return req
}

// Set - Change the active session
func (s *ActiveTarget) Set(session *clientpb.Session, beacon *clientpb.Beacon) {
	if session != nil && beacon != nil {
		// panic("cannot set both an active beacon and an active session")
		Client.PrintErrorf("cannot set both an active beacon and an active session")
		return
	}

	// Backgrounding
	if session == nil && beacon == nil {
		s.session = nil
		s.beacon = nil
		for _, observer := range s.observers {
			observer(s.session, s.beacon)
		}

		s.SessionPrompt.Session = nil
		s.BeaconPrompt.Beacon = nil

		// Switch back to server menu.
		if Client.App.CurrentMenu().Name() == "implant" {
			Client.App.SwitchMenu("")
		}
		return
	}

	// Foreground
	if session != nil {
		s.session = session
		s.beacon = nil
		for _, observer := range s.observers {
			observer(s.session, s.beacon)
		}

		s.SessionPrompt.Session = session
	} else if beacon != nil {
		s.beacon = beacon
		s.session = nil
		for _, observer := range s.observers {
			observer(s.session, s.beacon)
		}

		s.BeaconPrompt.Beacon = beacon
	}

	// Switch to implant menu.
	if Client.App.CurrentMenu().Name() != "implant" {
		Client.App.SwitchMenu("implant")
	}
}

// Background - Background the active session
func (s *ActiveTarget) Background() {
	s.session = nil
	s.beacon = nil
	for _, observer := range s.observers {
		observer(nil, nil)
	}

	// Switch back to server menu.
	if Client.App.CurrentMenu().Name() == "implant" {
		Client.App.SwitchMenu("")
	}
}
