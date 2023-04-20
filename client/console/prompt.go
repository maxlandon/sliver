package console

import (
	"strings"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/jandedobbeleer/oh-my-posh/src/engine"
	"github.com/jandedobbeleer/oh-my-posh/src/platform"
	"github.com/jandedobbeleer/oh-my-posh/src/properties"
)

// SetupPrompt creates different types responsible for rendering the various
// prompts (server and sliver menu) and loads the prompt configurations per menu.
func SetupPrompt(con *SliverConsole) {
	// Create the types and register them to the engine.
	server := &serverPrompt{con: con}
	implant := &sliverPrompt{con: con}
	con.ActiveTarget.prompt = implant

	engine.Segments[engine.SegmentType("sliverServer")] = func() engine.SegmentWriter { return server }
	engine.Segments[engine.SegmentType("sliverImplant")] = func() engine.SegmentWriter { return implant }

	// And load prompt configurations for each menu.
	con.App.CurrentMenu().Prompt().LoadConfig("/home/user/sliver-test/prompt.omp.json")
	con.App.Menu("implant").Prompt().LoadConfig("/home/user/sliver-test/prompt.omp.json")
}

type serverPrompt struct {
	con *SliverConsole
}

// Enabled returns true if no session/beacon is currently active.
func (s *serverPrompt) Enabled() bool {
	if s.con.ActiveTarget.session != nil {
		return false
	}
	if s.con.ActiveTarget.beacon != nil {
		return false
	}

	return true
}

// Template returns the default template of the server menu segment.
func (s *serverPrompt) Template() string {
	var tmpl string

	// Server or client
	tmpl += "<yellow>sliver</> "
	if s.con.IsServer {
		tmpl += "[server] "
	}

	// WorkingDirectory.
	tmpl += "<lightBlue>{{ .PWD }}</> "

	return tmpl
}

// Init implements the engine.SegmentWriter interface.
func (s *serverPrompt) Init(props properties.Properties, env platform.Environment) {
}

type sliverPrompt struct {
	con *SliverConsole

	Type             string
	WorkingDirectory string

	// Session fields
	ID                string
	Name              string
	Hostname          string
	UUID              string
	Username          string
	UID               string
	GID               string
	OS                string
	Arch              string
	Transport         string
	RemoteAddress     string
	PID               int32
	Filename          string
	LastCheckin       int64
	ActiveC2          string
	Version           string
	Evasion           bool
	IsDead            bool
	ReconnectInterval int64
	ProxyURL          string
	Burned            bool
	Extensions        []string
	PeerID            int64
	Locale            string
	FirstContact      int64

	// Beacon fields
	Interval            int64
	Jitter              int64
	NextCheckin         int64
	TasksCount          int64
	TasksCountCompleted int64
}

// Enabled returns true if a session/beacon is active, and that
// any segment making use of this type must be rendered and printed.
func (s *sliverPrompt) Enabled() bool {
	if s.con.ActiveTarget.session != nil {
		return true
	}
	if s.con.ActiveTarget.beacon != nil {
		return true
	}

	return false
}

// Template returns the default template of a sliver session/beacon segment.
func (s *sliverPrompt) Template() string {
	var tmpl []string

	// Target type.
	switch s.Type {
	case "session":
		tmpl = append(tmpl, "[S]")
	case "beacon":
		tmpl = append(tmpl, "[B]")
	}

	tmpl = append(tmpl, "<red>{{ .Name }}</>")                                      // Implant name
	tmpl = append(tmpl, "as <yellow>{{ .Username }}</>@<yellow>{{ .Hostname }}</>") // user@host
	tmpl = append(tmpl, "<blue>{{ .WorkingDirectory }}</>")                         // pwd

	return strings.Join(tmpl, " ")
}

// Init implements the engine.SegmentWriter interface.
func (s *sliverPrompt) Init(props properties.Properties, env platform.Environment) {
}

func (s *sliverPrompt) loadProperties(session *clientpb.Session, beacon *clientpb.Beacon) {
	if session == nil && beacon == nil {
		*s = sliverPrompt{}
		return
	}

	if session != nil {
		s.Type = "session"

		s.ID = session.ID
		s.Name = session.Name
		s.Hostname = session.Hostname
		s.UUID = session.UUID
		s.Username = session.Username
		s.UID = session.UID
		s.GID = session.GID
		s.OS = session.OS
		s.Arch = session.Arch
		s.Transport = session.Transport
		s.RemoteAddress = session.RemoteAddress
		s.PID = session.PID
		s.Filename = session.Filename
		s.LastCheckin = session.LastCheckin
		s.ActiveC2 = session.ActiveC2
		s.Version = session.Version
		s.Evasion = session.Evasion
		s.IsDead = session.IsDead
		s.ReconnectInterval = session.ReconnectInterval
		s.ProxyURL = session.ProxyURL
		s.Burned = session.Burned
		s.Extensions = session.Extensions
		s.PeerID = session.PeerID
		s.Locale = session.Locale
		s.FirstContact = session.FirstContact
	}

	if beacon != nil {
		s.Type = "beacon"

		s.ID = beacon.ID
		s.Name = beacon.Name
		s.Hostname = beacon.Hostname
		s.UUID = beacon.UUID
		s.Username = beacon.Username
		s.UID = beacon.UID
		s.GID = beacon.GID
		s.OS = beacon.OS
		s.Arch = beacon.Arch
		s.Transport = beacon.Transport
		s.RemoteAddress = beacon.RemoteAddress
		s.PID = beacon.PID
		s.Filename = beacon.Filename
		s.LastCheckin = beacon.LastCheckin
		s.ActiveC2 = beacon.ActiveC2
		s.Version = beacon.Version
		s.Evasion = beacon.Evasion
		s.IsDead = beacon.IsDead
		s.ReconnectInterval = beacon.ReconnectInterval
		s.ProxyURL = beacon.ProxyURL
		s.Burned = beacon.Burned
		s.Locale = beacon.Locale
		s.FirstContact = beacon.FirstContact

		s.Interval = beacon.Interval
		s.Jitter = beacon.Jitter
		s.NextCheckin = beacon.NextCheckin
		s.TasksCount = beacon.TasksCount
		s.TasksCountCompleted = beacon.TasksCountCompleted
	}
}
