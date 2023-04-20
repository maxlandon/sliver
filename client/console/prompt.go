package console

import (
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/jandedobbeleer/oh-my-posh/src/platform"
	"github.com/jandedobbeleer/oh-my-posh/src/properties"
)

type SliverSession struct {
	con *SliverConsole

	// Properties used in config
	*clientpb.Session

	// Additional fields
	WorkingDirectory string
}

func (s *SliverSession) Enabled() bool {
	if s.con.ActiveTarget.session == nil {
		return false
	}

	if s.Session == nil {
		return false
	}

	return true
}

func (s *SliverSession) Template() string {
	var tmpl string
	// Implant name and type.
	tmpl += "[S] <red>{{ .Name }}</> "

	// User and hostname
	tmpl += "as <yellow>{{ .Username }}</>@<yellow>{{ .Hostname }}</> "

	// WorkingDirectory.
	tmpl += "<blue>{{ .WorkingDirectory }}</> "

	// Operating system.
	tmpl += "<darkGray>({{.OS}}/{{.Arch}})</>"

	return tmpl
}

func (s *SliverSession) Init(props properties.Properties, env platform.Environment) {
}

type SliverBeacon struct {
	con *SliverConsole

	// Properties used in config
	*clientpb.Beacon

	// Additional fields
	WorkingDirectory string
}

func (s *SliverBeacon) Enabled() bool {
	if s.con.ActiveTarget.beacon == nil {
		return false
	}

	if s.Beacon == nil {
		return false
	}

	return true
}

func (s *SliverBeacon) Template() string {
	var tmpl string
	// Implant name and type.
	tmpl += "[B] <red>{{ .Name }}</> "

	// User and hostname
	tmpl += "as <yellow>{{ .Username }}</>@<yellow>{{ .Hostname }}</> "

	// WorkingDirectory.
	tmpl += "<blue>{{ .WorkingDirectory }}</> "

	// Operating system.
	tmpl += "<darkGray>({{.OS}}/{{.Arch}})</>"

	return tmpl
}

func (s *SliverBeacon) Init(props properties.Properties, env platform.Environment) {
}
