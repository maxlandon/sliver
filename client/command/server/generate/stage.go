package generate

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
	"os"

	"github.com/bishopfox/sliver/client/log"
)

// Generate - Configure and compile stage or stager payloads
type Generate struct {
}

// Execute - Configure and compile stage or stager payloads
func (g *Generate) Execute(args []string) (err error) {
	return
}

// GenerateStage - Configure and compile a Sliver (stage) implant
type GenerateStage struct {
	StageOptions // Command makes use of full stage options
}

// StageOptions - All these options, regrouped by area, are used by any command that needs full
// configuration information for a stage Sliver implant.
type StageOptions struct {
	// CoreOptions - All options about OS/arch, files to save, debugs, etc.
	CoreOptions struct {
		Platform string `long:"platform" short:"O" description:"os/arch target platform (completed)" default:"windows/amd64" value-name:"target platform"`
		Format   string `long:"format" short:"f" description:"output formats (exe, shared (DLL), service (see 'psexec' for info), shellcode (Windows only)" default:"exe" value-name:"stage formats"`
		Profile  string `long:"profile-name" description:"implant profile name to use (use only with 'profiles new' command)"`
		Name     string `long:"name" short:"N" description:"implant name to use (overrides random name generation)"`
		Save     string `long:"save" short:"s" description:"directory/file where to save binary"`
		Debug    bool   `long:"debug" short:"d" description:"enable debug features (incompatible with obfuscation, and prevailing)"`
	} `group:"core options"`

	// TransportOptions - All options pertaining to transport/RPC matters
	TransportOptions struct {
		MTLS        []string `long:"mtls" short:"m" description:"mTLS C2 domain(s), comma-separated (ex: host:port)" env-delim:","`
		WireGuard   []string `long:"wg" short:"g" description:"WireGuard connection strings" env-delim:","`
		DNS         []string `long:"dns" short:"n" description:"DNS C2 domain(s), comma-separated (ex: mydomain.com)" env-delim:","`
		HTTP        []string `long:"http" short:"h" description:"HTTP(S) C2 domain(s)" env-delim:","`
		NamedPipe   []string `long:"named-pipe" short:"p" description:"Named pipe transport strings, comma-separated" env-delim:","`
		TCPPivot    []string `long:"tcp-pivot" short:"i" description:"TCP pivot transport strings, comma-separated" env-delim:","`
		KeyExchange int      `long:"key-exchange" short:"X" description:"WireGuard key exchange port" default:"1337"`
		TCPComms    int      `long:"tcp-comms" short:"T" description:"WireGuard C2 comms port" default:"8888"`
		Reconnect   int      `long:"reconnect" short:"j" description:"attempt to reconnect every n second(s)" default:"60"`
		PollTimeout int      `long:"poll-timeout" short:"P" description:"attempt to poll every n second(s)" default:"360"`
		MaxErrors   int      `long:"max-errors" short:"k" description:"max number of transport errors" default:"1000"`
	} `group:"transport options"`

	// SecurityOptions - All security-oriented options like restrictions.
	SecurityOptions struct {
		LimitDatetime  string `long:"limit-datetime" short:"w" description:"limit execution to before datetime"`
		LimitDomain    bool   `long:"limit-domain-joined" short:"D" description:"limit execution to domain joined machines"`
		LimitUsername  string `long:"limit-username" short:"U" description:"limit execution to specified username"`
		LimitHosname   string `long:"limit-hostname" short:"H" description:"limit execution to specified hostname"`
		LimitFileExits string `long:"limit-file-exists" short:"F" description:"limit execution to hosts with this file in the filesystem"`
	} `group:"security options"`

	// EvasionOptions - All proactive security options (obfuscation, evasion, etc)
	EvasionOptions struct {
		Canary      []string `long:"canary" short:"c" description:"DNS canary domain strings, comma-separated" env-delim:","`
		SkipSymbols bool     `long:"skip-obfuscation" short:"b" description:"skip binary/symbol obfuscation"`
		Evasion     bool     `long:"evasion" short:"e" description:"enable evasion features"`
	} `group:"evasion options"`
}

// Execute - Configure and compile a Sliver (stage) implant
func (g *GenerateStage) Execute(args []string) (err error) {
	config, err := ParseCompileFlags(g.StageOptions)
	if err != nil {
		return log.Error(err)
	}
	save := g.CoreOptions.Save
	if save == "" {
		save, _ = os.Getwd()
	}
	_, err = Compile(config, save)

	return
}
