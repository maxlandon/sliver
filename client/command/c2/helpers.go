package c2

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
	"crypto/sha256"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/maxlandon/readline"
	rl "github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

const (
	defaultMTLSLPort  = 8888
	defaultHTTPLPort  = 80
	defaultHTTPSLPort = 443
	defaultDNSLPort   = 53
	defaultTCPPort    = 9898

	defaultReconnect = 60
	defaultMaxErrors = 1000

	defaultTimeout = 60
)

// PrintProfileSummaryLong - Get a detailed overview of a profile
func PrintProfileSummaryLong(profile *sliverpb.Malleable) {

	// Test for reference distances
	// ----dir := fmt.Sprintf(rl.YELLOW+"             ID: %s%s\n", rl.RESET, profile.ID)

	// Left hand
	id := fmt.Sprintf(rl.YELLOW+"            ID: %s%s", rl.RESET, profile.ID)
	name := fmt.Sprintf(rl.YELLOW+"          Name: %s%s", rl.RESET, profile.Name)
	dir := fmt.Sprintf(rl.YELLOW+"     Direction: %s%s", rl.RESET, profile.Direction.String())
	path := fmt.Sprintf(rl.YELLOW+"     Full Path: %s%s", rl.RESET, rl.Bold(FullTargetPath(profile)))
	var comms string
	if profile.CommDisabled {
		comms = rl.YELLOW + "no" + rl.RESET
	} else {
		comms = rl.GREEN + "yes" + rl.RESET
	}
	comm := fmt.Sprintf(rl.YELLOW+"          Comm: %s%s", rl.RESET, comms)

	// Right hand
	c2Type := fmt.Sprintf(rl.YELLOW+"          Type: %s%s", rl.RESET, profile.Type.String())
	errs := fmt.Sprintf(rl.YELLOW+"     Max errors: %s%d", rl.RESET, profile.MaxConnectionErrors)
	timeout := fmt.Sprintf(rl.YELLOW+" (Poll) Timeout: %s%s", rl.RESET, time.Duration(profile.PollTimeout))

	jitIntVal := fmt.Sprintf("%-3s / %3s", time.Duration(profile.Jitter), time.Duration(profile.Interval))
	jitInt := fmt.Sprintf(rl.YELLOW+"Jitter/Interval: %s%s", rl.RESET, jitIntVal)

	// Print the first part of the summary
	sWidth := rl.GetTermWidth()

	pad := getPromptPad(sWidth-20, len(id), len(c2Type))
	fmt.Println(id + pad + c2Type)
	pad = getPromptPad(sWidth-20, len(name), len(errs))
	fmt.Println(name + pad + errs)
	pad = getPromptPad(sWidth-20, len(dir), len(timeout))
	fmt.Println(dir + pad + timeout)
	pad = getPromptPad(sWidth-20, len(comm)-(len(comms))+3, len(jitInt)) // TODO: change this, hackish
	fmt.Println(comm + pad + jitInt)

	// The path is on its own empty line
	fmt.Println(path)

	// Bottom (Security)
	// TODO: Session Context ID on the right with ID/Name

	// Security Options
	if profile.Credentials.CertPEM != nil {
		fmt.Println()
		// TODO: derive hostnames from public key
		certSig := sha256.Sum256(profile.Credentials.CertPEM)
		fmt.Printf(rl.YELLOW+"    Public Key: %s%s\n", rl.RESET, certSig)
	} else {
		fmt.Println()
		login := rl.Dim("<implant name>")
		fmt.Printf(rl.YELLOW+"         Login: %s%s\n", rl.RESET, login)
		certSig := rl.Dim("<server key sig>")
		fmt.Printf(rl.YELLOW+"    Public Key: %s%s\n", rl.RESET, certSig)
	}

	// Protocol specific
	switch profile.C2 {
	case sliverpb.C2_MTLS:
	case sliverpb.C2_WG:
	case sliverpb.C2_DNS:
	case sliverpb.C2_HTTP:
	case sliverpb.C2_HTTPS:
	case sliverpb.C2_NamedPipe:
	}

}

func getPromptPad(total, base, menu int) (pad string) {
	var padLength = total - base - menu
	for i := 0; i < padLength; i++ {
		pad += " "
	}
	return
}

// PrintProfileSummary - Get a quick overview of a profile upon modification or creation, with analysis made
// here so that this is kinda context/malleable sensitive, you will have what you'll need each time.
func PrintProfileSummary(profile *sliverpb.Malleable) {

	fmt.Printf(rl.YELLOW+"            ID: %s%s\n", rl.RESET, profile.ID)
	fmt.Printf(rl.YELLOW+"          Name: %s%s\n", rl.RESET, profile.Name)
	fmt.Printf(rl.YELLOW+"          Type: %s%s\n", rl.RESET, profile.Direction.String())
	fmt.Printf(rl.YELLOW+"     Full Path: %s%s\n", rl.RESET, rl.Bold(FullTargetPath(profile)))

	// TODO: Session Context ID on the right with ID/Name

	switch profile.C2 {
	case sliverpb.C2_MTLS:
	case sliverpb.C2_WG:
	case sliverpb.C2_DNS:
	case sliverpb.C2_HTTP:
	case sliverpb.C2_HTTPS:
	case sliverpb.C2_NamedPipe:
	}

	// Security Options
	if profile.Credentials.CertPEM != nil {
		fmt.Println()
		// TODO: derive hostnames from public key
		certSig := sha256.Sum256(profile.Credentials.CertPEM)
		fmt.Printf(rl.YELLOW+"    Public Key: %s%s\n", rl.RESET, certSig)
	} else {
		fmt.Println()
		login := rl.Dim("<implant name>")
		fmt.Printf(rl.YELLOW+"         Login: %s%s\n", rl.RESET, login)
		certSig := rl.Dim("<server key sig>")
		fmt.Printf(rl.YELLOW+"    Public Key: %s%s\n", rl.RESET, certSig)
	}
}

// FullTargetPath - Get the entire target path of a Malleable profile.
func FullTargetPath(profile *sliverpb.Malleable) (path string) {
	path = profile.Hostname
	if profile.Port > 0 {
		path = path + ":" + strconv.Itoa(int(profile.Port))
	}
	if profile.Path != "" {
		path = path + profile.Path
	}
	return
}

// TransportConnection - Get the full transport connection string, depending
// on its state and runtime values. The padding is optional, but useful for tables.
func TransportConnection(transport *sliverpb.Transport, padding int) string {
	var lAddr = transport.LocalAddress
	var rAddr = transport.RemoteAddress
	var link string

	// Return an optionally padded connection string
	switch transport.Profile.Direction {
	case sliverpb.C2Direction_Bind:
		link = "==>"
	case sliverpb.C2Direction_Reverse:
		link = "<=="
	default:
		link = "<==>"
	}

	if !transport.Running {
		link = readline.Dim(link)
	} else {
		lAddr = readline.Bold(lAddr)
		rAddr = readline.Bold(rAddr)
	}

	// The non-padded connection string
	conn := fmt.Sprintf("%s  %s  %s", lAddr, link, rAddr)

	switch transport.Profile.Direction {
	case sliverpb.C2Direction_Bind:
		return fmt.Sprintf("        %*s", padding, conn)
	case sliverpb.C2Direction_Reverse:
		return fmt.Sprintf("%-*s", padding, conn)
	default:
		return conn
	}
}

// NewMalleable - A generic function that C2 channel writers can use in order to automatically parse
// most of the options needed by a basic C2 Malleable Profile. A few indications on parameters:
// @target:     Can be host, host:port or host:port/path combination.
//              No need for scheme: we derive it internally from the c2Type parameter.
func NewMalleable(c2Type sliverpb.C2, target string, direction sliverpb.C2Direction, opts ProfileOptions) (profile *sliverpb.Malleable) {

	// Base, with default timeouts, max conn errors, etc
	profile = defaultC2Profile()
	profile.Name = opts.Profile.Name
	profile.Direction = direction
	profile.C2 = c2Type

	// Target address/host/path/etc
	scheme, defaultPort := getProfileSheme(c2Type, profile)
	full := strings.Join([]string{scheme, target}, "://")
	profile.Hostname, _, profile.Port, _ = getHostPortFromURL(full)
	if profile.Port == 0 {
		profile.Port = defaultPort
	}

	// Base connection settings, which might be overriden
	// below if the transport session type is a beacon.
	configureConnectionSettings(opts, profile)
	profile.CommDisabled = opts.Profile.DisableComm

	// Beaconing & related allowed stacks
	configureBeaconing(opts, profile)

	return
}

// NewHandlerC2 - Similar to when you want to save a profile, parse your immediate Listen/Dial option into a profile,
// so the server has a standardized way of dealing with all C2 listeners/dialers at one. The only difference is no profile options.
func NewHandlerC2(c2Type sliverpb.C2, target string, direction sliverpb.C2Direction) (profile *sliverpb.Malleable) {

	// Base, with default timeouts, max conn errors, etc
	profile = defaultC2Profile()
	profile.Direction = direction
	profile.C2 = c2Type

	// Target address/host/path/etc
	scheme, defaultPort := getProfileSheme(c2Type, profile)
	full := strings.Join([]string{scheme, target}, "://")
	profile.Hostname, _, profile.Port, _ = getHostPortFromURL(full)
	if profile.Port == 0 {
		profile.Port = defaultPort
	}

	return
}

// GetShortID - Get a shorter 8 bits ID that is better to work with in commands and completions
func GetShortID(ID string) (short string) {
	if len(ID) < 8 {
		short = ID
	} else {
		short = ID[:8]
	}
	return
}

// defaultC2Profile - A C2 profile with default values into it, such as timeouts and pollers
func defaultC2Profile() *sliverpb.Malleable {
	profile := &sliverpb.Malleable{
		MaxConnectionErrors: 1000,
		PollTimeout:         int64(60 * time.Second),
		ReconnectInterval:   int64(30 * time.Second),
		Credentials:         &sliverpb.Credentials{},
		ContextSessionID:    core.ActiveTarget.UUID(), // Always give the current target
	}
	return profile
}

func getProfileSheme(c2Type sliverpb.C2, profile *sliverpb.Malleable) (scheme string, port uint32) {

	// Never override a port that has been set
	if profile.Port != 0 {
		scheme = strings.ToLower(c2Type.String())
		return scheme, profile.Port
	}

	switch profile.C2 {
	case sliverpb.C2_MTLS:
		profile.C2 = sliverpb.C2_MTLS
		profile.Port = defaultMTLSLPort
	case sliverpb.C2_WG:
		profile.C2 = sliverpb.C2_WG
		profile.Port = 53
		profile.ControlPort = 8888
		profile.KeyExchangePort = 1337
	case sliverpb.C2_DNS:
		profile.C2 = sliverpb.C2_DNS
		profile.Port = defaultDNSLPort
	case sliverpb.C2_HTTP:
		profile.C2 = sliverpb.C2_HTTP
		profile.Port = defaultHTTPLPort
	case sliverpb.C2_HTTPS:
		profile.C2 = sliverpb.C2_HTTPS
		profile.Port = defaultHTTPSLPort
	case sliverpb.C2_NamedPipe:
		profile.C2 = sliverpb.C2_NamedPipe
	case sliverpb.C2_TCP:
		profile.C2 = sliverpb.C2_TCP
		profile.Port = defaultTCPPort
	default:
		// We don't care, it's just for being able to
		// parse addresses easily with url.Parse(path)
		scheme = "unknown"
		return // Skip the overwrite below
	}

	scheme = strings.ToLower(c2Type.String())
	return scheme, profile.Port
}

// getHostPortFromURL - Parse the host:port combination given by arguments of commands (C2, transports, etc)
func getHostPortFromURL(hostport string) (host string, hostYes bool, port uint32, portYes bool) {
	uri, err := url.Parse(hostport)
	if err != nil {
		if uri.Host == hostport {
			rport, _ := strconv.Atoi(uri.Port())
			return uri.Hostname(), true, uint32(rport), true
		}
		if uri.Hostname() == hostport {
			return uri.Hostname(), true, 0, false
		}
	}
	rport, _ := strconv.Atoi(uri.Port())
	return uri.Hostname(), true, uint32(rport), false
}

// configureConnectionSettings - Overrides connection settings defaults if some or all
// have been specified by the user as command options.
func configureConnectionSettings(opts ProfileOptions, profile *sliverpb.Malleable) {

	if opts.Profile.PollTimeout != profile.PollTimeout {
		profile.PollTimeout = opts.Profile.PollTimeout * int64(time.Second)
	}
	if opts.Profile.MaxConnectionErrors != profile.MaxConnectionErrors {
		profile.MaxConnectionErrors = opts.Profile.MaxConnectionErrors
	}
	if opts.Profile.Reconnect != profile.ReconnectInterval {
		profile.ReconnectInterval = opts.Profile.Reconnect * int64(time.Second)
	}
}

// configureBeaconing - Sets the Beacon relevant parts of a C2 Profile
func configureBeaconing(opts ProfileOptions, profile *sliverpb.Malleable) (yes bool) {
	if opts.Beacon.IsBeacon {
		profile.Type = sliverpb.C2Type_Beacon
		profile.Jitter = int64(opts.Beacon.Jitter) * int64(time.Second)
		profile.Interval = int64(opts.Beacon.Interval) * int64(time.Second) //TODO: Parse human readable duration
		profile.CommDisabled = true                                         // Comms are not supported right now for beacons
		return true
	}
	profile.Type = sliverpb.C2Type_Session
	return false
}
