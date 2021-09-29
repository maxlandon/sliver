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

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// PrintProfileSummary - Get a quick overview of a profile upon modification or creation, with analysis made
// here so that this is kinda context/malleable sensitive, you will have what you'll need each time.
func PrintProfileSummaryLong(profile *sliverpb.C2Profile) {

	// Test for reference distances
	// ----dir := fmt.Sprintf(readline.YELLOW+"             ID: %s%s\n", readline.RESET, profile.ID)

	// Left hand
	id := fmt.Sprintf(readline.YELLOW+"            ID: %s%s", readline.RESET, profile.ID)
	name := fmt.Sprintf(readline.YELLOW+"          Name: %s%s", readline.RESET, profile.Name)
	dir := fmt.Sprintf(readline.YELLOW+"     Direction: %s%s", readline.RESET, profile.Direction.String())
	path := fmt.Sprintf(readline.YELLOW+"     Full Path: %s%s", readline.RESET, readline.Bold(FullTargetPath(profile)))
	var comms string
	if profile.CommDisabled {
		comms = readline.YELLOW + "no" + readline.RESET
	} else {
		comms = readline.GREEN + "yes" + readline.RESET
	}
	comm := fmt.Sprintf(readline.YELLOW+"          Comm: %s%s", readline.RESET, comms)

	// Right hand
	c2Type := fmt.Sprintf(readline.YELLOW+"          Type: %s%s", readline.RESET, profile.Type.String())
	errs := fmt.Sprintf(readline.YELLOW+"     Max errors: %s%d", readline.RESET, profile.MaxConnectionErrors)
	timeout := fmt.Sprintf(readline.YELLOW+" (Poll) Timeout: %s%s", readline.RESET, time.Duration(profile.PollTimeout))

	jitIntVal := fmt.Sprintf("%-3s / %3s", time.Duration(profile.Jitter), time.Duration(profile.Interval))
	jitInt := fmt.Sprintf(readline.YELLOW+"Jitter/Interval: %s%s", readline.RESET, jitIntVal)

	// Print the first part of the summary
	sWidth := readline.GetTermWidth()

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
		fmt.Printf(readline.YELLOW+"    Public Key: %s%s\n", readline.RESET, certSig)
	} else {
		fmt.Println()
		login := readline.Dim("<implant name>")
		fmt.Printf(readline.YELLOW+"         Login: %s%s\n", readline.RESET, login)
		certSig := readline.Dim("<server key sig>")
		fmt.Printf(readline.YELLOW+"    Public Key: %s%s\n", readline.RESET, certSig)
	}

	// Protocol specific
	switch profile.C2 {
	case sliverpb.C2Channel_MTLS:
	case sliverpb.C2Channel_WG:
	case sliverpb.C2Channel_DNS:
	case sliverpb.C2Channel_HTTP:
	case sliverpb.C2Channel_HTTPS:
	case sliverpb.C2Channel_NamedPipe:
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
func PrintProfileSummary(profile *sliverpb.C2Profile) {

	fmt.Printf(readline.YELLOW+"            ID: %s%s\n", readline.RESET, profile.ID)
	fmt.Printf(readline.YELLOW+"          Name: %s%s\n", readline.RESET, profile.Name)
	fmt.Printf(readline.YELLOW+"          Type: %s%s\n", readline.RESET, profile.Direction.String())
	fmt.Printf(readline.YELLOW+"     Full Path: %s%s\n", readline.RESET, readline.Bold(FullTargetPath(profile)))

	// TODO: Session Context ID on the right with ID/Name

	switch profile.C2 {
	case sliverpb.C2Channel_MTLS:
	case sliverpb.C2Channel_WG:
	case sliverpb.C2Channel_DNS:
	case sliverpb.C2Channel_HTTP:
	case sliverpb.C2Channel_HTTPS:
	case sliverpb.C2Channel_NamedPipe:
	}

	// Security Options
	if profile.Credentials.CertPEM != nil {
		fmt.Println()
		// TODO: derive hostnames from public key
		certSig := sha256.Sum256(profile.Credentials.CertPEM)
		fmt.Printf(readline.YELLOW+"    Public Key: %s%s\n", readline.RESET, certSig)
	} else {
		fmt.Println()
		login := readline.Dim("<implant name>")
		fmt.Printf(readline.YELLOW+"         Login: %s%s\n", readline.RESET, login)
		certSig := readline.Dim("<server key sig>")
		fmt.Printf(readline.YELLOW+"    Public Key: %s%s\n", readline.RESET, certSig)
	}
}

func FullTargetPath(profile *sliverpb.C2Profile) (path string) {
	path = profile.Hostname
	if profile.Port > 0 {
		path = path + ":" + strconv.Itoa(int(profile.Port))
	}
	if profile.Path != "" {
		path = path + profile.Path
	}
	return
}

// ParseProfile - A generic function that C2 channel writers can use in order to automatically parse
// most of the options needed by a basic C2 Malleable Profile. A few indications on parameters:
// @target:     Can be host, host:port or host:port/path combination.
//              No need for scheme: we derive it internally from the c2Type parameter.
func ParseProfile(c2Type sliverpb.C2Channel, target string, direction sliverpb.C2Direction, opts ProfileOptions) (profile *sliverpb.C2Profile) {

	// Base, with default timeouts, max conn errors, etc
	profile = defaultC2Profile()
	profile.Name = opts.Profile.Name
	profile.Direction = direction

	// Target address/host/path/etc
	scheme, defaultPort := getProfileSheme(c2Type, profile)
	full := strings.Join([]string{scheme, target}, "://")
	profile.Hostname, _, profile.Port, _ = getHostPortFromURL(full)
	if profile.Port == 0 {
		profile.Port = defaultPort // Always check the default port is set
	}

	// Base connection settings, which might be overriden
	// below if the transport session type is a beacon.
	configureConnectionSettings(opts, profile)
	profile.CommDisabled = opts.Profile.DisableComm
	profile.IsFallback = opts.Profile.IsFallback

	// Beaconing & related allowed stacks
	configureBeaconing(opts, profile)

	return
}

// ParseActionProfile - Similar to when you want to save a profile, parse your immediate Listen/Dial option into a profile,
// so the server has a standardized way of dealing with all C2 listeners/dialers at one. The only difference is no profile options.
func ParseActionProfile(c2Type sliverpb.C2Channel, target string, direction sliverpb.C2Direction) (profile *sliverpb.C2Profile) {

	// Base, with default timeouts, max conn errors, etc
	profile = defaultC2Profile()
	profile.Direction = direction

	// Target address/host/path/etc
	scheme, defaultPort := getProfileSheme(c2Type, profile)
	full := strings.Join([]string{scheme, target}, "://")
	profile.Hostname, _, profile.Port, _ = getHostPortFromURL(full)
	if profile.Port == 0 {
		profile.Port = defaultPort // Always check the default port is set
	}

	// When started from a handler, the profile is always marked anonymous: this
	// will not fetch it in further requests for profiles. NOTE: should be changed to: not added to DB

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
func defaultC2Profile() *sliverpb.C2Profile {
	profile := &sliverpb.C2Profile{
		IsFallback:          false,
		MaxConnectionErrors: 1000,
		PollTimeout:         60,
		Interval:            30,
		Credentials:         &sliverpb.Credentials{},
	}
	return profile
}

func getProfileSheme(c2Type sliverpb.C2Channel, profile *sliverpb.C2Profile) (scheme string, defaultPort uint32) {
	switch profile.C2 {
	case sliverpb.C2Channel_MTLS:
		profile.C2 = sliverpb.C2Channel_MTLS
		defaultPort = 9898
	case sliverpb.C2Channel_WG:
		profile.C2 = sliverpb.C2Channel_WG
	case sliverpb.C2Channel_DNS:
		profile.C2 = sliverpb.C2Channel_DNS
		defaultPort = 53
	case sliverpb.C2Channel_HTTP:
		profile.C2 = sliverpb.C2Channel_HTTP
		defaultPort = 8080
	case sliverpb.C2Channel_HTTPS:
		profile.C2 = sliverpb.C2Channel_HTTPS
		defaultPort = 443
	case sliverpb.C2Channel_NamedPipe:
		profile.C2 = sliverpb.C2Channel_NamedPipe
	default:
		// We don't care, it's just for being able to
		// parse addresses easily with url.Parse(path)
		scheme = "unknown"
		return // Skip the overwrite below
	}

	scheme = strings.ToLower(c2Type.String())
	return
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
func configureConnectionSettings(opts ProfileOptions, profile *sliverpb.C2Profile) {

	if opts.Profile.MaxConnectionErrors != profile.MaxConnectionErrors {
		profile.MaxConnectionErrors = opts.Profile.MaxConnectionErrors
	}
	if opts.Profile.Reconnect != int(profile.Interval) {
		profile.Interval = int64(opts.Profile.Reconnect) * int64(time.Second)
	}
	if opts.Profile.PollTimeout != int(profile.PollTimeout) {
		profile.PollTimeout = int64(opts.Profile.PollTimeout) * int64(time.Second)
	}
}

// configureBeaconing - Sets the Beacon relevant parts of a C2 Profile
func configureBeaconing(opts ProfileOptions, profile *sliverpb.C2Profile) (yes bool) {
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
