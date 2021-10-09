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
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

var (
	// SupportedCompilerTargets - Supported compiler targets
	SupportedCompilerTargets = map[string]bool{
		"darwin/amd64":  true,
		"darwin/arm64":  true,
		"linux/386":     true,
		"linux/amd64":   true,
		"windows/386":   true,
		"windows/amd64": true,
	}
)

const (
	crossCompilerInfoURL = "https://github.com/BishopFox/sliver/wiki/Cross-Compiling-Implants"
)

//
// Configuration Parsing & Setup ----------------------------------------------------------------------------------
//

// ParseCompileFlags - Parse the entirety of flags necessary to compile an implant and all its C2 Transports
func ParseCompileFlags(g StageOptions) (*clientpb.ImplantConfig, error) {
	cfg := &clientpb.ImplantConfig{}

	var name string
	if g.CoreOptions.Name != "" {
		name = strings.ToLower(g.CoreOptions.Name)

		if name != "" {
			isAlphanumeric := regexp.MustCompile(`^[[:alnum:]]+$`).MatchString
			if !isAlphanumeric(name) {
				return nil, fmt.Errorf("Agent's name must be in alphanumeric only")
			}
		}
	}
	cfg.Name = name

	// Parse the flags strictly related to the build itself, not its transports
	err := ParseImplantBuildFlags(g, cfg)
	if err != nil {
		return nil, err
	}

	// Parse the complete C2 configuration
	err = parseC2Transports(g, cfg)
	if err != nil {
		return nil, err
	}

	var canaryDomains []string
	if 0 < len(g.EvasionOptions.Canary) {
		for _, canaryDomain := range g.EvasionOptions.Canary {
			if !strings.HasSuffix(canaryDomain, ".") {
				canaryDomain += "." // Ensure we have the FQDN
			}
			canaryDomains = append(canaryDomains, canaryDomain)
		}
	}
	cfg.CanaryDomains = canaryDomains

	return cfg, nil
}

// ParseImplantBuildFlags - Only parse the flags and options related to the implant build itself,
// and do not take into account anything related to the C2 transports that it will embbed.
func ParseImplantBuildFlags(g StageOptions, cfg *clientpb.ImplantConfig) (err error) {

	cfg.Debug = g.CoreOptions.Debug
	if g.CoreOptions.Debug {
		cfg.ObfuscateSymbols = false
	} else {
		cfg.ObfuscateSymbols = !g.EvasionOptions.SkipSymbols
	}
	cfg.Evasion = g.EvasionOptions.Evasion

	cfg.LimitDomainJoined = g.SecurityOptions.LimitDomain
	cfg.LimitHostname = g.SecurityOptions.LimitHosname
	cfg.LimitUsername = g.SecurityOptions.LimitUsername
	cfg.LimitDatetime = g.SecurityOptions.LimitDatetime
	cfg.LimitFileExists = g.SecurityOptions.LimitFileExits

	cfg.IsSharedLib = false
	cfg.IsService = false
	cfg.IsShellcode = false

	format := g.CoreOptions.Format
	switch format {
	case "exe":
		cfg.Format = clientpb.OutputFormat_EXECUTABLE
	case "shared":
		cfg.Format = clientpb.OutputFormat_SHARED_LIB
		cfg.IsSharedLib = true
	case "shellcode":
		cfg.Format = clientpb.OutputFormat_SHELLCODE
		cfg.IsShellcode = true
	case "service":
		cfg.Format = clientpb.OutputFormat_SERVICE
		cfg.IsService = true
	default:
		// default to exe
		cfg.Format = clientpb.OutputFormat_EXECUTABLE
	}

	platform := strings.ToLower(g.CoreOptions.Platform)

	if len(strings.Split(platform, "/")) != 2 {
		return fmt.Errorf("--platform value must be os/arch value")
	}
	targetOS := strings.Split(platform, "/")[0]
	targetArch := strings.Split(platform, "/")[1]

	targetOS, targetArch = getTargets(targetOS, targetArch)
	if targetOS == "" || targetArch == "" {
		return fmt.Errorf("An error happened with platform/arch validation")
	}

	cfg.GOOS = targetOS
	cfg.GOARCH = targetArch

	// Check to see if we can *probably* build the target binary
	if !checkBuildTargetCompatibility(cfg.Format, targetOS, targetArch) {
		return errors.New("Cancelled compilation process due to user aborting")
	}

	return
}

func getTargets(targetOS string, targetArch string) (string, string) {

	/* For UX we convert some synonymous terms */
	if targetOS == "darwin" || targetOS == "mac" || targetOS == "macos" || targetOS == "osx" {
		targetOS = "darwin"
	}
	if targetOS == "windows" || targetOS == "win" || targetOS == "shit" {
		targetOS = "windows"
	}
	if targetOS == "linux" || targetOS == "lin" {
		targetOS = "linux"
	}

	if targetArch == "amd64" || targetArch == "x64" || strings.HasPrefix(targetArch, "64") {
		targetArch = "amd64"
	}
	if targetArch == "386" || targetArch == "x86" || strings.HasPrefix(targetArch, "32") {
		targetArch = "386"
	}

	target := fmt.Sprintf("%s/%s", targetOS, targetArch)
	if _, ok := SupportedCompilerTargets[target]; !ok {
		log.Warnf("Unsupported compiler target %s%s%s, but we can try to compile a generic implant.",
			readline.YELLOW, target, readline.RESET,
		)
		log.Warnf("Generic implants do not support all commands/features.")
		prompt := &survey.Confirm{Message: "Attempt to build generic implant?"}
		var confirm bool
		survey.AskOne(prompt, &confirm)
		if !confirm {
			return "", ""
		}
	}

	return targetOS, targetArch
}

func parseC2Transports(g StageOptions, cfg *clientpb.ImplantConfig) (err error) {

	// Targets parsing in C2 Profiles ----------------------------------------------------------------
	if len(g.TransportOptions.MTLS) > 0 {
		for _, address := range g.TransportOptions.MTLS {
			profile := c2.ParseProfile(
				sliverpb.C2Channel_MTLS,      // A Channel using Mutual TLS
				address,                      // Targeting the host:[port] argument of our command
				sliverpb.C2Direction_Reverse, // A listener
				c2.ProfileOptions{},          // This will automatically parse Profile options into the protobuf
			)
			cfg.C2S = append(cfg.C2S, profile)
		}
	}

	if len(g.TransportOptions.WireGuard) > 0 {
		for range g.TransportOptions.WireGuard {
			// for _, address := range g.TransportOptions.WireGuard {

			// Generate a new unique Tunnel IP per address for each string in WireGuard transports
			var tunIP net.IP
			if wg := g.TransportOptions.WireGuard; len(wg) > 0 {
				uniqueWGIP, err := transport.RPC.GenerateUniqueIP(context.Background(), &commonpb.Empty{})
				tunIP = net.ParseIP(uniqueWGIP.IP)
				if err != nil {
					return fmt.Errorf("Failed to generate unique ip for wg peer tun interface")
				}
				log.Infof("Generated unique IP for WireGuard peer tun interface: %s", readline.Yellow(tunIP.String()))
			}

			profile := c2.ParseProfile(
				sliverpb.C2Channel_WG,
				tunIP.String(),
				sliverpb.C2Direction_Reverse,
				c2.ProfileOptions{},
			)

			// Additional Wireguard options
			if profile.Port == 0 { // Not specified sometimes, and no Wireguard options in this command to know it...
				profile.Port = 53
			}
			profile.ControlPort = uint32(g.TransportOptions.TCPComms)
			profile.KeyExchangePort = uint32(g.TransportOptions.KeyExchange)
			cfg.C2S = append(cfg.C2S, profile)
		}
	}

	if len(g.TransportOptions.DNS) > 0 {
		for _, address := range g.TransportOptions.DNS {
			profile := c2.ParseProfile(
				sliverpb.C2Channel_DNS,
				address,
				sliverpb.C2Direction_Reverse,
				c2.ProfileOptions{},
			)
			cfg.C2S = append(cfg.C2S, profile)
		}
	}

	if len(g.TransportOptions.HTTP) > 0 {
		for _, address := range g.TransportOptions.HTTP {
			profile := c2.ParseProfile(
				sliverpb.C2Channel_HTTP,
				address,
				sliverpb.C2Direction_Reverse,
				c2.ProfileOptions{},
			)
			cfg.C2S = append(cfg.C2S, profile)
		}

	}

	if len(g.TransportOptions.NamedPipe) > 0 {
		for _, address := range g.TransportOptions.NamedPipe {
			profile := c2.ParseProfile(
				sliverpb.C2Channel_NamedPipe, // A Channel using Wireguard
				address,                      // Targeting the host:[port] argument of our command
				sliverpb.C2Direction_Reverse, // A listener
				c2.ProfileOptions{},          // This will automatically parse Profile options into the protobuf
			)
			cfg.C2S = append(cfg.C2S, profile)
		}
	}

	if len(g.TransportOptions.TCP) > 0 {
		for _, address := range g.TransportOptions.TCP {
			profile := c2.ParseProfile(
				sliverpb.C2Channel_TCP,       // A Channel using Mutual TLS
				address,                      // Targeting the host:[port] argument of our command
				sliverpb.C2Direction_Reverse, // A listener
				c2.ProfileOptions{},          // This will automatically parse Profile options into the protobuf
			)
			cfg.C2S = append(cfg.C2S, profile)
		}
	}

	// Base Options -----------------------------------------------------------------------------------

	// If connection settings have been specified, apply them to all profiles indiscriminatly.
	for _, profile := range cfg.C2S {
		profile.MaxConnectionErrors = int32(g.TransportOptions.MaxErrors)
		profile.PollTimeout = int64(g.TransportOptions.PollTimeout) * int64(time.Second)
		profile.Interval = int64(g.TransportOptions.Reconnect) * int64(time.Second)

		// All profiles are fallback by default
		profile.IsFallback = true
		// And they might be forbidden to use SSH multiplexing
		profile.CommDisabled = g.TransportOptions.DisableComm
	}

	// Malleable C2 Profiles ---------------------------------------------------------------------------

	// If no C2 strings specified and C2 profiles IDs given, return
	if len(cfg.C2S) == 0 && len(g.TransportOptions.C2Profiles) == 0 {
		return fmt.Errorf(`Must specify at least: 
                => one of --mtls, --http, --dns, --named-pipe, or --tcp-pivot 
                => one or more C2 profiles with --malleables <malleableID>,<malleableID2>`)
	}

	// Else add the profiles
	if len(g.TransportOptions.C2Profiles) > 0 {
		profiles, err := transport.RPC.GetC2Profiles(context.Background(),
			&clientpb.GetC2ProfilesReq{
				Request: core.ActiveTarget.Request(),
			})
		if err != nil {
			return fmt.Errorf("failed to fetch C2 profiles from server: %s", err)
		}

		// Each matching ID.
		for _, raw := range g.TransportOptions.C2Profiles {
			// Bug in split forces us to redo it here
			var splitted = strings.Split(raw, ",")
			for _, id := range splitted {
				for _, prof := range profiles.Profiles {
					if c2.GetShortID(prof.ID) == id {
						cfg.C2S = append(cfg.C2S, prof)
					}
				}
			}
		}
	}

	// Compatibility verifications ---------------------------------------------------------------------
	for _, c2 := range cfg.C2S {
		if c2.C2 == sliverpb.C2Channel_NamedPipe {
			if cfg.GOOS != "windows" {
				return fmt.Errorf("Named pipe C2 transports can only be used in Windows")
			}
		}
	}

	return
}

func parseMTLSc2(args []string) []*clientpb.ImplantC2 {
	c2s := []*clientpb.ImplantC2{}
	if len(args) == 0 {
		return c2s
	}
	for index, arg := range args {
		uri := url.URL{Scheme: "mtls"}
		uri.Host = arg
		if uri.Port() == "" {
			uri.Host = fmt.Sprintf("%s:%d", uri.Host, constants.DefaultMTLSLPort)
		}
		c2s = append(c2s, &clientpb.ImplantC2{
			Priority: uint32(index),
			URL:      uri.String(),
		})
	}
	return c2s
}

func parseWGc2(args []string) []*clientpb.ImplantC2 {
	c2s := []*clientpb.ImplantC2{}
	if len(args) == 0 {
		return c2s
	}
	for index, arg := range args {
		arg = strings.ToLower(arg)
		uri := url.URL{Scheme: "wg"}
		uri.Host = arg
		if uri.Port() == "" {
			uri.Host = fmt.Sprintf("%s:%d", uri.Host, constants.DefaultWGLPort)
		}
		c2s = append(c2s, &clientpb.ImplantC2{
			Priority: uint32(index),
			URL:      uri.String(),
		})
	}
	return c2s
}

func parseHTTPc2(args []string) []*clientpb.ImplantC2 {
	c2s := []*clientpb.ImplantC2{}
	if len(args) == 0 {
		return c2s
	}
	for index, arg := range args {
		arg = strings.ToLower(arg)
		var uri *url.URL
		var err error
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			uri, err = url.Parse(arg)
			if err != nil {
				log.Printf("Failed to parse C2 URL %v", err)
				continue
			}
		} else {
			uri, err = url.Parse(fmt.Sprintf("https://%s", arg))
			if err != nil {
				log.Printf("Failed to parse C2 URL %s", err)
				continue
			}
		}
		c2s = append(c2s, &clientpb.ImplantC2{
			Priority: uint32(index),
			URL:      uri.String(),
		})
	}
	return c2s
}

func parseDNSc2(args []string) []*clientpb.ImplantC2 {
	c2s := []*clientpb.ImplantC2{}
	if len(args) == 0 {
		return c2s
	}
	for index, arg := range args {
		uri := url.URL{Scheme: "dns"}
		if len(arg) < 1 {
			continue
		}
		// Make sure we have the FQDN
		if !strings.HasSuffix(arg, ".") {
			arg += "."
		}
		if strings.HasPrefix(arg, ".") {
			arg = arg[1:]
		}

		uri.Host = arg
		c2s = append(c2s, &clientpb.ImplantC2{
			Priority: uint32(index),
			URL:      uri.String(),
		})
	}
	return c2s
}

func parseNamedPipec2(args []string) []*clientpb.ImplantC2 {
	c2s := []*clientpb.ImplantC2{}
	if len(args) == 0 {
		return c2s
	}
	for index, arg := range args {
		uri, err := url.Parse("namedpipe://" + arg)
		if len(arg) < 1 {
			continue
		}
		if err != nil {
			return c2s
		}
		c2s = append(c2s, &clientpb.ImplantC2{
			Priority: uint32(index),
			URL:      uri.String(),
		})
	}
	return c2s
}

func parseTCPPivotc2(args []string) []*clientpb.ImplantC2 {
	c2s := []*clientpb.ImplantC2{}
	if len(args) == 0 {
		return c2s
	}
	for index, arg := range args {

		uri := url.URL{Scheme: "tcppivot"}
		uri.Host = arg
		if uri.Port() == "" {
			uri.Host = fmt.Sprintf("%s:%d", uri.Host, constants.DefaultTCPPivotPort)
		}
		c2s = append(c2s, &clientpb.ImplantC2{
			Priority: uint32(index),
			URL:      uri.String(),
		})
	}
	return c2s
}

//
// Compilation -------------------------------------------------------------------------------------------------
//

// Compile - Compile an implant based on a configuration
func Compile(config *clientpb.ImplantConfig, save string) (*commonpb.File, error) {

	if config.IsBeacon {
		interval := time.Duration(config.BeaconInterval)
		log.Infof("Generating new %s/%s beacon implant binary (%v)", config.GOOS, config.GOARCH, interval)
	} else {
		log.Infof("Generating new %s/%s implant binary", config.GOOS, config.GOARCH)
	}

	if config.ObfuscateSymbols {
		log.Infof("Symbol obfuscation is enabled.")
	} else if !config.Debug {
		log.Warnf("Symbol obfuscation is disabled")
	}

	start := time.Now()
	ctrl := make(chan bool)
	go log.SpinUntil("Compiling, please wait ...", ctrl)

	generated, err := transport.RPC.Generate(context.Background(), &clientpb.GenerateReq{
		Config:  config,
		Request: core.ActiveTarget.Request(),
	})
	ctrl <- true
	<-ctrl
	if err != nil {
		return nil, err
	}

	end := time.Now()
	elapsed := time.Time{}.Add(end.Sub(start))
	log.Infof("Build completed in %s", elapsed.Format("15:04:05"))
	if len(generated.File.Data) == 0 {
		return nil, errors.New("Build failed, No file data")
	}

	saveTo, err := saveLocation(save, generated.File.Name)
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(saveTo, generated.File.Data, 0700)
	if err != nil {
		return nil, log.Errorf("Failed to write to %s: %s", saveTo, err.Error())
	}
	log.Infof("Implant saved to %s", saveTo)
	return generated.File, err
}

func saveLocation(save, defaultName string) (string, error) {
	var saveTo string
	if save == "" {
		save, _ = os.Getwd()
	}
	fi, err := os.Stat(save)
	if os.IsNotExist(err) {
		log.Printf("%s does not exist\n", save)
		if strings.HasSuffix(save, "/") {
			log.Infof("%s is dir\n", save)
			os.MkdirAll(save, 0700)
			saveTo, _ = filepath.Abs(path.Join(saveTo, defaultName))
		} else {
			log.Printf("%s is not dir\n", save)
			saveDir := filepath.Dir(save)
			_, err := os.Stat(saveTo)
			if os.IsNotExist(err) {
				os.MkdirAll(saveDir, 0700)
			}
			saveTo, _ = filepath.Abs(save)
		}
	} else {
		log.Printf("%s does exist\n", save)
		if fi.IsDir() {
			log.Infof("%s is dir\n", save)
			saveTo, _ = filepath.Abs(path.Join(save, defaultName))
		} else {
			log.Printf("%s is not dir\n", save)
			prompt := &survey.Confirm{Message: "Overwrite existing file?"}
			var confirm bool
			survey.AskOne(prompt, &confirm, nil)
			if !confirm {
				return "", errors.New("File already exists")
			}
			saveTo, _ = filepath.Abs(save)
		}
	}
	return saveTo, nil
}

func getLimitsString(config *clientpb.ImplantConfig) string {
	limits := []string{}
	if config.LimitDatetime != "" {
		limits = append(limits, fmt.Sprintf("datetime=%s", config.LimitDatetime))
	}
	if config.LimitDomainJoined {
		limits = append(limits, fmt.Sprintf("domainjoined=%v", config.LimitDomainJoined))
	}
	if config.LimitUsername != "" {
		limits = append(limits, fmt.Sprintf("username=%s", config.LimitUsername))
	}
	if config.LimitHostname != "" {
		limits = append(limits, fmt.Sprintf("hostname=%s", config.LimitHostname))
	}
	if config.LimitFileExists != "" {
		limits = append(limits, fmt.Sprintf("fileexists=%s", config.LimitFileExists))
	}
	return strings.Join(limits, "; ")
}

func nameOfOutputFormat(value clientpb.OutputFormat) string {
	switch value {
	case clientpb.OutputFormat_EXECUTABLE:
		return "Executable"
	case clientpb.OutputFormat_SERVICE:
		return "Service"
	case clientpb.OutputFormat_SHARED_LIB:
		return "Shared Library"
	case clientpb.OutputFormat_SHELLCODE:
		return "Shellcode"
	}
	panic(fmt.Sprintf("Unknown format %v", value))
}

// BuildImplantName - Get the name of an implant based on a file
func BuildImplantName(name string) string {
	return strings.TrimSuffix(name, filepath.Ext(name))
}

func checkBuildTargetCompatibility(format clientpb.OutputFormat, targetOS string, targetArch string) bool {
	if format == clientpb.OutputFormat_EXECUTABLE {
		return true // We don't need cross-compilers when targeting EXECUTABLE formats
	}

	compilers, err := transport.RPC.GetCompiler(context.Background(), &commonpb.Empty{})
	if err != nil {
		log.Warnf("Failed to check target compatibility: %s", err)
		return true
	}

	if runtime.GOOS != "windows" && targetOS == "windows" {
		if !hasCC(targetOS, targetArch, compilers.CrossCompilers) {
			return warnMissingCrossCompiler(format, targetOS, targetArch)
		}
	}

	if runtime.GOOS != "darwin" && targetOS == "darwin" {
		if !hasCC(targetOS, targetArch, compilers.CrossCompilers) {
			return warnMissingCrossCompiler(format, targetOS, targetArch)
		}
	}

	if runtime.GOOS != "linux" && targetOS == "linux" {
		if !hasCC(targetOS, targetArch, compilers.CrossCompilers) {
			return warnMissingCrossCompiler(format, targetOS, targetArch)
		}
	}

	return true
}

func hasCC(targetOS string, targetArch string, crossCompilers []*clientpb.CrossCompiler) bool {
	for _, cc := range crossCompilers {
		if cc.GetTargetGOOS() == targetOS && cc.GetTargetGOARCH() == targetArch {
			return true
		}
	}
	return false
}

func warnMissingCrossCompiler(format clientpb.OutputFormat, targetOS string, targetArch string) bool {
	log.Warnf("WARNING: Missing cross-compiler for %s on %s/%s", nameOfOutputFormat(format), targetOS, targetArch)
	switch targetOS {
	case "windows":
		log.Warnf("The server cannot find an installation of mingw")
	case "darwin":
		log.Warnf("The server cannot find an installation of osxcross")
	case "linux":
		log.Warnf("The server cannot find an installation of musl-cross")
	}
	log.Warnf("For more information please read %s", crossCompilerInfoURL)

	confirm := false
	prompt := &survey.Confirm{Message: "Try to compile anyways (will likely fail)?"}
	survey.AskOne(prompt, &confirm, nil)
	return confirm
}
