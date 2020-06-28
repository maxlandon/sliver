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
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/server/assets"
	"github.com/bishopfox/sliver/server/build/canaries"
	"github.com/bishopfox/sliver/server/build/codenames"
	"github.com/bishopfox/sliver/server/build/gobfuscate"
	"github.com/bishopfox/sliver/server/build/gogo"
	"github.com/bishopfox/sliver/server/build/implants"
	"github.com/bishopfox/sliver/server/log"
	"github.com/bishopfox/sliver/util"

	"github.com/gobuffalo/packr"
)

var (
	buildLog = log.NamedLogger("build", "generate")
	// Fix #67: use an arch specific compiler
	defaultMingwPath = map[string]string{
		"386":   "/usr/bin/i686-w64-mingw32-gcc",
		"amd64": "/usr/bin/x86_64-w64-mingw32-gcc",
	}
)

const (
	// WINDOWS OS
	WINDOWS = "windows"

	// DARWIN / MacOS
	DARWIN = "darwin"

	// LINUX OS
	LINUX = "linux"

	clientsDirName = "clients"
	sliversDirName = "slivers"

	encryptKeySize = 16

	// DefaultReconnectInterval - In seconds
	DefaultReconnectInterval = 60
	// DefaultMTLSLPort - Default listen port
	DefaultMTLSLPort = 8888
	// DefaultHTTPLPort - Default HTTP listen port
	DefaultHTTPLPort = 443 // Assume SSL, it'll fallback

	// SliverCC64EnvVar - Environment variable that can specify the 64 bit mingw path
	SliverCC64EnvVar = "SLIVER_CC_64"
	// SliverCC32EnvVar - Environment variable that can specify the 32 bit mingw path
	SliverCC32EnvVar = "SLIVER_CC_32"
)

// BuildConfig - Helper values determined at runtime but not included in ImplantConfig
type BuildConfig struct {
	Cfg *clientpb.ImplantConfig

	MTLSC2Enabled     bool
	HTTPC2Enabled     bool
	DNSC2Enabled      bool
	NamePipeC2Enabled bool
	TCPPivotC2Enabled bool
}

func copyC2List(src []*clientpb.ImplantC2) []*clientpb.ImplantC2 {
	c2s := []*clientpb.ImplantC2{}
	for _, srcC2 := range src {
		c2URL, err := url.Parse(srcC2.URL)
		if err != nil {
			buildLog.Warnf("Failed to parse c2 url %v", err)
			continue
		}
		c2s = append(c2s, &clientpb.ImplantC2{
			Priority: srcC2.Priority,
			URL:      c2URL.String(),
			Options:  srcC2.Options,
		})
	}
	return c2s
}

func isC2Enabled(schemes []string, c2s []*clientpb.ImplantC2) bool {
	for _, c2 := range c2s {
		c2URL, err := url.Parse(c2.URL)
		if err != nil {
			buildLog.Warnf("Failed to parse c2 url %v", err)
			continue
		}
		for _, scheme := range schemes {
			if scheme == c2URL.Scheme {
				return true
			}
		}
	}
	buildLog.Debugf("No %v URLs found in %v", schemes, c2s)
	return false
}

// GetSliversDir - Get the binary directory
func GetSliversDir() string {
	appDir := assets.GetRootAppDir()
	sliversDir := path.Join(appDir, sliversDirName)
	if _, err := os.Stat(sliversDir); os.IsNotExist(err) {
		buildLog.Infof("Creating bin directory: %s", sliversDir)
		err = os.MkdirAll(sliversDir, 0700)
		if err != nil {
			buildLog.Fatal(err)
		}
	}
	return sliversDir
}

// -----------------------
// Sliver Generation Code
// -----------------------

// SliverShellcode - Generates a sliver shellcode using sRDI
func SliverShellcode(config *clientpb.ImplantConfig) (string, error) {
	// Compile go code
	var crossCompiler string
	appDir := assets.GetRootAppDir()
	// Don't use a cross-compiler if the target bin is built on the same platform
	// as the sliver-server.
	if runtime.GOOS != config.GOOS {
		crossCompiler = GetCCompiler(config.GOARCH)
		if crossCompiler == "" {
			return "", errors.New("No cross-compiler (mingw) found")
		}
	}
	goConfig := &gogo.GoConfig{
		CGO:    "1",
		CC:     crossCompiler,
		GOOS:   config.GOOS,
		GOARCH: config.GOARCH,
		GOROOT: gogo.GetGoRootDir(appDir),
	}
	pkgPath, err := renderSliverGoCode(config, goConfig)
	if err != nil {
		return "", err
	}

	dest := path.Join(goConfig.GOPATH, "bin", config.Name)
	dest += ".bin"

	tags := []string{"netgo"}
	ldflags := []string{"-s -w -buildid="}
	if !config.Debug && goConfig.GOOS == WINDOWS {
		ldflags[0] += " -H=windowsgui"
	}
	// Keep those for potential later use
	gcflags := fmt.Sprintf("")
	asmflags := fmt.Sprintf("")
	// trimpath is now a separate flag since Go 1.13
	trimpath := "-trimpath"
	_, err = gogo.GoBuild(*goConfig, pkgPath, dest, "c-shared", tags, ldflags, gcflags, asmflags, trimpath)
	config.FileName = path.Base(dest)
	shellcode, err := ShellcodeRDI(dest, "RunSliver", "")
	if err != nil {
		return "", err
	}
	err = ioutil.WriteFile(dest, shellcode, 0755)
	if err != nil {
		return "", err
	}
	config.Format = clientpb.ImplantConfig_SHELLCODE
	// Save to database
	saveFileErr := implants.ImplantFileSave(config.Name, dest)
	saveCfgErr := implants.ImplantConfigSave(config)
	if saveFileErr != nil || saveCfgErr != nil {
		buildLog.Errorf("Failed to save file to db %s %s", saveFileErr, saveCfgErr)
	}
	return dest, err

}

// SliverSharedLibrary - Generates a sliver shared library (DLL/dylib/so) binary
func SliverSharedLibrary(config *clientpb.ImplantConfig) (string, error) {
	// Compile go code
	var crossCompiler string
	appDir := assets.GetRootAppDir()
	// Don't use a cross-compiler if the target bin is built on the same platform
	// as the sliver-server.
	if runtime.GOOS != config.GOOS {
		crossCompiler = GetCCompiler(config.GOARCH)
		if crossCompiler == "" {
			return "", errors.New("No cross-compiler (mingw) found")
		}
	}
	goConfig := &gogo.GoConfig{
		CGO:    "1",
		CC:     crossCompiler,
		GOOS:   config.GOOS,
		GOARCH: config.GOARCH,
		GOROOT: gogo.GetGoRootDir(appDir),
	}
	pkgPath, err := renderSliverGoCode(config, goConfig)
	if err != nil {
		return "", err
	}

	dest := path.Join(goConfig.GOPATH, "bin", config.Name)
	if goConfig.GOOS == WINDOWS {
		dest += ".dll"
	}
	if goConfig.GOOS == DARWIN {
		dest += ".dylib"
	}
	if goConfig.GOOS == LINUX {
		dest += ".so"
	}

	tags := []string{"netgo"}
	ldflags := []string{"-s -w -buildid="}
	if !config.Debug && goConfig.GOOS == WINDOWS {
		ldflags[0] += " -H=windowsgui"
	}
	// Keep those for potential later use
	gcflags := fmt.Sprintf("")
	asmflags := fmt.Sprintf("")
	// trimpath is now a separate flag since Go 1.13
	trimpath := "-trimpath"
	_, err = gogo.GoBuild(*goConfig, pkgPath, dest, "c-shared", tags, ldflags, gcflags, asmflags, trimpath)
	config.FileName = path.Base(dest)
	saveFileErr := implants.ImplantFileSave(config.Name, dest)
	saveCfgErr := implants.ImplantConfigSave(config)
	if saveFileErr != nil || saveCfgErr != nil {
		buildLog.Errorf("Failed to save file to db %s %s", saveFileErr, saveCfgErr)
	}
	return dest, err
}

// SliverExecutable - Generates a sliver executable binary
func SliverExecutable(config *clientpb.ImplantConfig) (string, error) {

	// Compile go code
	appDir := assets.GetRootAppDir()
	cgo := "0"
	if config.IsSharedLib {
		cgo = "1"
	}
	goConfig := &gogo.GoConfig{
		CGO:    cgo,
		GOOS:   config.GOOS,
		GOARCH: config.GOARCH,
		GOROOT: gogo.GetGoRootDir(appDir),
	}
	pkgPath, err := renderSliverGoCode(config, goConfig)
	if err != nil {
		return "", err
	}

	dest := path.Join(goConfig.GOPATH, "bin", config.Name)
	if goConfig.GOOS == WINDOWS {
		dest += ".exe"
	}
	tags := []string{"netgo"}
	ldflags := []string{"-s -w -buildid="}
	if !config.Debug && goConfig.GOOS == WINDOWS {
		ldflags[0] += " -H=windowsgui"
	}
	gcflags := fmt.Sprintf("")
	asmflags := fmt.Sprintf("")
	// trimpath is now a separate flag since Go 1.13
	trimpath := "-trimpath"
	_, err = gogo.GoBuild(*goConfig, pkgPath, dest, "", tags, ldflags, gcflags, asmflags, trimpath)
	config.FileName = path.Base(dest)
	saveFileErr := implants.ImplantFileSave(config.Name, dest)
	saveCfgErr := implants.ImplantConfigSave(config)
	if saveFileErr != nil || saveCfgErr != nil {
		buildLog.Errorf("Failed to save file to db %s %s", saveFileErr, saveCfgErr)
	}
	return dest, err
}

// This function is a little too long, we should probably refactor it as some point
func renderSliverGoCode(implantConfig *clientpb.ImplantConfig, goConfig *gogo.GoConfig) (string, error) {
	target := fmt.Sprintf("%s/%s", implantConfig.GOOS, implantConfig.GOARCH)
	if _, ok := gogo.SupportedCompilerTargets[target]; !ok {
		return "", fmt.Errorf("Invalid compiler target: %s", target)
	}

	if implantConfig.Name == "" {
		implantConfig.Name = codenames.GetCodename()
	}
	buildLog.Infof("Generating new sliver binary '%s'", implantConfig.Name)

	buildConfig := &BuildConfig{
		Cfg:               implantConfig,
		MTLSC2Enabled:     isC2Enabled([]string{"mtls"}, implantConfig.C2),
		HTTPC2Enabled:     isC2Enabled([]string{"http", "https"}, implantConfig.C2),
		DNSC2Enabled:      isC2Enabled([]string{"dns"}, implantConfig.C2),
		NamePipeC2Enabled: isC2Enabled([]string{"namedpipe"}, implantConfig.C2),
		TCPPivotC2Enabled: isC2Enabled([]string{"tcppivot"}, implantConfig.C2),
	}

	sliversDir := GetSliversDir() // ~/.sliver/slivers
	projectGoPathDir := path.Join(sliversDir, implantConfig.GOOS, implantConfig.GOARCH, implantConfig.Name)
	os.MkdirAll(projectGoPathDir, 0700)
	goConfig.GOPATH = projectGoPathDir

	// binDir - ~/.sliver/slivers/<os>/<arch>/<name>/bin
	binDir := path.Join(projectGoPathDir, "bin")
	os.MkdirAll(binDir, 0700)

	// srcDir - ~/.sliver/slivers/<os>/<arch>/<name>/src
	srcDir := path.Join(projectGoPathDir, "src")
	assets.SetupGoPath(srcDir)             // Extract GOPATH dependency files
	err := util.ChmodR(srcDir, 0600, 0700) // Ensures src code files are writable
	if err != nil {
		buildLog.Errorf("fs perms: %v", err)
		return "", err
	}

	sliverPkgDir := path.Join(srcDir, "github.com", "bishopfox", "sliver") // "main"
	os.MkdirAll(sliverPkgDir, 0700)

	// Load code template
	sliverBox := packr.NewBox("../../sliver")
	for index, boxName := range srcFiles {

		// Gobfuscate doesn't handle all the platform specific code
		// well and the renamer can get confused when symbols for a
		// different OS don't show up. So we just filter out anything
		// we're not actually going to compile into the final binary
		suffix := ".go"
		if strings.Contains(boxName, "_") {
			fileNameParts := strings.Split(boxName, "_")
			suffix = "_" + fileNameParts[len(fileNameParts)-1]
			if strings.HasSuffix(boxName, "_test.go") {
				buildLog.Infof("Skipping (test): %s", boxName)
				continue
			}
			osSuffix := fmt.Sprintf("_%s.go", strings.ToLower(implantConfig.GOOS))
			archSuffix := fmt.Sprintf("_%s.go", strings.ToLower(implantConfig.GOARCH))
			if !strings.HasSuffix(boxName, osSuffix) && !strings.HasSuffix(boxName, archSuffix) {
				buildLog.Infof("Skipping file wrong os/arch: %s", boxName)
				continue
			}
		}

		implantGoCode, _ := sliverBox.FindString(boxName)

		// We need to correct for the "github.com/bishopfox/sliver/sliver/foo" imports, since Go
		// doesn't allow relative imports and "sliver" is a subdirectory of
		// the main "sliver" repo we need to fake this when coping the code
		// to our per-compile "GOPATH"
		var implantCodePath string
		dirName := filepath.Dir(boxName)
		var fileName string
		// Skip dllmain files for anything non windows
		if boxName == "sliver.h" || boxName == "sliver.c" {
			if !implantConfig.IsSharedLib {
				continue
			}
		}
		if implantConfig.Debug || strings.HasSuffix(boxName, ".c") || strings.HasSuffix(boxName, ".h") {
			fileName = filepath.Base(boxName)
		} else {
			fileName = fmt.Sprintf("s%d%s", index, suffix)
		}
		if dirName != "." {
			// Add an extra "sliver" dir
			dirPath := path.Join(sliverPkgDir, "sliver", dirName)
			if _, err := os.Stat(dirPath); os.IsNotExist(err) {
				buildLog.Infof("[mkdir] %#v", dirPath)
				os.MkdirAll(dirPath, 0700)
			}
			implantCodePath = path.Join(dirPath, fileName)
		} else {
			implantCodePath = path.Join(sliverPkgDir, fileName)
		}

		fSliver, _ := os.Create(implantCodePath)
		buf := bytes.NewBuffer([]byte{})
		buildLog.Infof("[render] %s -> %s", boxName, implantCodePath)

		// Render code
		sliverCodeTmpl, _ := template.New("sliver").Parse(implantGoCode)
		sliverCodeTmpl.Execute(buf, buildConfig)

		// Render canaries
		buildLog.Infof("Canary domain(s): %v", implantConfig.CanaryDomains)
		canaryTmpl := template.New("canary").Delims("[[", "]]")
		canaryGenerator := &canaries.CanaryGenerator{
			ImplantName:   implantConfig.Name,
			ParentDomains: implantConfig.CanaryDomains,
		}
		canaryTmpl, err := canaryTmpl.Funcs(template.FuncMap{
			"GenerateCanary": canaryGenerator.GenerateCanary,
		}).Parse(buf.String())
		canaryTmpl.Execute(fSliver, canaryGenerator)

		if err != nil {
			buildLog.Infof("Failed to render go code: %s", err)
			return "", err
		}
	}

	if !implantConfig.Debug {
		buildLog.Infof("Obfuscating source code ...")
		obfGoPath := path.Join(projectGoPathDir, "obfuscated")
		pkgName := "github.com/bishopfox/sliver"
		obfSymbols := implantConfig.ObfuscateSymbols
		obfKey := randomObfuscationKey()
		obfuscatedPkg, err := gobfuscate.Gobfuscate(*goConfig, obfKey, pkgName, obfGoPath, obfSymbols)
		if err != nil {
			buildLog.Infof("Error while obfuscating sliver %v", err)
			return "", err
		}
		goConfig.GOPATH = obfGoPath
		buildLog.Infof("Obfuscated GOPATH = %s", obfGoPath)
		buildLog.Infof("Obfuscated sliver package: %s", obfuscatedPkg)
		sliverPkgDir = path.Join(obfGoPath, "src", obfuscatedPkg) // new "main"
	}
	if err != nil {
		buildLog.Errorf("Failed to save sliver config %s", err)
	}
	return sliverPkgDir, nil
}

// GetCCompiler - Get path to cross-compiler for arch
func GetCCompiler(arch string) string {
	var found bool // meh, ugly
	var compiler string
	if arch == gogo.AMD64 {
		compiler = os.Getenv(SliverCC64EnvVar)
	}
	if arch == gogo.X86 {
		compiler = os.Getenv(SliverCC32EnvVar)
	}
	if compiler == "" {
		if compiler, found = defaultMingwPath[arch]; !found {
			compiler = defaultMingwPath[gogo.AMD64] // should not happen, but just in case ...
		}
	}
	if _, err := os.Stat(compiler); os.IsNotExist(err) {
		buildLog.Warnf("CC path %v does not exist", compiler)
		return ""
	}
	if runtime.GOOS == gogo.Windows {
		compiler = "" // TODO: Add windows mingw support
	}
	buildLog.Infof("CC = %v", compiler)
	return compiler
}

func randomObfuscationKey() string {
	randBuf := make([]byte, 64) // 64 bytes of randomness
	rand.Read(randBuf)
	digest := sha256.Sum256(randBuf)
	return fmt.Sprintf("%x", digest[:encryptKeySize])
}
