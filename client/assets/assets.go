package assets

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
	"embed"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"

	ver "github.com/bishopfox/sliver/client/version"
)

var (
	//go:embed fs/extensions/* fs/art/*
	assetsFs embed.FS
)

const (
	// SliverClientDirName - Directory storing all of the client configs/logs
	SliverClientDirName = ".sliver-client"
	// SliverExtensionsDirName - Directory storing the client side extensions
	SliverExtensionsDirName       = "extensions"
	SliverArtDirName              = ".art"
	versionFileName               = "version"
	SliverC2DirName               = "c2"
	SliverMalleableSchemasDirName = "malleable_schemas"
	SliverMalleableSchema         = "Malleable.json"
)

// GetRootAppDir - Get the Sliver app dir ~/.sliver-client/
func GetRootAppDir() string {
	user, _ := user.Current()
	dir := path.Join(user.HomeDir, SliverClientDirName)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
	return dir
}

// GetExtensionsDir - Get the Sliver extension directory: ~/.sliver-client/extensions
func GetExtensionsDir() string {
	user, _ := user.Current()
	dir := path.Join(user.HomeDir, SliverClientDirName, SliverExtensionsDirName)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
	return dir
}

// GetArtDir - Get the Sliver art directory: ~/.sliver-client/art
func GetArtDir() string {
	user, _ := user.Current()
	dir := path.Join(user.HomeDir, SliverClientDirName, SliverArtDirName)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
	return dir
}

// GetC2Dir - Directory where all C2 related things are stored for the client console.
func GetC2Dir() string {
	dir := path.Join(GetRootAppDir(), SliverC2DirName)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}
	return dir
}

// GetMalleableSchemaDir - The directory where JSON schemas related to Malleable profiles
// are stored. These schemas are passed to client consoles when they connect, so that they
// have full completion, validation and documentation available for Malleable C2 functionality.
func GetMalleableSchemaDir() (dir string) {
	dir = path.Join(GetC2Dir(), SliverMalleableSchemasDirName)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}
	return
}

// GetMalleableSchemaPath - The full, absolute path to the conventionned location of the
// Malleable JSON Schema file. This does not ensure that the file exists: if it doesn't
// no completion/validation/documentation will be available in the client editor.
func GetMalleableSchemaPath() string {
	return path.Join(GetMalleableSchemaDir(), SliverMalleableSchema)
}

func assetVersion() string {
	appDir := GetRootAppDir()
	data, err := ioutil.ReadFile(path.Join(appDir, versionFileName))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func saveAssetVersion(appDir string) {
	versionFilePath := path.Join(appDir, versionFileName)
	fVer, _ := os.Create(versionFilePath)
	defer fVer.Close()
	fVer.Write([]byte(ver.GitCommit))
}

// Setup - Extract or create local assets
func Setup(force bool, echo bool) {
	appDir := GetRootAppDir()
	localVer := assetVersion()
	if force || localVer == "" || localVer != ver.GitCommit {
		if echo {
			fmt.Printf("Unpacking assets ...\n")
		}
		err := setupCoffLoaderExt(appDir)
		if err != nil {
			fmt.Println(err)
			log.Fatal(err)
		}
		saveAssetVersion(appDir)
	}
	if _, err := os.Stat(filepath.Join(appDir, settingsFileName)); os.IsNotExist(err) {
		SaveSettings(nil)
	}
}

func setupCoffLoaderExt(appDir string) error {
	extDir := GetExtensionsDir()
	win32ExtDir := path.Join("windows", "386")
	win64ExtDir := path.Join("windows", "amd64")
	coffLoader32 := path.Join("fs", SliverExtensionsDirName, win32ExtDir, "COFFLoader.x86.dll")
	coffLoader64 := path.Join("fs", SliverExtensionsDirName, win64ExtDir, "COFFLoader.x64.dll")
	manifestPath := path.Join("fs", SliverExtensionsDirName, "manifest.json")
	loader64, err := assetsFs.ReadFile(coffLoader64)
	if err != nil {
		return err
	}
	loader32, err := assetsFs.ReadFile(coffLoader32)
	if err != nil {
		return err
	}
	manifest, err := assetsFs.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	localWin32ExtDir := path.Join(extDir, win32ExtDir)
	err = os.MkdirAll(localWin32ExtDir, 0700)
	if err != nil {
		return err
	}
	localWin64ExtDir := path.Join(extDir, win64ExtDir)
	err = os.MkdirAll(localWin64ExtDir, 0700)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path.Join(localWin32ExtDir, "COFFLoader.x86.dll"), loader32, 0744)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path.Join(extDir, "manifest.json"), manifest, 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path.Join(localWin64ExtDir, "COFFLoader.x64.dll"), loader64, 0744)
}

// SetupInstinct - Set up the instinct banner
func SetupInstinct() error {
	// Instinct
	instinct, err := assetsFs.ReadFile("fs/art/sharon.jpg")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path.Join(GetArtDir(), "instinct.jpg"), instinct, 0700)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}
