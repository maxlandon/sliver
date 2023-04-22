package armory

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

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
	"regexp"

	"github.com/spf13/cobra"

	"github.com/bishopfox/sliver/client/command/alias"
	"github.com/bishopfox/sliver/client/command/extensions"
	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/log"
)

// ArmorySearchCmd - Search for packages by name
func ArmorySearchCmd(cmd *cobra.Command, args []string) {
	con := console.Client

	log.Infof("Refreshing package cache ... ")
	clientConfig := parseArmoryHTTPConfig(cmd)
	refresh(clientConfig)
	log.Printf(console.Clearln + "\r")

	rawNameExpr := args[0]
	// rawNameExpr := ctx.Args.String("name")
	if rawNameExpr == "" {
		log.Errorf("Please specify a search term!\n")
		return
	}
	nameExpr, err := regexp.Compile(rawNameExpr)
	if err != nil {
		log.Errorf("Invalid regular expression: %s\n", err)
		return
	}

	aliases, exts := packagesInCache()
	matchedAliases := []*alias.AliasManifest{}
	for _, a := range aliases {
		if nameExpr.MatchString(a.CommandName) {
			matchedAliases = append(matchedAliases, a)
		}
	}
	matchedExts := []*extensions.ExtensionManifest{}
	for _, ext := range exts {
		if nameExpr.MatchString(ext.CommandName) {
			matchedExts = append(matchedExts, ext)
		}
	}
	if len(matchedAliases) == 0 && len(matchedExts) == 0 {
		log.Infof("No packages found matching '%s'\n", rawNameExpr)
		return
	}
	PrintArmoryPackages(matchedAliases, matchedExts, con)
}
