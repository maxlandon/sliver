package cli

/*
	Sliver Implant Framework
	Copyright (C) 2020  Bishop Fox

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
	"fmt"

	"github.com/reeflective/team/client/commands"
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"

	"github.com/bishopfox/sliver/client/command/completers"
	client "github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/version"
)

var cmdVersion = &cobra.Command{
	Use:     "version",
	Short:   "Print version and exit",
	Long:    ``,
	GroupID: constants.GenericHelpGroup,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", version.FullVersion())
	},
}

// bindServerConfig adds a CLI-specific flag for allowing users to force a specific
// remote Sliver server configuration to be used, instead of prompting user to choose.
func bindServerConfig(con *client.SliverClient, root *cobra.Command) {
	root.Flags().StringP("config", "c", "", "Force connecting to a specific Sliver server")
	completers.NewFlagCompsFor(root, func(comp *carapace.ActionMap) {
		(*comp)["config"] = carapace.ActionCallback(func(c carapace.Context) carapace.Action {
			return commands.ConfigsAppCompleter(con.Teamclient, "configs")
		})
	})
}
