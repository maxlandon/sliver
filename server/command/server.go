package command

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
	"os/user"
	"strings"

	"github.com/spf13/cobra"

	"github.com/reeflective/team/server"
	"github.com/reeflective/team/server/commands"

	"github.com/bishopfox/sliver/client/command"
	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/server/command/assets"
	"github.com/bishopfox/sliver/server/command/builder"
	"github.com/bishopfox/sliver/server/command/certs"
	"github.com/bishopfox/sliver/server/command/version"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"
)

var permissionsFlagStr = "permissions"

var operatorCmdLog = log.NamedLogger("command", "operator")

// TeamserverCommands is the equivalent of client/command.ServerCommands(), but for server-binary only ones.
func TeamserverCommands(team *server.Server, con *console.SliverClient) command.SliverBinder {
	return func(con *console.SliverClient) (cmds []*cobra.Command) {
		// Teamserver management
		teamclientCmds := commands.Generate(team, con.Teamclient)
		teamclientCmds.GroupID = constants.GenericHelpGroup
		cmds = append(cmds, teamclientCmds)

		// Sliver-specific teamserver stuff
		operatorCmd, _, _ := teamclientCmds.Find([]string{"teamserver", "user"})
		operatorCmd.Flags().StringSliceP(permissionsFlagStr, "P", []string{}, "grant permissions to the operator profile (all, builder, crackstation)")

		// The teamserver core only stores identity/credentials; Sliver owns
		// authorization. Wrap the user-creation command so that, once the core
		// has minted the user, we persist the operator's permissions (from -P)
		// into Sliver's own operator table, keyed by the user name.
		coreRun := operatorCmd.Run
		operatorCmd.Run = func(cmd *cobra.Command, args []string) {
			if coreRun != nil {
				coreRun(cmd, args)
			}
			saveOperatorPermissions(cmd)
		}

		// Sliver-specific
		cmds = append(cmds, version.Commands(con)...)
		cmds = append(cmds, assets.Commands()...)
		cmds = append(cmds, certs.Commands(con)...)

		// Commands requiring the server to be a remote teamclient.
		cmds = append(cmds, builder.Commands(con, team)...)

		return cmds
	}
}

// saveOperatorPermissions persists (or updates) the operator record in Sliver's
// own operator table with the permissions requested via the -P/--permissions
// flag, keyed by the created user name. This is what the permission interceptors
// enforce at RPC time, now that the teamserver core no longer stores permissions.
func saveOperatorPermissions(cmd *cobra.Command) {
	name, _ := cmd.Flags().GetString("name")

	// The core command uses the current OS user name when --system is set.
	if system, _ := cmd.Flags().GetBool("system"); system {
		if u, err := user.Current(); err == nil {
			name = u.Username
		}
	}

	if strings.TrimSpace(name) == "" {
		return
	}

	operator := &models.Operator{Name: name}

	perms, _ := cmd.Flags().GetStringSlice(permissionsFlagStr)
	for _, perm := range perms {
		switch strings.ToLower(strings.TrimSpace(perm)) {
		case "all":
			operator.PermissionAll = true
		case "builder":
			operator.PermissionBuilder = true
		case "crackstation":
			operator.PermissionCrackstation = true
		}
	}

	if err := db.SaveOperator(operator); err != nil {
		operatorCmdLog.Errorf("Failed to persist operator permissions for %q: %s", name, err)
		cmd.PrintErrf("Failed to persist operator permissions: %s\n", err)
	}
}
