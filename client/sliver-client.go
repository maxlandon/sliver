package main

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
	"flag"

	"github.com/BishopFox/sliver/client/assets"
	client "github.com/BishopFox/sliver/client/console"
)

func main() {

	// Process flags passed to this binary (os.Flags). All flag variables are
	// in their respective files (but, of course, in this package only).
	flag.Parse()

	// Load all necessary configurations (server connection details, TLS security,
	// console configuration, etc.). This function automatically determines if the
	// console binary has a builtin server configuration or not, and forges a configuration
	// depending on this. The configuration is then accessible to all client packages.
	assets.LoadServerConfig()

	// Start the client console. The latter automatically performs server connection,
	// prompt/command/completion setup, event loop listening, etc. Any critical error
	// is handled from within this function, so we don't process the return error here.
	client.Console.Start()
}