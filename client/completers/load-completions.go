package completers

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
	"github.com/jessevdk/go-flags"

	"github.com/bishopfox/sliver/client/commands/sliver/windows"
	"github.com/bishopfox/sliver/client/constants"
	cctx "github.com/bishopfox/sliver/client/context"
)

// LoadAdditionalCompletions - This func is stored and called at each
// command parser loop, for managing fixed-choice completions for some commands.
func LoadAdditionalCompletions(parser *flags.Parser) {
	if parser == nil {
		return
	}
	switch parser.Name {
	case "server":
		serverCompsAddtional(parser)
	case "sliver":
		serverCompsAddtional(parser)
		sliverCompsAdditional(parser)
	}
}

// Additional completion mappings for command in the server context
func serverCompsAddtional(parser *flags.Parser) {

	// Stage options
	g := parser.Find(constants.GenerateStr)
	g.FindOptionByLongName("os").Choices = implantOS
	g.FindOptionByLongName("arch").Choices = implantArch
	g.FindOptionByLongName("format").Choices = implantFmt

	// Stager options (mostly MSF)
	gs := g.Find(constants.StagerStr)
	gs.FindOptionByLongName("os").Choices = implantOS
	gs.FindOptionByLongName("arch").Choices = implantArch
	gs.FindOptionByLongName("protocol").Choices = msfStagerProtocols
	gs.FindOptionByLongName("msf-format").Choices = msfTransformFormats

	// Profile options, same as stage
	p := parser.Find(constants.NewProfileStr)
	p.FindOptionByLongName("os").Choices = implantOS
	p.FindOptionByLongName("arch").Choices = implantArch
	p.FindOptionByLongName("format").Choices = implantFmt

	// Portfwd protocols
	pfwd := parser.Find(constants.PortfwdStr)
	pfwd.FindOptionByLongName("protocol").Choices = portfwdProtocols
	pfwdOpen := pfwd.Find(constants.PortfwdOpenStr)
	pfwdOpen.FindOptionByLongName("protocol").Choices = portfwdProtocols
	pfwdClose := pfwd.Find(constants.PortfwdCloseStr)
	pfwdClose.FindOptionByLongName("protocol").Choices = portfwdProtocols
}

// Additional completion mappings for command in the Sliver session context
func sliverCompsAdditional(parser *flags.Parser) {
	session := cctx.Context.Sliver
	if session == nil {
		return // Don't screw up for completions.
	}

	// Extensions

	// MSF execution
	msf := parser.Find(constants.MsfStr)
	msf.FindOptionByLongName("payload").Choices = msfPayloads[session.OS]
	msf.FindOptionByLongName("encoder").Choices = msfEncoders

	// MSF injection
	inj := parser.Find(constants.MsfInjectStr)
	inj.FindOptionByLongName("payload").Choices = msfPayloads[session.OS]
	inj.FindOptionByLongName("encoder").Choices = msfEncoders

	// Portfwd protocols
	pfwd := parser.Find(constants.PortfwdStr)
	pfwd.FindOptionByLongName("protocol").Choices = portfwdProtocols
	pfwdOpen := pfwd.Find(constants.PortfwdOpenStr)
	pfwdOpen.FindOptionByLongName("protocol").Choices = portfwdProtocols
	pfwdClose := pfwd.Find(constants.PortfwdCloseStr)
	pfwdClose.FindOptionByLongName("protocol").Choices = portfwdProtocols

	// Windows only
	if session.OS == "windows" {
		// Registry
		reg := parser.Find(constants.RegistryStr)
		regWrite := reg.Find(constants.RegistryWriteStr)
		regWrite.FindOptionByLongName("type").Choices = windows.ValidTypes

		// Assembly architectures
		exass := parser.Find(constants.ExecuteAssemblyStr)
		exass.FindOptionByLongName("arch").Choices = extensionArch
	}
}