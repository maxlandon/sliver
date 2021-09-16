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
	"fmt"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// GenerateInfo - Display information on the Sliver server's compiler configuration
type GenerateInfo struct{}

// Execute - Display information on the Sliver server's compiler configuration
func (g *GenerateInfo) Execute(args []string) (err error) {

	compiler, err := transport.RPC.GetCompiler(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Errorf("Failed to get compiler information: %s", err)
	}
	log.Infof("%sServer:%s %s/%s\n", readline.BOLD, readline.RESET, compiler.GOOS, compiler.GOARCH)
	fmt.Printf("%sCross Compilers%s\n", readline.BOLD, readline.RESET)
	for _, cc := range compiler.CrossCompilers {
		fmt.Printf("  %s/%s - %s\n", cc.TargetGOOS, cc.TargetGOARCH, cc.GetCCPath())
	}
	fmt.Println()
	fmt.Printf("%sSupported Targets%s\n", readline.BOLD, readline.RESET)
	for _, target := range compiler.Targets {
		fmt.Printf("  %s/%s - %s\n", target.GOOS, target.GOARCH, nameOfOutputFormat(target.Format))
	}
	fmt.Println()
	fmt.Printf("%sDefault Builds Only%s\n", readline.BOLD, readline.RESET)
	for _, target := range compiler.UnsupportedTargets {
		fmt.Printf("  %s/%s - %s\n", target.GOOS, target.GOARCH, nameOfOutputFormat(target.Format))
	}

	return nil
}
