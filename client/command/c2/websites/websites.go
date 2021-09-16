package websites

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
	"strings"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

const (
	fileSampleSize  = 512
	defaultMimeType = "application/octet-stream"
)

// WebsiteOptions - General website options
type WebsiteOptions struct {
	Website     string `long:"website" short:"w" description:"website name" required:"true"`
	WebPath     string `long:"web-path" short:"p" description:"HTTP path to host file at" default:"/"`
	Content     string `long:"content" short:"c" description:"local file path/dir (must use --recursive if dir)"`
	ContentType string `long:"content-type" short:"C" description:"MIME content-type (if blank, use file ext.)"`
	Recursive   bool   `long:"recursive" short:"r" description:"apply command (delete/add) recursively"`
}

// Websites - All websites management commands
type Websites struct {
}

// Execute - Command
func (w *Websites) Execute(args []string) (err error) {
	err = listWebsites(w, transport.RPC)
	return
}

func listWebsites(w *Websites, rpc rpcpb.SliverRPCClient) (err error) {
	websites, err := rpc.Websites(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Errorf("Failed to list websites %s", err)
	}
	if len(websites.Websites) < 1 {
		log.Infof("No websites")
		return
	}
	fmt.Println(readline.Bold(readline.Yellow("Websites")))
	fmt.Println(strings.Repeat("=", len("Websites")))
	for _, site := range websites.Websites {
		fmt.Printf("%s%s%s - %d page(s)\n", readline.BOLD, site.Name, readline.RESET, len(site.Contents))
	}

	return
}
