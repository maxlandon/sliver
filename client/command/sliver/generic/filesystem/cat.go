package filesystem

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
	"os"

	"github.com/alecthomas/chroma/formatters"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/util/encoders"
)

// Cat - Print one or more files to screen
type Cat struct {
	Positional struct {
		Path []string `description:"remote file name" required:"1"`
	} `positional-args:"yes" required:"yes"`
	Options struct {
		Colorize bool `short:"c" long:"colorize" description:"colorize output according to file extension"`
	} `group:"rm options"`
}

// Execute - Command
func (c *Cat) Execute(args []string) (err error) {

	// Other files
	for _, other := range c.Positional.Path {
		download, err := transport.RPC.Download(context.Background(), &sliverpb.DownloadReq{
			Path:    other,
			Request: core.ActiveTarget.Request(),
		})
		if err != nil {
			log.Errorf("%s\n", err)
			continue
		}
		if download.Encoder == "gzip" {
			download.Data, err = new(encoders.Gzip).Decode(download.Data)
			if err != nil {
				log.Errorf("Encoder error: %s\n", err)
				return nil
			}
		}
		if c.Options.Colorize {
			if err = colorize(download); err != nil {
				fmt.Println(string(download.Data))
			}
		} else {
			fmt.Println(string(download.Data))
		}
	}

	return
}

func colorize(f *sliverpb.Download) error {
	lexer := lexers.Match(f.GetPath())
	if lexer == nil {
		lexer = lexers.Analyse(string(f.GetData()))
		if lexer == nil {
			lexer = lexers.Fallback
		}
	}
	style := styles.Get("monokai")
	if style == nil {
		style = styles.Fallback
	}
	formatter := formatters.Get("terminal16m")
	if formatter == nil {
		formatter = formatters.Fallback
	}
	if lexer != nil {
		iterator, err := lexer.Tokenise(nil, string(f.GetData()))
		if err != nil {
			return err
		}
		err = formatter.Format(os.Stdout, style, iterator)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no lexer found")
	}
	return nil
}
