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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/util/encoders"
)

// Upload - Upload one or more files from the client to the target filesystem.
type Upload struct {
	Positional struct {
		RemotePath string   `description:"remote directory/file to save in/as" required:"1-1"`
		LocalPath  []string `description:"directory name" required:"1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Command.
// Behavior is similar to Linu rm: any number of files arguments will be moved into
// the last, mandary path. The latter can be a file path if file arguments == 1,
// or a directory where everything will be moved when file arguments > 1
func (c *Upload) Execute(args []string) (err error) {

	// If multile files to be uploaded, check destination is a directory.
	var dst string // Absolute path of destination directory, resolved below.
	if len(c.Positional.LocalPath) > 1 {
		resp, err := transport.RPC.Ls(context.Background(), &sliverpb.LsReq{
			Path:    c.Positional.RemotePath,
			Request: core.ActiveTarget.Request(),
		})
		if err != nil {
			log.Errorf("%s\n", err)
			return nil
		}
		if !resp.Exists {
			log.Errorf("%s does not exists or is not a directory\n", c.Positional.RemotePath)
			return nil
		}
		dst = resp.Path
	}

	// For each file to upload, send data
	for _, file := range c.Positional.LocalPath {
		src, _ := filepath.Abs(file)
		_, err := os.Stat(src)
		if err != nil {
			log.Errorf("%s\n", err)
			continue
		}
		fileBuf, err := ioutil.ReadFile(src)
		uploadGzip := new(encoders.Gzip).Encode(fileBuf)

		// Adjust dest with filename
		fileDst := filepath.Join(dst, filepath.Base(src))

		ctrl := make(chan bool)
		go log.SpinUntil(fmt.Sprintf("%s -> %s", src, dst), ctrl)
		upload, err := transport.RPC.Upload(context.Background(), &sliverpb.UploadReq{
			Path:    fileDst,
			Data:    uploadGzip,
			Encoder: "gzip",
			Request: core.ActiveTarget.Request(),
		})
		ctrl <- true
		<-ctrl
		if err != nil {
			log.Errorf("Upload error: %s\n", err)
		} else {
			log.Infof("Wrote file to %s\n", upload.Path)
		}
	}

	return
}
