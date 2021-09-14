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
	"path"
	"path/filepath"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/util/encoders"
	"gopkg.in/AlecAivazis/survey.v1"
)

// Download - Download one or more files from the target to the client.
type Download struct {
	Positional struct {
		LocalPath  string   `description:"console directory/file to save in/as" required:"1-1"`
		RemotePath []string `description:"remote directory name" required:"1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Command.
// Behavior is similar to Linu rm: any number of files arguments will be moved into
// the last, mandary path. The latter can be a file path if file arguments == 1,
// or a directory where everything will be moved when file arguments > 1
func (c *Download) Execute(args []string) (err error) {

	// Local destination
	dlDst, _ := filepath.Abs(c.Positional.LocalPath)
	fi, err := os.Stat(dlDst)
	if err != nil && !os.IsNotExist(err) {
		return log.Errorf("%s", err)
	}

	// If we have more than one file to download, the destination must be a directory.
	if len(c.Positional.RemotePath) > 1 && !fi.IsDir() {
		return log.Errorf("%s is not a directory (must be if you download multiple files)", dlDst)
	}

	// This fucntion verifies that files are not directly overwritten
	var checkDestination = func(src, dst string) (dstFile string, err error) {
		// If our destination is a directory, adjust path
		if fi.IsDir() {
			fileName := filepath.Base(src)
			dst = path.Join(dst, fileName)
			if _, err := os.Stat(dst); err == nil {
				overwrite := false
				prompt := &survey.Confirm{Message: "Overwrite local file?"}
				survey.AskOne(prompt, &overwrite, nil)
				if !overwrite {
					return "", err
				}
			}
			return dst, nil
		}
		// Else directly check and prompt
		if _, err := os.Stat(dst); err == nil {
			overwrite := false
			prompt := &survey.Confirm{Message: "Overwrite local file?"}
			survey.AskOne(prompt, &overwrite, nil)
			if !overwrite {
				return "", err
			}
		}
		return dst, nil
	}

	// Prepare a download function & spinner to be used multiple times.
	var downloadFile = func(src string, dst string) (err error) {
		fileName := filepath.Base(src)

		ctrl := make(chan bool)
		go log.SpinUntil(fmt.Sprintf("%s -> %s", fileName, dst), ctrl)
		download, err := transport.RPC.Download(context.Background(), &sliverpb.DownloadReq{
			Path:    src,
			Request: core.ActiveTarget.Request(),
		})
		ctrl <- true
		<-ctrl
		if err != nil {
			return log.Errorf("%s", err)
		}

		if download.Encoder == "gzip" {
			download.Data, err = new(encoders.Gzip).Decode(download.Data)
			if err != nil {
				return log.Errorf("Decoding failed; %s", err)
			}
		}
		dstFile, err := os.Create(dst)
		if err != nil {
			return log.Errorf("Failed to open local file %s: %s", dst, err)
		}
		defer dstFile.Close()
		n, err := dstFile.Write(download.Data)
		if err != nil {
			return log.Errorf("Failed to write data: %v", err)
		}
		log.Infof("Wrote %d bytes to %s\n", n, dstFile.Name())
		return
	}

	// For each file in the positional arguments, download
	for _, src := range c.Positional.RemotePath {
		dst, err := checkDestination(src, dlDst)
		if err != nil {
			continue
		}
		err = downloadFile(src, dst)
		if err != nil {
			fmt.Printf(err.Error())
		}
	}

	return
}
