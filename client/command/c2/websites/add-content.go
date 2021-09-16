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
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"

	"gopkg.in/AlecAivazis/survey.v1"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// WebsitesAddContent - Add content to a website
type WebsitesAddContent struct {
	WebsiteOptions `group:"content options"`
}

// Execute - Command
func (w *WebsitesAddContent) Execute(args []string) (err error) {
	websiteName := w.Website
	if websiteName == "" {
		return log.Errorf("Must specify a website name via --website, see --help")
	}
	webPath := w.WebPath
	if webPath == "" {
		return log.Errorf("Must specify a web path via --web-path, see --help")
	}
	contentPath := w.Content
	if contentPath == "" {
		return log.Errorf("Must specify some --content")
	}
	contentPath, _ = filepath.Abs(contentPath)
	contentType := w.ContentType
	recursive := w.Recursive

	fileInfo, err := os.Stat(contentPath)
	if err != nil {
		return log.Errorf("Error adding content %s", err)
	}

	addWeb := &clientpb.WebsiteAddContent{
		Name:     websiteName,
		Contents: map[string]*clientpb.WebContent{},
	}

	if fileInfo.IsDir() {
		if !recursive && !confirmAddDirectory() {
			return
		}
		webAddDirectory(addWeb, webPath, contentPath)
	} else {
		webAddFile(addWeb, webPath, contentType, contentPath)
	}

	web, err := transport.RPC.WebsiteAddContent(context.Background(), addWeb)
	if err != nil {
		return log.Error(err)
	}
	displayWebsite(web)
	return
}

func confirmAddDirectory() bool {
	confirm := false
	prompt := &survey.Confirm{Message: "Recursively add entire directory?"}
	survey.AskOne(prompt, &confirm, nil)
	return confirm
}

func webAddDirectory(web *clientpb.WebsiteAddContent, webpath string, contentPath string) {
	fullLocalPath, _ := filepath.Abs(contentPath)
	filepath.Walk(contentPath, func(localPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// localPath is the full absolute path to the file, so we cut it down
			fullWebpath := path.Join(webpath, localPath[len(fullLocalPath):])
			webAddFile(web, fullWebpath, "", localPath)
		}
		return nil
	})
}

func webAddFile(web *clientpb.WebsiteAddContent, webpath string, contentType string, contentPath string) error {

	fileInfo, err := os.Stat(contentPath)
	if os.IsNotExist(err) {
		return err // contentPath does not exist
	}
	if fileInfo.IsDir() {
		return errors.New("file content path is directory")
	}

	file, err := os.Open(contentPath)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	if contentType == "" {
		contentType = sniffContentType(file)
	}

	web.Contents[webpath] = &clientpb.WebContent{
		Path:        webpath,
		ContentType: contentType,
		Content:     data,
	}
	return nil
}

func sniffContentType(out *os.File) string {
	out.Seek(0, io.SeekStart)
	buffer := make([]byte, fileSampleSize)
	_, err := out.Read(buffer)
	if err != nil {
		return defaultMimeType
	}
	contentType := http.DetectContentType(buffer)
	return contentType
}
