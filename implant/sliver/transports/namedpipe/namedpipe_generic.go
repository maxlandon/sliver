//go:build !windows

package namedpipe

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
	"errors"
	"net"
	"net/url"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Dial - Dial a target destination with a named pipe
func Dial(uri *url.URL, p *sliverpb.Malleable) (c net.Conn, err error) {
	return nil, errors.New("{{if .Config.Debug}}namedpipe.Dial not implemented on this platform{{end}}")
}

// Listen - Listen for incoming named pipe connections
func Listen(uri *url.URL, p *sliverpb.Malleable) (c net.Conn, err error) {
	return nil, errors.New("{{if .Config.Debug}}namedpipe.Listen not implemented on this platform{{end}}")
}
