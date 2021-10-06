//go:build !windows

package comm

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

	"golang.org/x/crypto/ssh"

	"github.com/bishopfox/sliver/protobuf/commpb"
)

// DialNamedPipe - Not implemented on generic implants
func DialNamedPipe(info *commpb.Conn, ch ssh.NewChannel) error {
	return errors.New("No named pipes on non-windows systems")
}

// ListenNamedPipe - Not implemented on generic implants
func ListenNamedPipe(handler *commpb.Handler) (ln net.Listener, err error) {
	return nil, errors.New("No named pipes on non-windows systems")
}
