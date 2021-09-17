package monitor

import (
	"context"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

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

// Start - Start monitoring threat intel for implants
type Start struct{}

// Execute - Start monitoring threat intel for implants
func (m *Start) Execute(args []string) (err error) {

	resp, err := transport.RPC.MonitorStart(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Errorf("Failed to start intel monitoring: %s", err)
	}
	if resp != nil && resp.Err != "" {
		return log.Errorf("Failed to start intel monitoring: %s", resp.Err)
	}
	log.Infof("Started monitoring threat intel platforms for implants hashes")

	return
}
