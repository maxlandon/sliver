package httpclient

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
	"net/url"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// NewBeacon - Instantiate a new HTTP beacon client channel, ready to work.
func NewBeacon(uri *url.URL) (client *SliverHTTPClient) {
	return
}

// Start - Implements the most basic Beacon interface, which is more of an async function now.
func (h *SliverHTTPClient) Start(uri *url.URL) {
	return
}

// Recv - Receive a beacon Task from the server. Implements the beacon interface
func (h *SliverHTTPClient) Recv() (envelope *sliverpb.Envelope, err error) {
	return
}

// Send - Send part or full output of a beacon task back to the server. Implements the beacon interface
func (h *SliverHTTPClient) Send(envelope *sliverpb.Envelope) (err error) {
	return
}

// Close - Close the HTTP C2 beacon channel. Implements the beacon interface
func (h *SliverHTTPClient) Close() (err error) {
	return
}
