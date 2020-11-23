package route

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

// The route package is used to route all traffic going either:
// - From the server to a pivoted implant (through this pivot)
// - From a pivoted implant back to the server
// - From the server to an endpoint that is not an implant.

// In the case of implant-to-server communications, the
// traffic should never leave the physical connections:
// Server -> pivot      and     pivot -> pivoted implant.

// In any case, this pivot should NEVER open any listener on the host.
// The listener is always a multiplexer, which satisfies the net.Listener interface.

// Also, as opposed to gost where it doesn't matter opening physical conns,
// and therefore where it does not matter to share the route chain between all
// proxy nodes, we need to divide the Route between all nodes, where each node
// only knows about the next one, and is therefore able to use mux conns to route traffic.
