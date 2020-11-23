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

// The server-side route package works similarly to the implant's route package with respect to:
//
// 1) Proxies used by C2 users are defined and used in the client/ (so that it does not make any
//    difference whether we are the admin -local- or a client -remote-).

// It also works differntly, because the server holds all routes for all implants, while implants
// only have a subset of each route (the next node).
