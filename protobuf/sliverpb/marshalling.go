package sliverpb

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

// MarshalJSON - A custom method for implementing the json.Marshaller interface,
// used to automatically set fields necessary to correct Malleable edition/usage.
// func (m *Malleable) MarshalJSON() (data []byte, err error) {
//         return json.Marshal(m)
// }
//
// // UnmarshalJSON - A custom method for implementing the json.Unmarshaller interface.
// // This always ensure that some private necessary for good operation of the Malleable
// // are present and correctly set.
// func (m *Malleable) UnmarshalJSON(data []byte) (err error) {
//         return json.Unmarshal(data, m)
// }
