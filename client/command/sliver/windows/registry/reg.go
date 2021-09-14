package registry

/*
	sliver implant framework
	copyright (c) 2019  bishop fox

	this program is free software: you can redistribute it and/or modify
	it under the terms of the gnu general public license as published by
	the free software foundation, either version 3 of the license, or
	(at your option) any later version.

	this program is distributed in the hope that it will be useful,
	but without any warranty; without even the implied warranty of
	merchantability or fitness for a particular purpose.  see the
	gnu general public license for more details.

	you should have received a copy of the gnu general public license
	along with this program.  if not, see <https://www.gnu.org/licenses/>.
*/

var validHives = []string{
	"HKCU",
	"HKLM",
	"HKCC",
	"HKPD",
	"HKU",
	"HKCR",
}

var ValidTypes = []string{
	"binary",
	"dword",
	"qword",
	"string",
}

// Registry - Windows registry management
type Registry struct{}

// Execute - Windows registry management. Requires a subcommand.
func (r *Registry) Execute(args []string) (err error) {
	return
}
