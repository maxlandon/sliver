package completion

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
	"github.com/maxlandon/readline"
)

// Command/option argument choices
var (
	// Logs & components
	logLevels = []string{"trace", "debug", "info", "warning", "error"}
	loggers   = []string{"client"}
)

func LogLevels() (comps []*readline.CompletionGroup) {
	comp := &readline.CompletionGroup{
		Name:         "levels",
		Descriptions: map[string]string{},
		DisplayType:  readline.TabDisplayGrid,
	}
	for _, lvl := range logLevels {
		comp.Suggestions = append(comp.Suggestions, lvl)
	}

	return []*readline.CompletionGroup{comp}
}

func Loggers() (comps []*readline.CompletionGroup) {
	comp := &readline.CompletionGroup{
		Name:         "loggers",
		Descriptions: map[string]string{},
		DisplayType:  readline.TabDisplayGrid,
	}
	for _, logger := range loggers {
		comp.Suggestions = append(comp.Suggestions, logger)
	}

	return []*readline.CompletionGroup{comp}
}