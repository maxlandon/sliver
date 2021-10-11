package http

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

import "github.com/bishopfox/sliver/protobuf/sliverpb"

// HTTP - HTTP handlers management root command.
type HTTP struct{}

// Execute - HTTP handlers management root command.
func (h *HTTP) Execute(args []string) (err error) {
	return
}

// Options - All options pertaining to HTTP C2 Profiles
type Options struct {
	Core struct {
		PollTimeout int32  `long:"poll-timeout" short:"T" description:"timeout between long polling" default:"30"`
		ProxyURL    string `long:"proxy" short:"P" description:"an optional URL to a system proxy"`
		UserAgent   string `long:"user-agent" short:"U" description:"a single-quoted user agent string"`
	} `group:"core http options"`
}

type AdvancedOptions struct {
	Core struct {
		// Key Exchange (default .txt) files and paths
		KeyExchangeFileExt string   `long:"key_exchange_file_ext" description:"file extensions for key exchange"`
		KeyExchangeFiles   []string `long:"key_exchange_files" description:"filenames for key exchange"`
		KeyExchangePaths   []string `long:"key_exchange_paths" description:"paths for key exchange"`

		// Poll files and paths
		PollFileExt string   `long:"poll_file_ext" description:"file extensions for polling"`
		PollFiles   []string `long:"poll_files" description:"filenames for key exchange"`
		PollPaths   []string `long:"poll_paths" description:"paths for polling"`

		// Session files and paths
		StartSessionFileExt string   `long:"start_session_file_ext" description:"file extensions for Session start"`
		SessionFileExt      string   `long:"session_file_ext" description:"file extensions for session"`
		SessionFiles        []string `long:"session_files" description:"filenames for session"`
		SessionPaths        []string `long:"session_paths" description:"paths for session"`

		// Close session files and paths
		CloseFileExt string   `long:"close_file_ext" description:"file extensions for closing session"`
		CloseFiles   []string `long:"close_files" description:"filenames for closing session"`
		ClosePaths   []string `long:"close_paths" description:"paths for closing session"`
	} `group:"advanced http options"`
}

func PopulateProfileHTTP(profile *sliverpb.Malleable, options AdvancedOptions) {
	opts := options.Core

	profile.HTTP = &sliverpb.MalleableHTTP{
		// Stager File Extension
		// StagerFileExt : opts.S

		// Key Exchange (default .txt) files and paths
		KeyExchangeFileExt: opts.KeyExchangeFileExt,
		KeyExchangeFiles:   opts.KeyExchangeFiles,
		KeyExchangePaths:   opts.KeyExchangePaths,

		// Poll files and paths
		PollFileExt: opts.PollFileExt,
		PollFiles:   opts.PollFiles,
		PollPaths:   opts.PollPaths,

		// Session files and paths
		StartSessionFileExt: opts.StartSessionFileExt,
		SessionFileExt:      opts.SessionFileExt,
		SessionFiles:        opts.SessionFiles,
		SessionPaths:        opts.SessionPaths,
	}
}
