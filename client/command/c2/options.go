package c2

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
	"fmt"
	"io/ioutil"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// GenericCmd - Generic root command
type GenericCmd struct {
}

// Execute - Generic root command
func (c *GenericCmd) Execute(args []string) (err error) {
	return
}

type DialerOptions struct {
	Core struct {
		Profile string `long:"malleable" short:"m" description:"profile to use as dialer driver: will target its content"`
	} `group:"core dialer options"`
}

type ListenerOptions struct {
	Core struct {
		Profile    string `long:"malleable" short:"m" description:"Profile to use as listener driver: will listen on content"`
		Persistent bool   `long:"persistent" short:"P" description:"listen: transport is a fallback one, and dial: will start listening when implant reconnects"`
	} `group:"core listener options"`
}

type ProfileOptions struct {
	Profile struct {
		Name                string `long:"name" short:"n" description:"A name for this C2 profile"`
		Type                string `long:"type" short:"t" description:"force C2 core type (beacon or session)"`
		Reconnect           int    `long:"reconnect" short:"r" description:"attempt to reconnect every n second(s)" default:"60"`
		PollTimeout         int    `long:"poll-timeout" description:"attempt to poll every n second(s)" default:"360"`
		MaxConnectionErrors int32  `long:"max-errors" short:"E" description:"max number of failed connection attempts" default:"1000"`
		IsFallback          bool   `long:"fallback" short:"f" description:"if true, when cycling C2s the implant is allowed to use it"`
		DisableComm         bool   `long:"no-comm" description:"disable the use of Sessions SSH multiplexing on this channel"`
	} `group:"core profile options"`

	Beacon struct {
		// Beaconing
		IsBeacon bool  `long:"beacon" short:"B" description:"If true, this C2 profile will be a C2 Beacon"`
		Interval int64 `long:"interval" short:"i" description:"reconnection interval between beacons (sets this C2 as beacon)" default:"30"`
		Jitter   int64 `long:"jitter" short:"j" description:"jitter for this beacon (sets this C2 as beacon)" default:"10"`
	} `group:"beacon options"`
}

// SecurityOptions - All options that can be set on any type of C2 Channel Profile.
// Most of these options will be populated with sane defaults anyway.
type SecurityOptions struct {
	Core struct {
		Login       string `long:"login" short:"l" description:"force use of a login name used to fetch and authenticate against creds" default:""`
		Certificate string `long:"cert" short:"c" description:"use a precise server certificate from credential store"`
		PrivateKey  string `long:"key" short:"k" description:"use a precise private key from credential server"`
	} `group:"core security options"`
}

// StagerOptions - Options for C2 handlers that stage payloads.
type StagerOptions struct {
	Core struct {
		Profile   string `long:"profile" short:"p" description:"implant profile/build to serve as stage"`
		LocalPath string `long:"file" short:"f" description:"local path to file containing stage payload bytes"`
		Bytes     string `long:"bytes" short:"b" description:"payload bytes, single-quoted if spaces in it"`
	} `group:"stager options"`
}

// ParseStagerOptions - Based on the user-given values
func ParseStagerOptions(req *clientpb.HandlerStagerReq, options StagerOptions) (err error) {
	opts := options.Core

	if opts.Profile == "" && opts.LocalPath == "" && len(opts.Bytes) == 0 {
		return errors.New("You need to provide a stage with either --profile, --file or --bytes options")
	}

	// If a profile name is given, return this: bytes will be populated server-side
	if opts.Profile != "" {
		req.StageImplant = opts.Profile
		return
	}

	// Read a file for its payload and return without any name.
	if opts.LocalPath != "" {
		bytes, err := ioutil.ReadFile(opts.LocalPath)
		if err != nil {
			return fmt.Errorf("failed to read payload file: %s", err)
		}
		req.StageBytes = bytes
		return nil
	}

	// If the payload was directly given as an option, populate and return.
	if len(opts.Bytes) > 0 {
		req.StageBytes = []byte(opts.Bytes)
		return
	}

	return
}

func getLocalCertificatePair(certPath, keyPath string) ([]byte, []byte, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil, nil
	}
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}
