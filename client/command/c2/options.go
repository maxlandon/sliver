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

// GenericCmd - Generic root command
type GenericCmd struct {
}

// Execute - Generic root command
func (c *GenericCmd) Execute(args []string) (err error) {
	return
}

type DialerOptions struct {
	Core struct {
		Profile string `long:"profile" short:"p" description:"profile to use as dialer driver: will target its content"`
	} `group:"core dialer options"`
}

// Dialer - Create a new dialer C2 Profile for any available protocol
type Dialer struct {
}

// Execute - Create a new dialer C2 Profile for any available protocol
func (d *Dialer) Execute(args []string) (err error) {
	return
}

type ListenerOptions struct {
	Core struct {
		Profile    string `long:"profile" short:"p" description:"Profile to use as listener driver: will listen on content"`
		Persistent bool   `long:"persistent" short:"P" description:"listen: transport is a fallback one, and dial: will start listening when implant reconnects"`
	} `group:"core listener options"`
}

// Listener - Create a new listener C2 Profile for available protocol
type Listener struct{}

// Execute - Create a new listener C2 Profile for available protocol
func (l *Listener) Execute(args []string) (err error) {
	return
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

// Configure - Root C2 profile management command for
// all root commands needing it (malleable, mtls, dns, http, etc...)
type Configure struct {
}

// Execute - Dispatch to sub command specialized per C2 type.
func (t *Configure) Execute(args []string) (err error) {
	return
}
