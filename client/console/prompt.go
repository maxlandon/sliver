package console

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
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/maxlandon/readline"
	"google.golang.org/grpc"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

var (
	// serverCallbacks - All items needed by the prompt when in Server menu.
	serverCallbacks = map[string]func() string{
		// Local working directory
		"{cwd}": func() string {
			cwd, err := os.Getwd()
			if err != nil {
				return "ERROR: Could not get working directory !"
			}
			return cwd
		},
		// Server IP
		"{server_ip}": func() string {
			return serverConfig.LHost
		},
		// Local IP address
		"{local_ip}": func() string {
			addrs, _ := net.InterfaceAddrs()
			var ip string
			for _, addr := range addrs {
				network, ok := addr.(*net.IPNet)
				if ok && !network.IP.IsLoopback() && network.IP.To4() != nil {
					ip = network.IP.String()
				}
			}
			return ip
		},
		// Jobs and/or listeners
		"{jobs}": func() string {
			req := &commonpb.Empty{}
			res, _ := transport.RPC.GetJobs(context.Background(), req, grpc.EmptyCallOption{})
			return strconv.Itoa(len(res.Active))
		},
		// Sessions
		"{sessions}": func() string {
			sReq := &commonpb.Empty{}
			sRes, _ := transport.RPC.GetSessions(context.Background(), sReq, grpc.EmptyCallOption{})
			return strconv.Itoa(len(sRes.Sessions))
		},
		"{timestamp}": func() string {
			return time.Now().Format("15:04:05.000")
		},
	}

	// serverColorCallbacks - All colors and effects needed in the main menu
	serverColorCallbacks = map[string]string{
		// Base readline colors
		"{blink}": "\033[5m", // blinking
		"{bold}":  readline.BOLD,
		"{dim}":   readline.DIM,
		"{fr}":    readline.RED,
		"{g}":     readline.GREEN,
		"{b}":     readline.BLUE,
		"{y}":     readline.YELLOW,
		"{fw}":    readline.FOREWHITE,
		"{bdg}":   readline.BACKDARKGRAY,
		"{br}":    readline.BACKRED,
		"{bg}":    readline.BACKGREEN,
		"{by}":    readline.BACKYELLOW,
		"{blb}":   readline.BACKLIGHTBLUE,
		"{reset}": readline.RESET,
		// Custom colors
		"{ly}":   "\033[38;5;187m",
		"{lb}":   "\033[38;5;117m", // like VSCode var keyword
		"{db}":   "\033[38;5;24m",
		"{bddg}": "\033[48;5;237m",
	}
)

var (
	sliverCallbacks = map[string]func() string{
		"{session_name}": func() string {
			if core.ActiveTarget.Session != nil {
				return core.ActiveTarget.Session.Name
			}
			return core.ActiveTarget.Beacon.Name
		},
		"{wd}": func() string {
			if core.ActiveTarget.Session != nil {
				return core.ActiveTarget.Session.WorkingDirectory
			}
			return core.ActiveTarget.Beacon.WorkingDirectory
		},
		"{user}": func() string {
			if core.ActiveTarget.Session != nil {
				return core.ActiveTarget.Session.Username
			}
			return core.ActiveTarget.Beacon.Username
		},
		"{host}": func() string {
			if core.ActiveTarget.Session != nil {
				return core.ActiveTarget.Session.Hostname
			}
			return core.ActiveTarget.Beacon.Hostname
		},
		"{address}": func() string {
			if core.ActiveTarget.Session != nil {
				return core.ActiveTarget.Session.RemoteAddress
			}
			return core.ActiveTarget.Beacon.RemoteAddress
		},
		"{platform}": func() string {
			if core.ActiveTarget.Session != nil {
				os := core.ActiveTarget.Session.OS
				arch := core.ActiveTarget.Session.Arch
				return fmt.Sprintf("%s/%s", os, arch)
			}
			os := core.ActiveTarget.Beacon.OS
			arch := core.ActiveTarget.Beacon.Arch
			return fmt.Sprintf("%s/%s", os, arch)
		},
		"{os}": func() string {
			if core.ActiveTarget.Session != nil {
				return core.ActiveTarget.Session.OS
			}
			return core.ActiveTarget.Beacon.OS
		},
		"{arch}": func() string {
			if core.ActiveTarget.Session != nil {
				return core.ActiveTarget.Session.Arch
			}
			return core.ActiveTarget.Beacon.Arch
		},
		"{status}": func() string {
			if core.ActiveTarget.Session != nil {
				if core.ActiveTarget.Session.IsDead {
					return "DEAD"
				}
				return "up"
			}
			if core.ActiveTarget.Beacon.IsDead {
				return "DEAD"
			}
			return "up"
		},
		"{version}": func() string {
			if core.ActiveTarget.Session != nil {
				return core.ActiveTarget.Session.Version
			}
			return core.ActiveTarget.Beacon.Version
		},
		"{uid}": func() string {
			if core.ActiveTarget.Session != nil {
				return core.ActiveTarget.Session.UID
			}
			return core.ActiveTarget.Beacon.UID
		},
		"{gid}": func() string {
			if core.ActiveTarget.Session != nil {
				return core.ActiveTarget.Session.GID
			}
			return core.ActiveTarget.Beacon.GID
		},
		"{pid}": func() string {
			if core.ActiveTarget.Session != nil {
				return strconv.Itoa(int(core.ActiveTarget.Session.PID))
			}
			return strconv.Itoa(int(core.ActiveTarget.Beacon.PID))
		},
	}

	sliverColorCallbacks = map[string]string{
		// Base readline colors
		"{blink}": "\033[5m", // blinking
		"{bold}":  readline.BOLD,
		"{dim}":   readline.DIM, // for Base Dim
		"{fr}":    readline.RED, // for Base Fore Red
		"{g}":     readline.GREEN,
		"{b}":     readline.BLUE,
		"{y}":     readline.YELLOW,
		"{fw}":    readline.FOREWHITE, // for Base Fore White.
		"{dg}":    readline.BACKDARKGRAY,
		"{br}":    readline.BACKRED,
		"{bg}":    readline.BACKGREEN,
		"{by}":    readline.BACKYELLOW,
		"{blb}":   readline.BACKLIGHTBLUE,
		"{reset}": readline.RESET,
		// Custom colors
		"{ly}":   "\033[38;5;187m",
		"{lb}":   "\033[38;5;117m", // like VSCode var keyword
		"{bddg}": "\033[48;5;237m",
	}
)
