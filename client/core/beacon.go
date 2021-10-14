package core

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
	"sync"

	"github.com/maxlandon/readline"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

var (
	beacons = &beaconCallbacks{
		TaskCallbacks:      map[string]BeaconTaskCallback{},
		TaskCallbacksMutex: &sync.Mutex{},
	}
)

// BeaconTaskCallback - A function called on requests/interactions with beacons
type BeaconTaskCallback func(*clientpb.BeaconTask)

type beaconCallbacks struct {
	TaskCallbacks      map[string]BeaconTaskCallback
	TaskCallbacksMutex *sync.Mutex
}

// TriggerBeaconTaskCallback - Triggers the callback for a beacon task
func TriggerBeaconTaskCallback(data []byte) {

	task := &clientpb.BeaconTask{}
	err := proto.Unmarshal(data, task)
	if err != nil {
		log.ErrorfAsync("Could not unmarshal beacon task: %s", err)
		return
	}

	// If the callback is not in our map then we don't do anything, the beacon task
	// was either issued by another operator in multiplayer mode or the client process
	// was restarted between the time the task was created and the server go the result
	beacons.TaskCallbacksMutex.Lock()
	defer beacons.TaskCallbacksMutex.Unlock()

	if callback, ok := beacons.TaskCallbacks[task.ID]; ok {

		// Notify the client
		log.SuccessfAsync("Task completed: %s %s[%s]%s", ShortID(task.ID),
			readline.DIM, ShortID(task.BeaconID), readline.RESET)

		if assets.UserClientSettings.BeaconAutoResults {
			// TODO: The background context could block forever and deadlock the mutex
			task, err = transport.RPC.GetBeaconTaskContent(context.Background(), &clientpb.BeaconTask{
				ID: task.ID,
			})
			if err == nil {
				callback(task)
			} else {
				log.ErrorfAsync("Could not get beacon task content: %s", err)
			}
		}
		delete(beacons.TaskCallbacks, task.ID)
	}
}

// AddBeaconCallback - Map the command sent for identifying the response and displaying it.
func AddBeaconCallback(taskID string, callback BeaconTaskCallback) {
	log.Infof("Tasked beacon (%s)", taskID)
	beacons.TaskCallbacksMutex.Lock()
	defer beacons.TaskCallbacksMutex.Unlock()
	beacons.TaskCallbacks[taskID] = callback
}

// ShortID - Get a short ID for long beacon UUIDs
func ShortID(id string) string {
	var shortID string
	if len(id) < 8 {
		shortID = id
	} else {
		shortID = id[:8]
	}
	return shortID
}
