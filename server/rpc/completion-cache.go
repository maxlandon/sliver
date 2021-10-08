package rpc

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
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"

	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
)

var (
	// Cache The unique completion cache for this console client.
	Cache = &cache{
		Hosts: map[string]*HostCache{},
		mutex: sync.RWMutex{},
	}

	// Refresh frequency times
	fsRefreshTime   = 10 * time.Second
	procRefreshTime = 10 * time.Second
	netRefreshTime  = 1 * time.Hour
	envRefreshTime  = 1 * time.Hour
)

type genericHandler func(req GenericRequest, res GenericResponse) error

// cache - In order to avoid making too many requests to implants,
// we use a global cache that stores many items that we might have to retrieve
// from implants. This cache is also responsible for actually requesting data
// to implants, either when forced to, or when it determines the values are too
// old to be reliable. We can also request the cache to update part or fully.
type cache struct {
	Hosts map[string]*HostCache
	mutex sync.RWMutex
}

// AddSessionCache - Create a new cache for a newly registered session.
func (c *cache) AddSessionCache(host *models.Host, rpcHandler genericHandler) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	cache := &HostCache{
		host:        host,
		rpcHandler:  rpcHandler,
		CurrentDirs: map[string]*directory{},
		mutex:       &sync.RWMutex{},
		vars:        map[string]string{},
	}
	c.Hosts[host.HostUUID.String()] = cache
}

// GetSessionCache - A completer needs the cache of a session.
func (c *cache) GetSessionCache(ID string, rpcHandler genericHandler) (cache *HostCache) {

	cache, found := c.Hosts[ID]
	if !found {
		// Create a new cache if it does not exist
		host, err := db.HostByHostUUID(ID)
		if err != nil {
			c.AddSessionCache(&models.Host{HostUUID: uuid.FromStringOrNil(ID)}, rpcHandler)
			cache, found = c.Hosts[ID]
			return cache
		}
		c.AddSessionCache(host, rpcHandler)
		cache, found = c.Hosts[host.HostUUID.String()]
		return cache
	}

	return cache
}

// Reset - After each input loop (command executed) reset
// parts or all of session completion data caches
func (c *cache) Reset() {
	for _, cache := range c.Hosts {
		cache.Reset(false)
	}
}

// HostCache - A cache of data dedicated to a single Session.
type HostCache struct {
	host       *models.Host
	rpcHandler genericHandler

	CurrentDirs map[string]*directory // File system

	// Environment
	vars           map[string]string
	envlastUpdated time.Time

	// Network
	Interfaces      *sliverpb.Ifconfig
	ifaceLastUpdate time.Time

	// Processes. Usually we request to implant if processes have
	// not been updated in the last 30 seconds, as might move fast.
	Processes      *sliverpb.Ps
	procLastUpdate time.Time

	// Concurrency management
	mutex *sync.RWMutex
}

// directory - A directory and its contents stored in the cache
type directory struct {
	path        string
	contents    *sliverpb.Ls
	lastUpdated time.Time
}

// GetDirectoryContents - A completer wants a directory list. If we have it and its fresh enough, return
// it directly. Otherwise, make the request on behalf of the completer, store results and return them.
func (sc *HostCache) GetDirectoryContents(path string, sessionID uint32) (files *sliverpb.Ls) {

	// Check cache first
	if dir, found := sc.CurrentDirs[path]; found {
		if time.Since(dir.lastUpdated) < fsRefreshTime && dir.contents.Files != nil {
			return dir.contents
		}
	}

	// Sometimes the path given by the client contains an incomplete base path,
	// which we trim and check the current dir against.
	if strings.HasSuffix(path, "/") && path != "/" {
		path = strings.TrimSuffix(path, "/")
	}
	if dir, found := sc.CurrentDirs[path]; found {
		if time.Since(dir.lastUpdated) < fsRefreshTime && dir.contents.Files != nil {
			return dir.contents
		}
	}

	dir, found := sc.CurrentDirs[path]

	// Else, request files to the implant.
	var dirList = &sliverpb.Ls{}
	err := sc.rpcHandler(&sliverpb.LsReq{
		Request: &commonpb.Request{SessionID: sessionID},
		Path:    path},
		dirList,
	)
	// If error, the session is a beacon, return the last value known
	if err != nil {
		if found {
			return dir.contents
		}
		return nil
	}

	// Cache the data first
	sc.mutex.Lock()
	sc.CurrentDirs[path] = &directory{
		// sc.CurrentDirs[dirList.Path] = &directory{
		// path: dirList.Path, // TODO: Maybe on the long run this is more reliable
		path:        path,
		contents:    dirList,
		lastUpdated: time.Now(),
	}
	sc.mutex.Unlock()

	// And then return it
	return dirList
}

// AddDirectory - Add directory contents to the cache.
func (sc *HostCache) AddDirectory(dir *sliverpb.Ls) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	sc.CurrentDirs[dir.Path] = &directory{
		path:        dir.Path,
		contents:    dir,
		lastUpdated: time.Now(),
	}
}

// RmDirectory - Remove a directory contents from the cache.
func (sc *HostCache) RmDirectory(path string) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	for dirPath := range sc.CurrentDirs {
		if dirPath == path {
			delete(sc.CurrentDirs, path)
		}
	}
}

// RefreshInterfaces - Update the list of network interfaces
func (sc *HostCache) RefreshInterfaces(ifaces *sliverpb.Ifconfig) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	sc.Interfaces = ifaces
	sc.ifaceLastUpdate = time.Now()
}

// GetNetInterfaces - Returns the net interfaces for an implant, either cached or requested.
func (sc *HostCache) GetNetInterfaces(sessionID uint32) (ifaces *sliverpb.Ifconfig) {

	if time.Since(sc.ifaceLastUpdate) < netRefreshTime && sc.Interfaces != nil {
		return sc.Interfaces
	}

	ifaces = &sliverpb.Ifconfig{}
	err := sc.rpcHandler(&sliverpb.IfconfigReq{
		Request: &commonpb.Request{SessionID: sessionID}},
		ifaces,
	)
	if err != nil {
		if sc.Interfaces != nil {
			return sc.Interfaces
		}
		return
	}

	// Cache data and reset timer
	sc.Interfaces = ifaces
	sc.ifaceLastUpdate = time.Now()

	return ifaces
}

func (sc *HostCache) envToProtobuf() *sliverpb.EnvInfo {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	info := &sliverpb.EnvInfo{}
	for key, value := range sc.vars {
		info.Variables = append(info.Variables, &commonpb.EnvVar{
			Key:   key,
			Value: value,
		})
	}
	return info
}

// RefreshEnvironmentVariables - Update the list of environment variables
func (sc *HostCache) RefreshEnvironmentVariables(env *sliverpb.EnvInfo) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	for _, variable := range env.Variables {
		sc.vars[variable.Key] = variable.Value
	}
	sc.envlastUpdated = time.Now()
}

// RemoveEnvironmentVariables - Remove one or more env vars
func (sc *HostCache) RemoveEnvironmentVariables(vars []string) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	for _, variable := range vars {
		sc.mutex.Lock()
		defer sc.mutex.Unlock()
		delete(sc.vars, variable)
	}
}

// GetEnvironmentVariables - Returns the list of environment variables found on the host
func (sc *HostCache) GetEnvironmentVariables(sessionID uint32) (env *sliverpb.EnvInfo) {

	if time.Since(sc.envlastUpdated) < envRefreshTime {
		return sc.envToProtobuf()
	}

	env = &sliverpb.EnvInfo{}
	err := sc.rpcHandler(&sliverpb.EnvReq{
		Request: &commonpb.Request{SessionID: sessionID},
		Name:    ""},
		env,
	)
	if err != nil {
		return sc.envToProtobuf()
	}

	sc.RefreshEnvironmentVariables(env)
	return sc.envToProtobuf()
}

// RefreshProcesses - Update the list of running processes
func (sc *HostCache) RefreshProcesses(procs *sliverpb.Ps) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	sc.Processes = procs
	sc.procLastUpdate = time.Now()
}

// GetProcesses - Returns the list of processes running on the session host.
func (sc *HostCache) GetProcesses(sessionID uint32) (procs *sliverpb.Ps) {

	if time.Since(sc.procLastUpdate) < procRefreshTime && sc.Processes != nil {
		return sc.Processes
	}

	procs = &sliverpb.Ps{}
	err := sc.rpcHandler(&sliverpb.PsReq{
		Request: &commonpb.Request{SessionID: sessionID}},
		procs,
	)
	if err != nil {
		if sc.Processes != nil {
			return sc.Processes
		}
		return
	}

	// We should not have an empty list
	if len(procs.Processes) == 0 {
		if sc.Processes != nil {
			return sc.Processes
		}
		return procs
	}

	// Cache data and reset timer
	sc.RefreshProcesses(procs)
	return sc.Processes
}

// Reset - The session completion cache resets all or most of its items.
// This function is usually called at the end of each input command, because
// we might have modified the filesystem, processes may have new IDs pretty fast, etc...
// If all is false, we don't reset things like net Interfaces.
func (sc *HostCache) Reset(all bool) {

	sc.CurrentDirs = map[string]*directory{} // Reset directory contents
	sc.Processes = nil                       // Reset processes

	// More stable (usually) values are only cleared if all is true
	if all {
		sc.Interfaces = nil
		sc.vars = map[string]string{}
	}
}
