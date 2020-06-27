package core

/*
	Sliver Implant Framework
	Copyright (C) 2020  Bishop Fox

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
	"sync"

	insecureRand "math/rand"

	"github.com/bishopfox/sliver/protobuf/builderpb"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/google/uuid"
)

var (
	// Factories - Manages remote/local builders
	Factories = &factories{
		active: &map[int]*Factory{},
		mutex:  &sync.RWMutex{},
	}
	factoryID = new(int)

	// ErrBuildTaskNotFound - We got an artifact for a task that no longer exists
	ErrBuildTaskNotFound = errors.New("Build task not found")
)

// Factory - Single builder connection
type Factory struct {
	ID             int
	Manifest       *builderpb.FactoryManifest
	Builds         chan *builderpb.BuildTask
	stream         rpcpb.BuilderRPC_RegisterServer
	artifactsMutex *sync.Mutex
	artifacts      map[string]chan *builderpb.Artifact
}

// Build - Build an implant based on a config
func (f *Factory) Build(config *clientpb.ImplantConfig) (<-chan *builderpb.Artifact, string, error) {
	f.artifactsMutex.Lock()
	defer f.artifactsMutex.Unlock()
	guid := uuid.New().String()
	buildTask := &builderpb.BuildTask{
		GUID:          guid,
		ImplantConfig: config,
	}
	artifactChan := make(chan *builderpb.Artifact)
	f.artifacts[guid] = artifactChan
	f.Builds <- buildTask
	return artifactChan, buildTask.GUID, nil
}

// Cancel - Cancel a build task and ignore result
func (f *Factory) Cancel(guid string) {
	f.artifactsMutex.Lock()
	defer f.artifactsMutex.Unlock()
	delete(f.artifacts, guid)
}

// factories - Manage active clients
type factories struct {
	mutex  *sync.RWMutex
	active *map[int]*Factory
}

// AddClient - Add a client struct atomically
func (f *factories) Add(manifest *builderpb.FactoryManifest, stream rpcpb.BuilderRPC_RegisterServer) *Factory {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	factory := &Factory{
		ID:             nextFactoryID(),
		Manifest:       manifest,
		Builds:         make(chan *builderpb.BuildTask),
		stream:         stream,
		artifactsMutex: &sync.Mutex{},
		artifacts:      map[string]chan *builderpb.Artifact{},
	}
	(*f.active)[factory.ID] = factory
	return factory
}

// List - Get a list of active factories
func (f *factories) List() []*Factory {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	factoryList := []*Factory{}
	for _, factory := range *f.active {
		factoryList = append(factoryList, factory)
	}
	return factoryList
}

// Get - Get a specific builder
func (f *factories) Get(factoryID int) *Factory {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if builder, ok := (*f.active)[factoryID]; ok {
		return builder
	}
	return nil
}

// GetFactoryFor - Get a factory for a specific target
func (f *factories) GetFactoryFor(config *clientpb.ImplantConfig) *Factory {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	availableFactories := []*Factory{}
	for _, factory := range *f.active {
		for _, target := range factory.Manifest.Targets {
			if target.GOOS == config.GOOS && target.GOARCH == config.GOARCH {
				availableFactories = append(availableFactories, factory)
			}
		}
	}
	if len(availableFactories) < 1 {
		return nil
	}
	index := insecureRand.Intn(len(availableFactories))
	return availableFactories[index]
}

func (f *factories) BuiltArtifact(artifact *builderpb.Artifact) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	for _, factory := range *f.active {
		if artifactChan, ok := factory.artifacts[artifact.GUID]; ok {
			factory.artifactsMutex.Lock()
			defer factory.artifactsMutex.Unlock()
			artifactChan <- artifact
			delete(factory.artifacts, artifact.GUID)
			close(artifactChan)
			return nil
		}
	}
	return ErrBuildTaskNotFound
}

// RemoveClient - Remove a client struct atomically
func (f *factories) Remove(factoryID int) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if builder, ok := (*f.active)[factoryID]; ok {
		close(builder.Builds)
		delete((*f.active), factoryID)
	}
}

// nextBuilderID - Get a Builder ID
func nextFactoryID() int {
	newID := (*factoryID) + 1
	(*factoryID)++
	return newID
}
