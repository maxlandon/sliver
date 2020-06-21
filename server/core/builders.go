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
	"sync"

	"github.com/bishopfox/sliver/protobuf/builderpb"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

var (
	// Builders - Manages remote/local builders
	Builders = &builders{
		active: &map[int]*Builder{},
		mutex:  &sync.RWMutex{},
	}
	builderID = new(int)
)

// Builder - Single builder connection
type Builder struct {
	ID       int
	Manifest *builderpb.BuilderManifest
	Stream   rpcpb.BuilderRPC_RegisterServer
	Builds   chan *clientpb.ImplantConfig
}

// builders - Manage active clients
type builders struct {
	mutex  *sync.RWMutex
	active *map[int]*Builder
}

// AddClient - Add a client struct atomically
func (b *builders) Add(manifest *builderpb.BuilderManifest, stream rpcpb.BuilderRPC_RegisterServer) *Builder {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	builder := &Builder{
		ID:       nextBuilderID(),
		Manifest: manifest,
		Stream:   stream,
		Builds:   make(chan *clientpb.ImplantConfig),
	}
	(*b.active)[builder.ID] = builder
	return builder
}

// List - Get a list of builders
func (b builders) List() []*Builder {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	builders := []*Builder{}
	for _, builder := range *b.active {
		builders = append(builders, builder)
	}
	return builders
}

// Get - Get a specific builder
func (b *builder) Get(builderID int) *Builder {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if builder, ok := (*b.active)[builderID]; ok {
		return builder
	}
	return nil
}

// GetBuilderFor - Get a builder for a specific target
func (b *builder) GetBuilderFor(config *clientpb.ImplantConfig) *Builder {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	availableBuilders := []*Builder{}
	for builder := range *b.active {
		for _, target := builder.Manifest.Targets {
			if target.GOOS == config.GOOS && target.GOARCH == config.GOARCH {
				availableBuilders = append(availableBuilders, builder)
			}
		}
	}
	if len(availableBuilders) < 1 {
		return nil
	}
	index := insecureRand.Intn(0, len(avavailableBuilders))
	return availableBuilders[index]
}

// RemoveClient - Remove a client struct atomically
func (b *builders) Remove(builderID int) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if builder, ok := (*b.active)[builderID]; ok {
		close(builder.Builds)
		delete((*b.active), builderID)
	}
}

// nextBuilderID - Get a Builder ID
func nextBuilderID() int {
	newID := (*builderID) + 1
	(*builderID)++
	return newID
}
