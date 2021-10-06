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
	"math/rand"
	"strconv"
	"sync"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/gofrs/uuid"
)

var (
	// Clients - Manages client active
	Clients = &clients{
		active: map[string]*Client{},
		mutex:  &sync.Mutex{},
	}

	clientID = 0
)

// Client - Single client connection
type Client struct {
	ID       string
	Operator *clientpb.Operator
}

// ToProtobuf - Get the protobuf version of the object
func (c *Client) ToProtobuf() *clientpb.Client {
	return &clientpb.Client{
		ID:       c.ID,
		Operator: c.Operator,
	}
}

// clients - Manage active clients
type clients struct {
	active map[string]*Client
	mutex  *sync.Mutex
}

// AddClient - Add a client struct atomically
func (cc *clients) Add(client *Client) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	cc.active[client.ID] = client

	if len(cc.OperatorClients(client.Operator.Name)) == 1 {
		EventBroker.Publish(Event{
			Type:   clientpb.EventType_UserJoined,
			Client: client,
		})
	}
}

// AddClient - Add a client struct atomically
func (cc *clients) ActiveOperators() []string {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	operators := []string{}
	for _, client := range cc.active {
		operators = append(operators, client.Operator.Name)
	}
	return operators
}

// Get - Find a client by its ID, always sent in command requests
func (cc *clients) Get(ID string) *Client {
	for _, client := range cc.active {
		if client.ID == ID {
			return client
		}
	}
	return nil
}

// Get all clients for an operator
func (cc *clients) OperatorClients(name string) (clis []*Client) {
	for _, client := range cc.active {
		if client.Operator.Name == name {
			clis = append(clis, client)
		}
	}
	return
}

// RemoveClient - Remove a client struct atomically
func (cc *clients) Remove(clientID string) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	client := cc.active[clientID]
	delete(cc.active, clientID)

	if len(cc.OperatorClients(client.Operator.Name)) == 0 {
		EventBroker.Publish(Event{
			Type:   clientpb.EventType_UserLeft,
			Client: client,
		})
	}
}

// nextClientID - Get a client ID
func nextClientID() string {
	id, err := uuid.NewV4()
	if err != nil {
		coreLog.Errorf("Failed to get ID for new console client: %s", err)
		return strconv.Itoa(rand.Int())
	}
	return id.String()
}

// NewClient - Create a new client object
func NewClient(operatorName string) *Client {
	return &Client{
		ID: nextClientID(),
		Operator: &clientpb.Operator{
			Name: operatorName,
		},
		// mutex: &sync.RWMutex{},
	}
}
