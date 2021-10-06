package rpc

import (
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/log"
)

var (
	rpcEventsLog = log.NamedLogger("rpc", "events")
)

// Events - Stream events to client
func (s *Server) Events(req *commonpb.Request, stream rpcpb.SliverRPC_EventsServer) error {
	client := core.Clients.Get(req.ClientID)
	events := core.EventBroker.Subscribe()

	defer func() {
		rpcEventsLog.Infof("%d client disconnected (user: %s)", client.ID, client.Operator.Name)
		core.EventBroker.Unsubscribe(events)
		core.Clients.Remove(client.ID)
	}()

	// This client ID is going to be pushed in the events.
	// Only this very client will receive this confirmation.
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case event := <-events:
			pbEvent := &clientpb.Event{
				EventType: event.EventType,
				Data:      event.Data,
			}

			if event.Job != nil {
				pbEvent.Job = event.Job.ToProtobuf()
			}
			if event.Client != nil {
				pbEvent.Client = event.Client.ToProtobuf()
			}
			if event.Session != nil {
				pbEvent.Session = event.Session.ToProtobuf()
			}
			if event.Err != nil {
				pbEvent.Err = event.Err.Error()
			}

			err := stream.Send(pbEvent)
			if err != nil {
				rpcEventsLog.Warnf(err.Error())
				return err
			}
		}
	}
}
