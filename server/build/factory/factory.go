package factory

import (
	"context"
	"io"
	"net"

	"github.com/bishopfox/sliver/protobuf/builderpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/server/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

var (
	factoryLog = log.NamedLogger("build", "factory")
)

// Factory - A client that can build artifacts
type Factory struct {
	Manifest   builderpb.FactoryManifest
	builderRPC rpcpb.BuilderRPCClient
}

// NewFactory - Initialize a new build factory
func NewFactory(builderRPC rpcpb.BuilderRPCClient) *BuildFactory {
	return &BuildFactory{builderRPC: builderRPC}
}

// StartLocalFactory - Start the factory via local connection
func (f *Factory) StartLocalFactory(localLn *bufconn.Listener) error {
	ctxDialer := grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return localLn.Dial()
	})
	buildServerOptions := []grpc.DialOption{
		ctxDialer,
		grpc.WithInsecure(), // This is an in-memory listener, no need for secure transport
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(ServerMaxMessageSize)),
	}
	conn, err := grpc.DialContext(context.Background(), "bufnet", buildServerOptions...)
	if err != nil {
		return err
	}
	builderRPC := rpcpb.NewBuilderRPCClient(conn)
	manifest, err := f.GenerateManifest()
	if err != nil {
		return err
	}
	taskStream, err := builderRPC.Register(context.Background(), manifest)
	if err != nil {
		return err
	}
	for {
		task, err := taskStream.Recv()
		if err == io.EOF || event == nil {
			return
		}
		factoryLog.Infof("Received build task %v", task)
	}
}

// GenerateManifest - Generate a manifest for the factory
func (f *Factory) GenerateManifest() (*builderpb.FactoryManifest, error) {
	return nil, nil
}
