package buildserver

import (
	"context"
	"errors"

	"github.com/bishopfox/sliver/protobuf/builderpb"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/server/core"
)

// BuildServer - gRPC server
type BuildServer struct{}

var (
	// ErrBuilderInitializationFailure - Returned if we failed to create the Builder object
	ErrBuilderInitializationFailure = errors.New("Failed to add builder to core")
)

// NewBuildServer - Create new server instance
func NewBuildServer() *BuildServer {
	return &BuildServer{}
}

// Register - Register a new builder
func (b *BuildServer) Register(manifest *builderpb.BuilderManifest, stream rpcpb.BuilderRPC_RegisterServer) error {
	builder := core.Builders.Add(manifest, stream)
	if builder == nil {
		return ErrBuilderInitializationFailure
	}
	defer core.Builders.Remove(builder.ID)
	for config := range builder.Builds {
		err := stream.Send(config)
		if err != nil {
			return err
		}
	}
	return nil
}

// Builders - List builders
func (b *BuildServer) Builders(ctx context.Context, _ *commonpb.Empty) (*builderpb.Builders, error) {

	return nil, nil
}

// Build - Build an implant using a given config
func (b *BuildServer) Build(ctx context.Context, config *clientpb.ImplantConfig) (*builderpb.Artifact, error) {

	return nil, nil
}

// Built - Upload a built artifact
func (b *BuildServer) Built(ctx context.Context, artifact *builderpb.Artifact) (*commonpb.Empty, error) {

	return nil, nil
}
