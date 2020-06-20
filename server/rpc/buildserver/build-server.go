package buildserver

import (
	"context"

	"github.com/bishopfox/sliver/protobuf/builderpb"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

// BuildServer - gRPC server
type BuildServer struct{}

// NewBuildServer - Create new server instance
func NewBuildServer() *BuildServer {
	return &BuildServer{}
}

// Register - Register a new builder
func (b *BuildServer) Register(manifest *builderpb.BuilderManifest, stream rpcpb.BuilderRPC_RegisterServer) error {

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
