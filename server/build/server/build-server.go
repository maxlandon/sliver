package buildserver

import (
	"context"
	"errors"
	"time"

	"github.com/bishopfox/sliver/protobuf/builderpb"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/log"
)

// BuildServer - gRPC server
type BuildServer struct{}

var (
	buildServerLog = log.NamedLogger("build", "server")

	// ErrBuilderInitializationFailure - Returned if we failed to create the Builder object
	ErrBuilderInitializationFailure = errors.New("Failed to register builder with core")
	// ErrNoBuildersForTarget - Returned if we couldn't find a builder that can compile for a target
	ErrNoBuildersForTarget = errors.New("No builders for target")

	// ErrBuildTaskTimeout - Returned when the build times out
	ErrBuildTaskTimeout = errors.New("Build task timeout")
)

// NewBuildServer - Create new server instance
func NewBuildServer() *BuildServer {
	return &BuildServer{}
}

// Register - Register a new builder
func (b *BuildServer) Register(manifest *builderpb.BuilderManifest, stream rpcpb.BuilderRPC_RegisterServer) error {
	builder := core.Builders.Add(manifest, stream)
	if builder == nil {
		buildServerLog.Error("Failed to initialize builder")
		return ErrBuilderInitializationFailure
	}
	buildServerLog.Infof("Builder registered (%d): %v", builder.ID, manifest)
	defer core.Builders.Remove(builder.ID)
	for buildTask := range builder.Builds {
		err := stream.Send(buildTask)
		if err != nil {
			buildServerLog.Errorf("Failed to send build task to builder %s", err)
			return err
		}
	}
	buildServerLog.Infof("Closing connection to builder %d", builder.ID)
	return nil
}

// Builders - List builders
func (b *BuildServer) Builders(ctx context.Context, _ *commonpb.Empty) (*builderpb.Builders, error) {
	builders := []*builderpb.BuilderManifest{}
	for _, builder := range core.Builders.List() {
		builders = append(builders, builder.Manifest)
	}
	return &builderpb.Builders{Builders: builders}, nil
}

// Build - Build an implant using a given config
func (b *BuildServer) Build(ctx context.Context, config *clientpb.ImplantConfig) (*builderpb.Artifact, error) {
	builder := core.Builders.GetBuilderFor(config)
	if builder == nil {
		return nil, ErrNoBuildersForTarget
	}
	artifactChan, guid, err := builder.Build(config)
	if err != nil {
		return nil, err
	}
	buildServerLog.Infof("Started build task %s", guid)
	select {
	case artifact := <-artifactChan:
		buildServerLog.Infof("Builder returned artifact for build task %s", guid)
		return artifact, nil
	case <-time.After(time.Duration(config.BuildTimeout)):
		buildServerLog.Warnf("Build task %s exceeded timeout", guid)
		builder.Cancel(guid)
		return nil, ErrBuildTaskTimeout
	}
}

// Built - Upload a built artifact
func (b *BuildServer) Built(ctx context.Context, artifact *builderpb.Artifact) (*commonpb.Empty, error) {
	err := core.Builders.BuiltArtifact(artifact)
	if err != nil {
		buildServerLog.Warnf("Error handling build artifact %s", err)
	}
	return &commonpb.Empty{}, err
}
