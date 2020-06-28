package buildserver

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/bishopfox/sliver/client/version"
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

// GetVersion - Get the server version
func (server *BuildServer) GetVersion(ctx context.Context, _ *commonpb.Empty) (*clientpb.Version, error) {
	dirty := version.GitDirty != ""
	semVer := version.SemanticVersion()
	compiled, _ := version.Compiled()
	return &clientpb.Version{
		Major:      int32(semVer[0]),
		Minor:      int32(semVer[1]),
		Patch:      int32(semVer[2]),
		Commit:     version.GitCommit,
		Dirty:      dirty,
		CompiledAt: compiled.Unix(),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
	}, nil
}

// Register - Register a new builder
func (server *BuildServer) Register(manifest *builderpb.FactoryManifest, stream rpcpb.BuilderRPC_RegisterServer) error {
	factory := core.Factories.Add(manifest, stream)
	if factory == nil {
		buildServerLog.Error("Failed to initialize builder")
		return ErrBuilderInitializationFailure
	}
	buildServerLog.Infof("Builder registered (%d): %v", factory.ID, manifest)
	defer core.Factories.Remove(factory.ID)
	for buildTask := range factory.Builds {
		err := stream.Send(buildTask)
		if err != nil {
			buildServerLog.Errorf("Failed to send build task to builder %s", err)
			return err
		}
	}
	buildServerLog.Infof("Closing connection to builder %d", factory.ID)
	return nil
}

// Factories - List builders
func (server *BuildServer) Factories(ctx context.Context, _ *commonpb.Empty) (*builderpb.Factories, error) {
	factoryManifests := []*builderpb.FactoryManifest{}
	for _, factory := range core.Factories.List() {
		factoryManifests = append(factoryManifests, factory.Manifest)
	}
	return &builderpb.Factories{Manifests: factoryManifests}, nil
}

// Build - Build an implant using a given config
func (server *BuildServer) Build(ctx context.Context, task *builderpb.BuildTask) (*builderpb.Artifact, error) {
	factory := core.Factories.GetFactoryFor(task.ImplantConfig)
	if factory == nil {
		return nil, ErrNoBuildersForTarget
	}
	artifactChan, err := factory.Build(task)
	if err != nil {
		return nil, err
	}
	buildServerLog.Infof("Started build task %s", task.GUID)
	select {
	case artifact := <-artifactChan:
		buildServerLog.Infof("Factory produced artifact for build task %s", task.GUID)
		return artifact, nil
	case <-time.After(time.Duration(task.ImplantConfig.BuildTimeout)):
		buildServerLog.Warnf("Build task %s exceeded timeout", task.GUID)
		factory.Cancel(task.GUID)
		return nil, ErrBuildTaskTimeout
	}
}

// Built - Upload a built artifact
func (server *BuildServer) Built(ctx context.Context, artifact *builderpb.Artifact) (*commonpb.Empty, error) {
	err := core.Factories.BuiltArtifact(artifact)
	if err != nil {
		buildServerLog.Warnf("Error handling build artifact %s", err)
	}
	return &commonpb.Empty{}, err
}
