package factory

import (
	"context"
	"io"
	"io/ioutil"
	"net"
	"os"
	"runtime"

	"github.com/bishopfox/sliver/protobuf/builderpb"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/server/build/generate"
	"github.com/bishopfox/sliver/server/build/gogo"
	"github.com/bishopfox/sliver/server/log"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const (
	kb = 1024
	mb = 1024 * kb
	gb = 1024 * mb
	// FactoryClientMaxMessageSize - Max size of a factory client message
	FactoryClientMaxMessageSize = 2 * gb

	localName = "local"
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
func NewFactory() *Factory {
	return &Factory{}
}

// StartLocal - Start the factory via local connection
func (f *Factory) StartLocal(localLn *bufconn.Listener) error {
	ctxDialer := grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return localLn.Dial()
	})
	options := []grpc.DialOption{
		ctxDialer,
		grpc.WithInsecure(), // This is an in-memory listener, no need for secure transport
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(FactoryClientMaxMessageSize)),
	}
	conn, err := grpc.DialContext(context.Background(), "bufnet", options...)
	if err != nil {
		return err
	}
	f.builderRPC = rpcpb.NewBuilderRPCClient(conn)
	manifest := f.GenerateManifest(true)
	taskStream, err := f.builderRPC.Register(context.Background(), manifest)
	if err != nil {
		return err
	}
	for {
		task, err := taskStream.Recv()
		if err == io.EOF || task == nil {
			return nil
		}
		if err != nil {
			return err
		}
		go f.executeTask(task)
	}
}

func (f *Factory) executeTask(task *builderpb.BuildTask) {
	var path string
	var err error
	switch task.ImplantConfig.Format {
	case clientpb.ImplantConfig_EXECUTABLE:
		path, err = generate.SliverExecutable(task.ImplantConfig)
	case clientpb.ImplantConfig_SHARED_LIB:
		path, err = generate.SliverSharedLibrary(task.ImplantConfig)
	}
	artifact := &builderpb.Artifact{
		GUID:          task.GUID,
		ImplantConfig: task.ImplantConfig,
	}
	if err == nil {
		data, err := ioutil.ReadFile(path)
		if err == nil {
			artifact.File = &commonpb.File{Data: data}
		}
	}
	factoryLog.Infof("Build completed: %s", path)
	f.builderRPC.Built(context.Background(), artifact)
}

// GenerateManifest - Generate a manifest for the factory
func (f *Factory) GenerateManifest(isLocal bool) *builderpb.FactoryManifest {
	factoryLog.Infof("Generating manifest ...")
	name, err := os.Hostname()
	if err != nil {
		factoryLog.Warnf("Failed to determine hostname %s", err)
		name = uuid.New().String()
	}
	if isLocal {
		name = localName
	}

	return &builderpb.FactoryManifest{
		Name:     name,
		HostArch: runtime.GOARCH,
		HostOS:   runtime.GOOS,
		Targets: []*builderpb.Target{
			f.getWindowsX86Targets(),
			f.getWindowsAMD64Targets(),
			f.getLinuxX86Targets(),
			f.getLinuxAMD64Targets(),
			f.getDarwinAMD64Targets(),
		},
	}
}

func (f *Factory) getWindowsX86Targets() *builderpb.Target {
	target := &builderpb.Target{
		GOOS:   gogo.Windows,
		GOARCH: gogo.X86,
		Formats: []builderpb.Target_OutputFormat{
			builderpb.Target_EXECUTABLE,
		},
	}
	cc := generate.GetCCompiler(gogo.X86)
	if cc != "" {
		factoryLog.Infof("Found %s cc = %s", gogo.X86, cc)
		target.Formats = append(target.Formats, builderpb.Target_SHARED_LIB)
		target.Formats = append(target.Formats, builderpb.Target_SHELLCODE)
		target.Formats = append(target.Formats, builderpb.Target_SERVICE)
	}
	return target
}

func (f *Factory) getWindowsAMD64Targets() *builderpb.Target {
	target := &builderpb.Target{
		GOOS:   gogo.Windows,
		GOARCH: gogo.AMD64,
		Formats: []builderpb.Target_OutputFormat{
			builderpb.Target_EXECUTABLE,
		},
	}
	cc := generate.GetCCompiler(gogo.AMD64)
	if cc != "" {
		factoryLog.Infof("Found %s cc = %s", gogo.AMD64, cc)
		target.Formats = append(target.Formats, builderpb.Target_SHARED_LIB)
		target.Formats = append(target.Formats, builderpb.Target_SHELLCODE)
		target.Formats = append(target.Formats, builderpb.Target_SERVICE)
	}
	return target
}

func (f *Factory) getLinuxX86Targets() *builderpb.Target {
	target := &builderpb.Target{
		GOOS:   gogo.Linux,
		GOARCH: gogo.X86,
		Formats: []builderpb.Target_OutputFormat{
			builderpb.Target_EXECUTABLE,
		},
	}
	if runtime.GOOS == gogo.Linux {
		target.Formats = append(target.Formats, builderpb.Target_SHARED_LIB)
	}
	return target
}

func (f *Factory) getLinuxAMD64Targets() *builderpb.Target {
	target := &builderpb.Target{
		GOOS:   gogo.Linux,
		GOARCH: gogo.AMD64,
		Formats: []builderpb.Target_OutputFormat{
			builderpb.Target_EXECUTABLE,
		},
	}
	if runtime.GOOS == gogo.Linux {
		target.Formats = append(target.Formats, builderpb.Target_SHARED_LIB)
	}
	return target
}

func (f *Factory) getDarwinAMD64Targets() *builderpb.Target {
	target := &builderpb.Target{
		GOOS:   gogo.Darwin,
		GOARCH: gogo.AMD64,
		Formats: []builderpb.Target_OutputFormat{
			builderpb.Target_EXECUTABLE,
		},
	}
	if runtime.GOOS == gogo.Darwin {
		target.Formats = append(target.Formats, builderpb.Target_SHARED_LIB)
	}
	return target
}
