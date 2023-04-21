package generate

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// GenerateInfoCmd - Display information about the Sliver server's compiler configuration
func GenerateInfoCmd(cmd *cobra.Command, args []string) {
	con := console.Client

	compiler, err := con.Rpc.GetCompiler(context.Background(), &commonpb.Empty{})
	if err != nil {
		log.Errorf("Failed to get compiler information: %s\n", err)
		return
	}
	log.Printf("%sServer:%s %s/%s\n", console.Bold, console.Normal, compiler.GOOS, compiler.GOARCH)
	con.Println()
	log.Printf("%sCross Compilers%s\n", console.Bold, console.Normal)
	for _, cc := range compiler.CrossCompilers {
		log.Printf("%s/%s - %s\n", cc.TargetGOOS, cc.TargetGOARCH, cc.GetCCPath())
	}
	con.Println()
	log.Printf("%sSupported Targets%s\n", console.Bold, console.Normal)
	for _, target := range compiler.Targets {
		log.Printf("%s/%s - %s\n", target.GOOS, target.GOARCH, nameOfOutputFormat(target.Format))
	}
	con.Println()
	log.Printf("%sDefault Builds Only%s\n", console.Bold, console.Normal)
	for _, target := range compiler.UnsupportedTargets {
		log.Printf("%s/%s - %s\n", target.GOOS, target.GOARCH, nameOfOutputFormat(target.Format))
	}
}
