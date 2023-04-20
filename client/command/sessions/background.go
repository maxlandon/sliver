package sessions

import (
	"github.com/bishopfox/sliver/client/console"
	"github.com/spf13/cobra"
)

// BackgroundCmd - Background the active session
func BackgroundCmd(cmd *cobra.Command, args []string) {
	con := console.Client

	con.ActiveTarget.Background()
	con.PrintInfof("Background ...\n")
}
