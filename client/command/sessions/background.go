package sessions

import (
	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/log"
	"github.com/spf13/cobra"
)

// BackgroundCmd - Background the active session
func BackgroundCmd(cmd *cobra.Command, args []string) {
	con := console.Client

	con.ActiveTarget.Background()
	log.Infof("Background ...\n")
}
