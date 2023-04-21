package info

import (
	"context"
	insecureRand "math/rand"

	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/spf13/cobra"
)

// PingCmd - Send a round trip C2 message to an implant (does not use ICMP)
func PingCmd(cmd *cobra.Command, args []string) {
	con := console.Client

	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}

	nonce := insecureRand.Intn(999999)
	log.Infof("Ping %d\n", nonce)
	pong, err := con.Rpc.Ping(context.Background(), &sliverpb.Ping{
		Nonce:   int32(nonce),
		Request: con.ActiveTarget.Request(cmd),
	})
	if err != nil {
		log.Errorf("%s\n", err)
	} else {
		log.Infof("Pong %d\n", pong.Nonce)
	}
}
