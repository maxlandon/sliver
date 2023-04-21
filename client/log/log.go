package log

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/spin"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

const (
	// ANSI Colors
	Normal    = "\033[0m"
	Black     = "\033[30m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Orange    = "\033[33m"
	Blue      = "\033[34m"
	Purple    = "\033[35m"
	Cyan      = "\033[36m"
	Gray      = "\033[37m"
	Bold      = "\033[1m"
	Clearln   = "\r\x1b[2K"
	UpN       = "\033[%dA"
	DownN     = "\033[%dB"
	Underline = "\033[4m"

	// Info - Display colorful information
	Info = Bold + Cyan + "[*] " + Normal
	// Warn - Warn a user
	Warn = Bold + Red + "[!] " + Normal
	// Debug - Display debug information
	Debug = Bold + Purple + "[-] " + Normal
	// Woot - Display success
	Woot = Bold + Green + "[$] " + Normal
	// Success - Diplay success
	Success = Bold + Green + "[+] " + Normal
)

var print func(format string, args ...any) (n int, err error)

// Init is used to pass the console specialized print function,
// It's generally a transient logging utility, but can be fmt.Print.
func Init(printf func(format string, args ...any) (n int, err error)) {
	if printf != nil {
		print = printf
	} else {
		print = fmt.Printf
	}
}

func Printf(format string, args ...any) (n int, err error) {
	return print(format, args...)
}

func Println(args ...any) (n int, err error) {
	format := strings.Repeat("%s", len(args))
	return print(format+"\n", args...)
}

func Infof(format string, args ...any) (n int, err error) {
	return print(Clearln+Info+format, args...)
}

func Successf(format string, args ...any) (n int, err error) {
	return print(Clearln+Success+format, args...)
}

func Warnf(format string, args ...any) (n int, err error) {
	return print(Clearln+"⚠️  "+Normal+format, args...)
}

func Errorf(format string, args ...any) (n int, err error) {
	return print(Clearln+Warn+format, args...)
}

func EventInfof(format string, args ...any) (n int, err error) {
	return print(Clearln+Info+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func EventErrorf(format string, args ...any) (n int, err error) {
	return print(Clearln+Warn+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func EventSuccessf(format string, args ...any) (n int, err error) {
	return print(Clearln+Success+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func SpinUntil(message string, ctrl chan bool) {
	go spin.Until(os.Stdout, message, ctrl)
}

// AsyncResponse - Print the generic async response information
func AsyncResponse(resp *commonpb.Response) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	beacon, err := console.Client.Rpc.GetBeacon(ctx, &clientpb.Beacon{ID: resp.BeaconID})
	if err != nil {
		fmt.Printf(Warn+"%s\n", err)
		return
	}
	Infof("Tasked beacon %s (%s)\n", beacon.Name, strings.Split(resp.TaskID, "-")[0])
}
