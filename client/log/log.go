package log

import (
	"os"

	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/spin"
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

func Printf(format string, args ...interface{}) {
	// return fmt.Fprintf(console.Console.Stdout(), format, args...)
	console.Console.LogTransient(format, args)
}

func Println(args ...interface{}) {
	// return fmt.Fprintln(console.Console.Stdout(), args...)
	// console.Console.LogTransient(args...)
}

func PrintInfof(format string, args ...interface{}) {
	// return fmt.Fprintf(console.Console.Stdout(), Clearln+Info+format, args...)
	console.Console.LogTransient(Clearln+Info+format, args...)
}

func PrintSuccessf(format string, args ...interface{}) {
	// return fmt.Fprintf(console.Console.Stdout(), Clearln+Success+format, args...)
	console.Console.LogTransient(Clearln+Success+format, args...)
}

func PrintWarnf(format string, args ...interface{}) {
	// return fmt.Fprintf(console.Console.Stdout(), Clearln+"⚠️  "+Normal+format, args...)
	console.Console.LogTransient(Clearln+"⚠️  "+Normal+format, args...)
}

func PrintErrorf(format string, args ...interface{}) {
	// return fmt.Fprintf(console.Console.Stderr(), Clearln+Warn+format, args...)
	console.Console.LogTransient(Clearln+Warn+format, args...)
}

func PrintEventInfof(format string, args ...interface{}) {
	// return fmt.Fprintf(console.Console.Stdout(), Clearln+Info+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
	console.Console.LogTransient(Clearln+Info+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func PrintEventErrorf(format string, args ...interface{}) {
	// return fmt.Fprintf(console.Console.Stderr(), Clearln+Warn+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
	console.Console.LogTransient(Clearln+Warn+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func PrintEventSuccessf(format string, args ...interface{}) {
	// return fmt.Fprintf(console.Console.Stdout(), Clearln+Success+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
	console.Console.LogTransient(Clearln+Success+format+"\n"+Clearln+"\r\n"+Clearln+"\r", args...)
}

func SpinUntil(message string, ctrl chan bool) {
	go spin.Until(os.Stdout, message, ctrl)
}
