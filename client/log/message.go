package log

import (
	"fmt"
	"os"

	"github.com/bishopfox/sliver/client/spin"
	"github.com/evilsocket/islazy/tui"
)

const (
	// ANSI Colors
	normal    = "\033[0m"
	black     = "\033[30m"
	red       = "\033[31m"
	green     = "\033[32m"
	orange    = "\033[33m"
	blue      = "\033[34m"
	purple    = "\033[35m"
	cyan      = "\033[36m"
	gray      = "\033[37m"
	bold      = "\033[1m"
	clearln   = "\r\x1b[2K"
	upN       = "\033[%dA"
	downN     = "\033[%dB"
	underline = "\033[4m"

	// Info - Display colorful information
	// Info = bold + cyan + "[*] " + normal
	// Warn - Warn a user
	// Warn = bold + red + "[!] " + normal
	// Debug - Display debug information
	// Debug = bold + purple + "[-] " + normal
	// Woot - Display success
	Woot = bold + green + "[$] " + normal

	// ensure that nothing remains when we refresh the prompt
	seqClearScreenBelow = "\x1b[0J"
)

var (
	debug   = fmt.Sprintf("%s[-]%s ", tui.DIM, tui.RESET)    // Info - All normal messages
	info    = fmt.Sprintf("%s[-]%s ", tui.BLUE, tui.RESET)   // Info - All normal messages
	warn    = fmt.Sprintf("%s[!]%s ", tui.YELLOW, tui.RESET) // Warn - Errors in parameters, notifiable events in modules/sessions
	errorf  = fmt.Sprintf("%s[!]%s ", tui.RED, tui.RESET)    // Error - Error in commands, filters, modules and implants.
	success = fmt.Sprintf("%s[*]%s ", tui.GREEN, tui.RESET)  // Success - Success events

	// Infof   = fmt.Sprintf("%s[-] ", tui.BLUE)   // Infof - formatted
	// Warnf   = fmt.Sprintf("%s[!] ", tui.YELLOW) // Warnf - formatted
	// Errorf  = fmt.Sprintf("%s[!] ", tui.RED)    // Errorf - formatted
	// Sucessf = fmt.Sprintf("%s[*] ", tui.GREEN) // Sucessf - formatted

	RPCError     = fmt.Sprintf("%s[RPC Error]%s ", tui.RED, tui.RESET)     // RPCError - Errors from the server
	CommandError = fmt.Sprintf("%s[Command Error]%s ", tui.RED, tui.RESET) // CommandError - Command input error
	ParserError  = fmt.Sprintf("%s[Parser Error]%s ", tui.RED, tui.RESET)  // ParserError - Failed to parse some tokens in the input
	DBError      = fmt.Sprintf("%s[DB Error]%s ", tui.RED, tui.RESET)      // DBError - Data Service error
)

func Printf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(format, args...)
}

func Println(args ...interface{}) (n int, err error) {
	return fmt.Println(args...)
}

func Debugf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(debug+format, args...)
}

func Infof(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(info+format, args...)
}

func Warnf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(warn+format, args...)
}

func Errorf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(errorf+format, args...)
}

func Successf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(success+format, args...)
}

func SpinUntil(message string, ctrl chan bool) {
	go spin.Until(os.Stdout, info+message, ctrl)
}

// Additional Message Types ------------------------------------------------

func CommandErrorf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(CommandError+format, args...)
}

func RPCErrorf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(RPCError+format, args...)
}
func ParserErrorf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(ParserError+format, args...)
}

func DBErrorf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(DBError+format, args...)
}
