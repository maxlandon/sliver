package log

import (
	"fmt"
	"os"

	"github.com/bishopfox/sliver/client/spin"
	"github.com/evilsocket/islazy/tui"
	"google.golang.org/grpc/status"
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
	debug   = fmt.Sprintf("%s[-]%s ", tui.DIM, tui.RESET)    // debug - All debug messages
	info    = fmt.Sprintf("%s[-]%s ", tui.BLUE, tui.RESET)   // info - All normal messages
	warn    = fmt.Sprintf("%s[!]%s ", tui.YELLOW, tui.RESET) // warn - Errors in parameters, notifiable events in modules/sessions
	errror  = fmt.Sprintf("%s[!]%s ", tui.RED, tui.RESET)    // errror - Error in commands, filters, modules and implants.
	success = fmt.Sprintf("%s[*]%s ", tui.GREEN, tui.RESET)  // success - Success events

	infof   = fmt.Sprintf("%s[-] ", tui.BLUE)   // infof - formatted
	warnf   = fmt.Sprintf("%s[!] ", tui.YELLOW) // warnf - formatted
	errorf  = fmt.Sprintf("%s[!] ", tui.RED)    // errorf - formatted
	sucessf = fmt.Sprintf("%s[*] ", tui.GREEN)  // sucessf - formatted

	rpcError     = fmt.Sprintf("%s[RPC Error]%s ", tui.RED, tui.RESET)     // RPCError - Errors from the server
	commandError = fmt.Sprintf("%s[Command Error]%s ", tui.RED, tui.RESET) // CommandError - Command input error
	parserError  = fmt.Sprintf("%s[Parser Error]%s ", tui.RED, tui.RESET)  // ParserError - Failed to parse some tokens in the input
	dbError      = fmt.Sprintf("%s[DB Error]%s ", tui.RED, tui.RESET)      // DBError - Data Service error
)

// Error Log Messages -----------------------------------------------------
// These functions format log status messages and wrap them into an error,
// that they return for it to be handled down the call chain.

// Error - Wraps an error type into another error type (with formatting) and returns it.
// In case the error has been created by a gRPC component, we unwrap its message before.
func Error(errIn error) (err error) {
	st := status.Convert(errIn)
	return fmt.Errorf(errror + st.Message())
}

// Errorf - Wraps an error message into an error type and returns it to be handled
// further down the call chain. Useful when you want to create your own error.
func Errorf(format string, args ...interface{}) (err error) {
	return fmt.Errorf(errror+format, args...)
}

// Direct Log Messages -----------------------------------------------------
// These functions only print status log messages to the console,
// and do not return errors to be handled down the call chain.

// Printf - Print a generic message
func Printf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(format, args...)
}

// Debugf - Notify a debug message.
func Debugf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(debug+format, args...)
}

// Infof - Notify an info message.
func Infof(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(info+format, args...)
}

// Warnf - Notify a warning message.
func Warnf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(warn+format, args...)
}

// Errorf - Notify an error message without returning the error itself.
// func Errorf(format string, args ...interface{}) (n int, err error) {
//         return fmt.Printf(errror+format, args...)
// }

// Successf - Notify sucess message.
func Successf(format string, args ...interface{}) (n int, err error) {
	return fmt.Printf(success+format, args...)
}

// SpinUntil - Start a spinner with an embedded message.
func SpinUntil(message string, ctrl chan bool) {
	go spin.Until(os.Stdout, info+message, ctrl)
}

// Additional Message Types ------------------------------------------------
// These messages also format error messages and wrap them into an error type,
// that they return to the caller. These messages are more specific on their source.

// CommandErrorf - Notify an error message related to a command implementation failure.
func CommandErrorf(format string, args ...interface{}) (err error) {
	return fmt.Errorf(commandError+format+"\n", args...)
}

// RPCErrorf - Notify an error message related to a RPC call (internal) failure
func RPCErrorf(format string, args ...interface{}) (err error) {
	return fmt.Errorf(rpcError+format+"\n", args...)
}

// ParserErrorf - Notify an error message related to a command parser failure.
func ParserErrorf(format string, args ...interface{}) (err error) {
	return fmt.Errorf(parserError+format+"\n", args...)
}

// DBErrorf - Notify an error message related to a database operation failure.
func DBErrorf(format string, args ...interface{}) (err error) {
	return fmt.Errorf(dbError+format+"\n", args...)
}

// Error processing and printing -------------------------------------------

// PrintError - This function unwraps an error type, which might or might not
// be originating from gRPC, and prints it to the screen with a newline added.
func PrintError(err error) {
	errStatus := status.Convert(err)
	fmt.Printf(errStatus.Message() + "\n")
}
