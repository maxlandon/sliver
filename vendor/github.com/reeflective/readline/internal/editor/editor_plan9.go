//go:build plan9
// +build plan9

package editor

import "errors"

// EditBuffer is currently not supported on Plan9 operating systems.
func EditBuffer(buf []rune, filename, filetype string) ([]rune, error) {
	return buf, errors.New("Not currently supported on Plan 9")
}
