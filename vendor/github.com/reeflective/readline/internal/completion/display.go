package completion

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/reeflective/readline/internal/color"
	"github.com/reeflective/readline/internal/term"
)

// Display prints the current completion list to the screen,
// respecting the current display and completion settings.
func (e *Engine) Display() {
	e.usedY = 0

	// The completion engine might be inactive but still having
	// a non-empty list of completions. This is on purpose, as
	// sometimes it's better to keep completions printed for a
	// little more time. The engine itself is responsible for
	// deleting those lists when it deems them useless.
	if e.Matches() == 0 {
		return
	}

	// The final completions string to print.
	var completions string

	for _, group := range e.groups {
		completions += group.writeComps(e)
	}

	// Crop the completions so that it fits within our terminal
	completions, e.usedY = e.cropCompletions(completions)

	if completions != "" {
		fmt.Print(term.ClearScreenBelow)
		fmt.Print(completions)
	}
}

// Coordinates returns the number of terminal rows used
// when displaying the completions with Display().
func (e *Engine) Coordinates() int {
	return e.usedY
}

// cropCompletions - When the user cycles through a completion list longer
// than the console MaxTabCompleterRows value, we crop the completions string
// so that "global" cycling (across all groups) is printed correctly.
func (e *Engine) cropCompletions(comps string) (cropped string, usedY int) {
	maxRows := e.getCompletionMaxRows()

	// Get the current absolute candidate position
	absPos := e.getAbsPos()

	// Scan the completions for cutting them at newlines
	scanner := bufio.NewScanner(strings.NewReader(comps))

	// If absPos < MaxTabCompleterRows, cut below MaxTabCompleterRows and return
	if absPos < maxRows {
		return e.cutCompletionsBelow(scanner, maxRows)
	}

	// If absolute > MaxTabCompleterRows, cut above and below and return
	//      -> This includes de facto when we tabCompletionReverse
	if absPos >= maxRows {
		return e.cutCompletionsAboveBelow(scanner, maxRows, absPos)
	}

	return
}

func (e *Engine) cutCompletionsBelow(scanner *bufio.Scanner, maxRows int) (string, int) {
	var count int
	var cropped string

	for scanner.Scan() {
		line := scanner.Text()
		if count < maxRows {
			cropped += line + "\n"
			count++
		} else {
			break
		}
	}

	cropped = e.excessCompletionsHint(cropped, maxRows, count)

	return cropped, count
}

func (e *Engine) cutCompletionsAboveBelow(scanner *bufio.Scanner, maxRows, absPos int) (string, int) {
	cutAbove := absPos - maxRows + 1

	var cropped string
	var count int

	for scanner.Scan() {
		line := scanner.Text()

		if count <= cutAbove {
			count++

			continue
		}

		if count > cutAbove && count <= absPos {
			cropped += line + "\n"
			count++
		} else {
			break
		}
	}

	cropped = e.excessCompletionsHint(cropped, maxRows, maxRows+cutAbove)
	count--

	return cropped, count - cutAbove
}

func (e *Engine) excessCompletionsHint(cropped string, maxRows, offset int) string {
	_, used := e.completionCount()
	remain := used - offset

	if remain <= 0 || offset < maxRows {
		return cropped
	}

	hint := fmt.Sprintf(color.Dim+color.FgYellow+" %d more completion rows... (scroll down to show)"+color.Reset, remain)

	hinted := cropped + hint

	return hinted
}

// returns either the max number of completion rows configured
// or a reasonable amount of rows so as not to bother the user.
func (e *Engine) getCompletionMaxRows() (maxRows int) {
	_, termHeight, _ := term.GetSize(int(os.Stdin.Fd()))

	// Pause the key reading routine and query the terminal
	_, cposY := e.keys.GetCursorPos()
	if cposY == -1 {
		if termHeight != -1 {
			return termHeight / maxRowsRatio
		}

		return maxRows
	}

	spaceBelow := (termHeight - cposY) - 1

	// Only return the space below if it's reasonably large.
	if spaceBelow >= minRowsSpaceBelow {
		return spaceBelow
	}

	// Otherwise return half the terminal.
	return termHeight / maxRowsRatio
}
