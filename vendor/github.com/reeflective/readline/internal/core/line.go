package core

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/reeflective/readline/inputrc"
	"github.com/reeflective/readline/internal/color"
	"github.com/reeflective/readline/internal/strutil"
	"github.com/reeflective/readline/internal/term"
)

// Tokenizer is a method used by a (line) type to split itself according to
// different rules (split between spaces, punctuation, brackets, quotes, etc.).
type Tokenizer func(cursorPos int) (split []string, index int, newPos int)

// Line is an input line buffer.
// Contains methods to search and modify its contents,
// split itself with tokenizers, and displaying itself.
type Line []rune

// Set replaces the line contents altogether with a new slice of characters.
func (l *Line) Set(chars ...rune) {
	*l = chars
}

// Insert inserts one or more runes at the given position.
// If the position is either negative or greater than the
// length of the line, nothing is inserted.
func (l *Line) Insert(pos int, chars ...rune) {
	for {
		// I don't really understand why `0` is creaping in at the
		// end of the array but it only happens with unicode characters.
		if len(chars) > 1 && chars[len(chars)-1] == 0 {
			chars = chars[:len(chars)-1]
			continue
		}

		break
	}

	// Invalid position cancels the insertion
	if pos < 0 || pos > l.Len() {
		return
	}

	switch {
	case l.Len() == 0:
		*l = chars
	case pos < l.Len():
		forward := string((*l)[pos:])
		cut := string(append((*l)[:pos], chars...))
		cut += forward
		*l = []rune(cut)
	case pos == l.Len():
		*l = append(*l, chars...)
	}
}

// InsertAt inserts one or more runes into the line, between the specified
// begin and end position, effectively deleting everything in between those.
// If either or these positions is equal to -1, the selection content
// is inserted at the other position. If both are -1, nothing is done.
func (l *Line) InsertBetween(bpos, epos int, chars ...rune) {
	bpos, epos, valid := l.checkRange(bpos, epos)
	if !valid {
		return
	}

	switch {
	case epos == -1:
		l.Insert(bpos, chars...)
	case epos == l.Len():
		cut := string((*l)[:bpos]) + string(chars)
		*l = []rune(cut)
	default:
		forward := string((*l)[epos:])
		cut := string(append((*l)[:bpos], chars...))
		cut += forward
		*l = []rune(cut)
	}
}

// Cut deletes a slice of runes between a beginning and end position on the line.
// If the begin/end pos is negative/greater than the line, all runes located on
// valid indexes in the given range are removed.
func (l *Line) Cut(bpos, epos int) {
	bpos, epos, valid := l.checkRange(bpos, epos)
	if !valid {
		return
	}

	switch epos {
	case -1:
		cut := string((*l)[:bpos])
		*l = []rune(cut)
	default:
		forward := string((*l)[epos:])
		cut := string((*l)[:bpos])
		cut += forward
		*l = []rune(cut)
	}
}

// CutRune deletes a rune at the given position in the line.
// If the position is out of bounds, nothing is deleted.
func (l *Line) CutRune(pos int) {
	if pos < 0 || pos > l.Len() || l.Len() == 0 {
		return
	}

	switch {
	case pos == 0:
		*l = (*l)[1:]
	case pos == l.Len():
		*l = (*l)[:pos-1]
	default:
		forward := string((*l)[pos+1:])
		cut := string((*l)[:pos])
		cut += forward
		*l = []rune(cut)
	}
}

// Len returns the length of the line.
func (l *Line) Len() int {
	return utf8.RuneCountInString(string(*l))
}

// SelectWord returns the full non-blank word around the specified position.
func (l *Line) SelectWord(pos int) (bpos, epos int) {
	pos, valid := l.checkPos(pos)
	if !valid {
		return
	}

	if pos == l.Len() {
		pos--
	}

	pattern := "[0-9a-zA-Z_]"
	bpos, epos = pos, pos

	if match, _ := regexp.MatchString(pattern, string((*l)[pos])); !match {
		pattern = "[^0-9a-zA-Z_ ]"
	}

	// To first space found backward
	for ; bpos >= 0; bpos-- {
		if match, _ := regexp.MatchString(pattern, string((*l)[bpos])); !match {
			break
		}
	}

	// And to first space found forward
	for ; epos < l.Len(); epos++ {
		if match, _ := regexp.MatchString(pattern, string((*l)[epos])); !match {
			break
		}
	}

	bpos++

	// Ending position must be greater than 0
	if epos > 0 {
		epos--
	}

	return bpos, epos
}

// SelectBlankWord returns the full bigword around the specified position.
func (l *Line) SelectBlankWord(pos int) (bpos, epos int) {
	pos, valid := l.checkPos(pos)
	if !valid {
		return
	}

	if pos == l.Len() {
		pos--
	}

	pattern := `[^\s\\]`
	bpos, epos = pos, pos

	if match, _ := regexp.MatchString(pattern, string((*l)[pos])); !match {
		pattern = `[^\s\\ ]`
	}

	// To first space found backward
	for ; bpos >= 0; bpos-- {
		if match, _ := regexp.MatchString(pattern, string((*l)[bpos])); !match {
			break
		}
	}

	// And to first space found forward
	for ; epos < l.Len(); epos++ {
		if match, _ := regexp.MatchString(pattern, string((*l)[epos])); !match {
			break
		}
	}

	bpos++

	// Ending position must be greater than 0
	if epos > 0 {
		epos--
	}

	return bpos, epos
}

// Find returns the index position of a target rune, or -1 if not found.
func (l *Line) Find(char rune, pos int, forward bool) int {
	for {
		if forward {
			pos++
			if pos > l.Len()-1 {
				break
			}
		} else {
			pos--
			if pos < 0 {
				pos++
				break
			}
		}

		// Check positions
		if pos < 0 {
			pos = 0
		} else if pos > l.Len()-1 {
			pos = l.Len() - 1
		}

		// Check if character matches
		if (*l)[pos] == char {
			return pos
		}
	}

	// The rune was not found.
	return -1
}

// FindSurround returns the beginning and end positions of an enclosing rune (either
// matching signs -brackets- or the rune itself -quotes/letters-) and the enclosing chars.
func (l *Line) FindSurround(char rune, pos int) (bpos, epos int, bchar, echar rune) {
	bchar, echar = strutil.MatchSurround(char)

	bpos = l.Find(bchar, pos+1, false)
	epos = l.Find(echar, pos-1, true)

	if bpos == epos {
		pos++
		epos = l.Find(echar, pos, true)

		if epos == -1 {
			pos--
			epos = l.Find(echar, pos, false)

			if epos != -1 {
				bpos, epos = epos, bpos
			}
		}
	}

	return
}

// SurroundQuotes returns the index positions of enclosing quotes around the given cursor
// position, provided that these quotes are really enclosing the inner selection (that is,
// that each of those quotes is not paired with another, outer quote).
// bpos or epos can be -1 if no quotes have been forward/backward found.
func (l *Line) SurroundQuotes(single bool, pos int) (bpos, epos int) {
	var bchar, echar rune

	if single {
		bchar, echar = '\'', '\''
	} else {
		bchar, echar = '"', '"'
	}

	// How many occurrences before and after cursor.
	var before, after int

	bpos = l.Find(bchar, pos+1, false)
	epos = l.Find(echar, pos, true)

	next, prev := epos, bpos

	// Recursively search for occurrences, forward and backward.
	for {
		if prev != -1 {
			before++
		}

		if next != -1 {
			after++
		}

		// If one of the searches failed, we're done.
		if prev == -1 || next == -1 {
			break
		}

		// Or we use a new forward/backward reference pos.
		prev = l.Find(bchar, prev, false)
		next = l.Find(echar, next, true)
	}

	// If there is an equal number of signs (like quotes) on each side,
	// that means we are not pointing at a word/phrase within quotes.
	if before%2 == 0 && after%2 == 0 {
		return -1, -1
	}

	// Or we possibly are (but not mandatorily: bpos/epos can be -1)
	return
}

// Forward returns the offset to the beginning of the next
// (forward) token determined by the tokenizer function.
func (l *Line) Forward(tokenizer Tokenizer, pos int) (adjust int) {
	split, index, pos := tokenizer(pos)

	switch {
	case len(split) == 0:
		return
	case index+1 == len(split):
		adjust = l.Len() - pos
	default:
		adjust = len(split[index]) - pos
	}

	return
}

// ForwardEnd returns the offset to the end of the next
// (forward) token determined by the tokenizer function.
func (l *Line) ForwardEnd(tokenizer Tokenizer, pos int) (adjust int) {
	split, index, pos := tokenizer(pos)
	if len(split) == 0 {
		return
	}

	word := strutil.TrimWhiteSpaceRight(split[index])

	switch {
	case len(split) == 0:
		return
	case index == len(split)-1 && pos >= len(word)-1:
		return
	case pos >= len(word)-1:
		word = strutil.TrimWhiteSpaceRight(split[index+1])
		adjust = len(split[index]) - pos
		adjust += len(word) - 1
	default:
		adjust = len(word) - pos - 1
	}

	return
}

// Backward returns the offset to the beginning position of the previous
// (backward) token determined by the tokenizer function.
func (l *Line) Backward(tokenizer Tokenizer, pos int) (adjust int) {
	split, index, pos := tokenizer(pos)

	switch {
	case len(split) == 0:
		return
	case index == 0 && pos == 0:
		return
	case pos == 0:
		adjust = len(split[index-1])
	default:
		adjust = pos
	}

	return adjust * -1
}

// Tokenize splits the line on each word, that is, split on every punctuation or space.
func (l *Line) Tokenize(cpos int) ([]string, int, int) {
	cpos, valid := l.checkPos(cpos)
	if !valid {
		return nil, 0, 0
	}

	line := *l

	if len(line) == 0 {
		return nil, 0, 0
	}

	var index, pos int
	var punc bool

	split := make([]string, 1)

	for i, char := range line {
		switch {
		case strutil.IsPunctuation(char):
			if i > 0 && line[i-1] != char {
				split = append(split, "")
			}

			split[len(split)-1] += string(char)
			punc = true

		case char == ' ' || char == '\t':
			split[len(split)-1] += string(char)
			punc = true

		case char == '\n':
			// Newlines are a word of their own only
			// when the last rune of the previous word
			// is one as well.
			if i > 0 && line[i-1] == char {
				split = append(split, "")
			}

			split[len(split)-1] += string(char)
			punc = true

		default:
			if punc {
				split = append(split, "")
			}

			split[len(split)-1] += string(char)
			punc = false
		}

		// Not caught when we are appending to the end
		// of the line, where rl.pos = linePos + 1, so...
		if i == cpos {
			index = len(split) - 1
			pos = len(split[index]) - 1
		}
	}

	// ... so we ajust here for this case.
	if cpos == len(line) {
		index = len(split) - 1
		pos = len(split[index])
	}

	return split, index, pos
}

// Tokenize splits the line on each WORD (blank word), that is, split on every space.
func (l *Line) TokenizeSpace(cpos int) ([]string, int, int) {
	cpos, valid := l.checkPos(cpos)
	if !valid {
		return nil, 0, 0
	}

	line := *l

	if len(line) == 0 {
		return nil, 0, 0
	}

	var index, pos int
	split := make([]string, 1)

	for i, char := range line {
		switch char {
		case ' ', '\t':
			split[len(split)-1] += string(char)

		case '\n':
			// Newlines are a word of their own only
			// when the last rune of the previous word
			// is one as well.
			if i > 0 && line[i-1] == char {
				split = append(split, "")
			}

			split[len(split)-1] += string(char)

		default:
			if i > 0 && (line[i-1] == ' ' || line[i-1] == '\t') {
				split = append(split, "")
			}

			split[len(split)-1] += string(char)
		}

		// Not caught when we are appending to the end
		// of the line, where rl.pos = linePos + 1, so...
		if i == cpos {
			index = len(split) - 1
			pos = len(split[index]) - 1
		}
	}

	// ... so we ajust here for this case.
	if cpos == len(line) {
		index = len(split) - 1
		pos = len(split[index])
	}

	return split, index, pos
}

// TokenizeBlock splits the line into arguments delimited either by
// brackets, braces and parenthesis, and/or single and double quotes.
func (l *Line) TokenizeBlock(cpos int) ([]string, int, int) {
	cpos, valid := l.checkPos(cpos)
	if !valid {
		return nil, 0, 0
	}

	line := *l

	var (
		bpos, epos     rune
		split          []string
		count          int
		pos            = make(map[int]int)
		match          int
		single, double bool
	)

	switch line[cpos] {
	case '(', ')', '{', '[', '}', ']':
		bpos, epos = strutil.MatchSurround(line[cpos])

	default:
		return nil, 0, 0
	}

	for i := range line {
		switch line[i] {
		case '\'':
			if !single {
				double = !double
			}

		case '"':
			if !double {
				single = !single
			}

		case bpos:
			if !single && !double {
				count++

				pos[count] = i

				if i == cpos {
					match = count
					split = []string{string(line[:i-1])}
				}
			} else if i == cpos {
				return nil, 0, 0
			}

		case epos:
			if !single && !double {
				if match == count {
					split = append(split, string(line[pos[count]:i]))
					return split, 1, 0
				}

				if i == cpos {
					split = []string{
						string(line[:pos[count]-1]),
						string(line[pos[count]:i]),
					}

					return split, 1, len(split[1])
				}
				count--
			} else if i == cpos {
				return nil, 0, 0
			}
		}
	}

	return nil, 0, 0
}

// Display prints the line to stdout, starting at the current terminal
// cursor position, assuming it is at the end of the shell prompt string.
// Params:
// @indent -    Used to align all lines (except the first) together on a single column.
func (l *Line) Display(indent int) {
	lines := strings.Split(string(*l), "\n")

	if l.Len() > 0 && (*l)[l.Len()-1] == '\n' {
		lines = append(lines, "")
	}

	for num, line := range lines {
		// Don't let any visual selection go further than length.
		line += color.BgDefault

		// Clear everything before each line, except the first.
		if num > 0 {
			term.MoveCursorForwards(indent)
			line = term.ClearLineBefore + line
		}

		// Clear everything after each line, except the last.
		if num < len(lines)-1 {
			line += term.ClearLineAfter
			line += "\n"
		}

		fmt.Print(line)
	}
}

// Coordinates returns the number of real terminal lines on which the input line spans, considering
// any contained newlines, any overflowing line, and the indent passed as parameter. The values
// also take into account an eventual suggestion added to the line before printing.
// Params:
// @indent - Coordinates to align all lines (except the first) together on a single column.
// Returns:
// @x - The number of columns, starting from the terminal left, to the end of the last line.
// @y - The number of actual lines on which the line spans, accounting for line wrap.
func (l *Line) Coordinates(indent int) (x, y int) {
	newlines := l.newlines()
	bpos := 0
	usedY, usedX := 0, 0

	for i, newline := range newlines {
		bline := (*l)[bpos:newline[0]]
		bpos = newline[0]
		x, y := strutil.LineSpan(bline, i, indent)
		usedY += y
		usedX = x
	}

	return usedX, usedY
}

// Lines returns the number of real lines in the input buffer.
// If there are no newlines, the result is 1, otherwise it's
// the number of newlines + 1.
func (l *Line) Lines() int {
	line := string(*l)
	nl := regexp.MustCompile(string(inputrc.Newline))
	lines := nl.FindAllStringIndex(line, -1)

	return len(lines)
}

// newlines gives the indexes of all newline characters in the line.
func (l *Line) newlines() [][]int {
	line := string(*l)
	line += string(inputrc.Newline)
	nl := regexp.MustCompile(string(inputrc.Newline))

	return nl.FindAllStringIndex(line, -1)
}

// returns bpos, epos ordered and true if either is valid.
func (l *Line) checkRange(bpos, epos int) (int, int, bool) {
	if bpos == -1 && epos == -1 {
		return -1, -1, false
	}

	// Check positions out of bounnd
	if epos > l.Len() {
		epos = l.Len()
	}

	if bpos < 0 {
		bpos = 0
	}

	// Order begin and end pos
	if epos > -1 && epos < bpos {
		bpos, epos = epos, bpos
	}

	return bpos, epos, true
}

func (l *Line) checkPos(pos int) (int, bool) {
	if pos < 0 || pos > l.Len() || l.Len() == 0 {
		return -1, false
	}

	return pos, true
}
