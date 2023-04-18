package readline

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/reeflective/readline/inputrc"
	"github.com/reeflective/readline/internal/color"
	"github.com/reeflective/readline/internal/editor"
	"github.com/reeflective/readline/internal/keymap"
	"github.com/reeflective/readline/internal/strutil"
	"github.com/reeflective/readline/internal/term"
)

// standardCommands returns all standard/emacs commands.
// Under each comment are gathered all commands related to the comment's
// subject. When there are two subgroups separated by an empty line, the
// second one comprises commands that are not legacy readline commands.
//
// Modes
// Moving
// Changing text
// Killing and Yanking
// Numeric arguments.
// Macros
// Miscellaneous.
func (rl *Shell) standardCommands() commands {
	widgets := map[string]func(){
		// Modes
		"emacs-editing-mode": rl.emacsEditingMode,

		// Moving
		"forward-char":         rl.forwardChar,
		"backward-char":        rl.backwardChar,
		"forward-word":         rl.forwardWord,
		"backward-word":        rl.backwardWord,
		"shell-forward-word":   rl.forwardShellWord,
		"shell-backward-word":  rl.backwardShellWord,
		"beginning-of-line":    rl.beginningOfLine,
		"end-of-line":          rl.endOfLine,
		"previous-screen-line": rl.upLine,   // up-line
		"next-screen-line":     rl.downLine, // down-line
		"clear-screen":         rl.clearScreen,
		"clear-display":        rl.clearDisplay,
		"redraw-current-line":  rl.display.Refresh,

		// Changing text
		"end-of-file":                  rl.endOfFile,
		"delete-char":                  rl.deleteChar,
		"backward-delete-char":         rl.backwardDeleteChar,
		"forward-backward-delete-char": rl.forwardBackwardDeleteChar,
		"quoted-insert":                rl.quotedInsert,
		"tab-insert":                   rl.tabInsert,
		"self-insert":                  rl.selfInsert,
		"bracketed-paste-begin":        rl.bracketedPasteBegin, // TODO: Finish and find how to do it.
		"transpose-chars":              rl.transposeChars,
		"transpose-words":              rl.transposeWords,
		"shell-transpose-words":        rl.shellTransposeWords,
		"down-case-word":               rl.downCaseWord,
		"up-case-word":                 rl.upCaseWord,
		"capitalize-word":              rl.capitalizeWord,
		"overwrite-mode":               rl.overwriteMode,
		"delete-horizontal-whitespace": rl.deleteHorizontalWhitespace,

		"delete-word":      rl.deleteWord,
		"quote-region":     rl.quoteRegion,
		"quote-line":       rl.quoteLine,
		"keyword-increase": rl.keywordIncrease,
		"keyword-decrease": rl.keywordDecrease,

		// Killing & yanking
		"kill-line":                rl.killLine,
		"backward-kill-line":       rl.backwardKillLine,
		"unix-line-discard":        rl.backwardKillLine,
		"kill-whole-line":          rl.killWholeLine,
		"kill-word":                rl.killWord,
		"backward-kill-word":       rl.backwardKillWord,
		"shell-kill-word":          rl.shellKillWord,
		"shell-backward-kill-word": rl.shellBackwardKillWord,
		"unix-word-rubout":         rl.backwardKillWord,
		"kill-region":              rl.killRegion,
		"copy-region-as-kill":      rl.copyRegionAsKill,
		"copy-backward-word":       rl.copyBackwardWord,
		"copy-forward-word":        rl.copyForwardWord,
		"yank":                     rl.yank,
		"yank-pop":                 rl.yankPop,

		"kill-buffer":          rl.killBuffer,
		"copy-prev-shell-word": rl.copyPrevShellWord,

		// Numeric arguments
		"digit-argument": rl.digitArgument,

		// Macros
		"start-kbd-macro":      rl.startKeyboardMacro,
		"end-kbd-macro":        rl.endKeyboardMacro,
		"call-last-kbd-macro":  rl.callLastKeyboardMacro,
		"print-last-kbd-macro": rl.printLastKeyboardMacro,

		// Miscellaneous
		"re-read-init-file":         rl.reReadInitFile,
		"abort":                     rl.abort,
		"do-lowercase-version":      rl.doLowercaseVersion,
		"prefix-meta":               rl.prefixMeta,
		"undo":                      rl.undoLast,
		"revert-line":               rl.revertLine,
		"set-mark":                  rl.setMark, // set-mark-command
		"exchange-point-and-mark":   rl.exchangePointAndMark,
		"character-search":          rl.characterSearch,
		"character-search-backward": rl.characterSearchBackward,
		"insert-comment":            rl.insertComment,
		"dump-functions":            rl.dumpFunctions,
		"dump-variables":            rl.dumpVariables,
		"dump-macros":               rl.dumpMacros,
		"magic-space":               rl.magicSpace,
		"edit-and-execute-command":  rl.editAndExecuteCommand,
		"edit-command-line":         rl.editCommandLine,

		"redo": rl.redo,
	}

	return widgets
}

//
// Modes ----------------------------------------------------------------
//

func (rl *Shell) emacsEditingMode() {
	rl.keymaps.SetMain(keymap.Emacs)
}

//
// Movement -------------------------------------------------------------
//

func (rl *Shell) forwardChar() {
	// Only exception where we actually don't forward a character.
	if rl.opts.GetBool("history-autosuggest") && rl.cursor.Pos() == rl.line.Len()-1 {
		rl.autosuggestAccept()
		return
	}

	rl.undo.SkipSave()
	vii := rl.iterations.Get()

	for i := 1; i <= vii; i++ {
		rl.cursor.Inc()
	}
}

func (rl *Shell) backwardChar() {
	rl.undo.SkipSave()
	vii := rl.iterations.Get()

	for i := 1; i <= vii; i++ {
		rl.cursor.Dec()
	}
}

func (rl *Shell) forwardWord() {
	rl.undo.SkipSave()
	vii := rl.iterations.Get()

	for i := 1; i <= vii; i++ {
		// When we have an autosuggested history and if we are at the end
		// of the line, insert the next word from this suggested line.
		rl.insertAutosuggestPartial(true)

		forward := rl.line.ForwardEnd(rl.line.Tokenize, rl.cursor.Pos())
		rl.cursor.Move(forward + 1)
	}
}

func (rl *Shell) backwardWord() {
	rl.undo.SkipSave()

	vii := rl.iterations.Get()
	for i := 1; i <= vii; i++ {
		backward := rl.line.Backward(rl.line.Tokenize, rl.cursor.Pos())
		rl.cursor.Move(backward)
	}
}

func (rl *Shell) forwardShellWord() {
	vii := rl.iterations.Get()

	for i := 1; i <= vii; i++ {
		rl.selection.SelectAShellWord()
		_, _, tepos, _ := rl.selection.Pop()
		rl.cursor.Set(tepos)
	}
}

func (rl *Shell) backwardShellWord() {
	vii := rl.iterations.Get()

	for i := 1; i <= vii; i++ {
		// First go the beginning of the blank word
		startPos := rl.cursor.Pos()
		backward := rl.line.Backward(rl.line.TokenizeSpace, startPos)
		rl.cursor.Move(backward)

		// Now try to find enclosing quotes from here.
		bpos, _ := rl.selection.SelectAShellWord()
		rl.cursor.Set(bpos)
	}
}

func (rl *Shell) beginningOfLine() {
	rl.undo.SkipSave()

	// Handle 0 as iteration to Vim.
	if !rl.keymaps.IsEmacs() && rl.iterations.IsSet() {
		rl.iterations.Add("0")
		return
	}

	rl.cursor.BeginningOfLine()
}

func (rl *Shell) endOfLine() {
	rl.undo.SkipSave()
	// If in Vim command mode, cursor
	// will be brought back once later.
	rl.cursor.EndOfLineAppend()
}

func (rl *Shell) upLine() {
	lines := rl.iterations.Get()
	rl.cursor.LineMove(lines * -1)
}

func (rl *Shell) downLine() {
	lines := rl.iterations.Get()
	rl.cursor.LineMove(lines)
}

func (rl *Shell) clearScreen() {
	rl.undo.SkipSave()

	fmt.Print(term.CursorTopLeft)
	fmt.Print(term.ClearScreen)

	rl.prompt.PrimaryPrint()
	rl.display.CursorToPos()
}

func (rl *Shell) clearDisplay() {
	rl.undo.SkipSave()

	fmt.Print(term.CursorTopLeft)
	fmt.Print(term.ClearDisplay)

	rl.prompt.PrimaryPrint()
	rl.display.CursorToPos()
}

//
// Changing Text --------------------------------------------------------
//

func (rl *Shell) endOfFile() {
	switch rl.line.Len() {
	case 0:
		rl.display.AcceptLine()
		rl.histories.Accept(false, false, io.EOF)
	default:
		rl.deleteChar()
	}
}

func (rl *Shell) deleteChar() {
	// Extract from bash documentation of readline:
	// Delete the character at point.  If this function is bound
	// to the same character as the tty EOF character, as C-d
	//
	// TODO: We should match the same behavior here.

	rl.undo.Save()

	vii := rl.iterations.Get()

	// Delete the chars in the line anyway
	for i := 1; i <= vii; i++ {
		rl.line.CutRune(rl.cursor.Pos())
	}
}

func (rl *Shell) backwardDeleteChar() {
	if rl.keymaps.Main() == keymap.ViIns {
		rl.undo.SkipSave()
	} else {
		rl.undo.Save()
	}

	rl.completer.Update()

	if rl.cursor.Pos() == 0 {
		return
	}

	vii := rl.iterations.Get()

	switch vii {
	case 1:
		var toDelete rune
		var isSurround, matcher bool

		if rl.line.Len() > rl.cursor.Pos() {
			toDelete = (*rl.line)[rl.cursor.Pos()-1]
			isSurround = strutil.IsBracket(toDelete) || toDelete == '\'' || toDelete == '"'
			matcher = strutil.IsSurround(toDelete, (*rl.line)[rl.cursor.Pos()])
		}

		rl.cursor.Dec()
		rl.line.CutRune(rl.cursor.Pos())

		if isSurround && matcher {
			rl.line.CutRune(rl.cursor.Pos())
		}

	default:
		for i := 1; i <= vii; i++ {
			rl.cursor.Dec()
			rl.line.CutRune(rl.cursor.Pos())
		}
	}
}

func (rl *Shell) forwardBackwardDeleteChar() {
	switch rl.cursor.Pos() {
	case rl.line.Len():
		rl.backwardDeleteChar()
	default:
		rl.deleteChar()
	}
}

func (rl *Shell) quotedInsert() {
	rl.undo.SkipSave()
	rl.completer.TrimSuffix()

	done := rl.keymaps.PendingCursor()
	defer done()

	keys, _ := rl.keys.ReadArgument()

	quoted := []rune{}

	for _, key := range keys {
		switch {
		case inputrc.IsControl(key):
			quoted = append(quoted, '^')
			quoted = append(quoted, inputrc.Decontrol(key))
		default:
			quoted = append(quoted, key)
		}
	}

	rl.line.Insert(rl.cursor.Pos(), quoted...)
	rl.cursor.Move(len(quoted))
}

func (rl *Shell) tabInsert() {
	rl.undo.SkipSave()

	// tab := fmt.Sprint("\t")
	// rl.line.Insert(rl.cursor.Pos(), '\t')
	// rl.cursor.Move(1)
}

func (rl *Shell) selfInsert() {
	rl.undo.SkipSave()

	// Handle suffix-autoremoval for inserted completions.
	rl.completer.TrimSuffix()

	key, empty := rl.keys.Peek()
	if empty {
		return
	}

	// Insert the unescaped version of the key, and update cursor position.
	unescaped := inputrc.Unescape(string(key))
	rl.line.Insert(rl.cursor.Pos(), []rune(unescaped)...)
	rl.cursor.Move(len(unescaped))
}

func (rl *Shell) bracketedPasteBegin() {
	fmt.Println("Keys:")
	keys, _ := rl.keys.PeekAll()
	fmt.Println(string(keys))
}

func (rl *Shell) transposeChars() {
	if rl.cursor.Pos() < 2 || rl.line.Len() < 2 {
		rl.undo.SkipSave()
		return
	}

	switch {
	case rl.cursor.Pos() == rl.line.Len():
		last := (*rl.line)[rl.cursor.Pos()-1]
		blast := (*rl.line)[rl.cursor.Pos()-2]
		(*rl.line)[rl.cursor.Pos()-2] = last
		(*rl.line)[rl.cursor.Pos()-1] = blast
	default:
		last := (*rl.line)[rl.cursor.Pos()]
		blast := (*rl.line)[rl.cursor.Pos()-1]
		(*rl.line)[rl.cursor.Pos()-1] = last
		(*rl.line)[rl.cursor.Pos()] = blast
	}
}

func (rl *Shell) transposeWords() {
	rl.undo.Save()

	startPos := rl.cursor.Pos()
	rl.cursor.ToFirstNonSpace(true)
	rl.cursor.CheckCommand()

	// Save the current word and move the cursor to its beginning
	rl.viSelectInWord()
	toTranspose, tbpos, tepos, _ := rl.selection.Pop()

	// Then move some number of words.
	// Either use words backward (if we are at end of line) or forward.
	rl.cursor.Set(tbpos)
	if tepos == rl.line.Len()-1 || tepos == rl.line.Len() || rl.iterations.IsSet() {
		rl.backwardWord()
	} else {
		rl.forwardWord()
	}

	// Save the word to transpose with
	rl.viSelectInWord()
	transposeWith, wbpos, wepos, _ := rl.selection.Pop()

	// We might be on the first word of the line,
	// in which case we don't do anything.
	if tbpos == 0 {
		rl.cursor.Set(startPos)
		return
	}

	// If we went forward rather than backward, swap everything.
	if wbpos > tbpos {
		wbpos, tbpos = tbpos, wbpos
		wepos, tepos = tepos, wepos
		transposeWith, toTranspose = toTranspose, transposeWith
	}

	// Assemble the newline
	begin := string((*rl.line)[:wbpos])
	newLine := append([]rune(begin), []rune(toTranspose)...)
	newLine = append(newLine, (*rl.line)[wepos:tbpos]...)
	newLine = append(newLine, []rune(transposeWith)...)
	newLine = append(newLine, (*rl.line)[tepos:]...)
	rl.line.Set(newLine...)

	// And replace the cursor
	rl.cursor.Set(tepos)
}

func (rl *Shell) shellTransposeWords() {
	rl.undo.Save()

	startPos := rl.cursor.Pos()

	// Save the current word
	rl.viSelectAShellWord()
	toTranspose, tbpos, tepos, _ := rl.selection.Pop()

	// First move back the number of words
	rl.cursor.Set(tbpos)
	rl.backwardShellWord()

	// Save the word to transpose with
	rl.viSelectAShellWord()
	transposeWith, wbpos, wepos, _ := rl.selection.Pop()

	// We might be on the first word of the line,
	// in which case we don't do anything.
	if wepos > tbpos {
		rl.cursor.Set(startPos)
		return
	}

	// Assemble the newline
	begin := string((*rl.line)[:wbpos])
	newLine := append([]rune(begin), []rune(toTranspose)...)
	newLine = append(newLine, (*rl.line)[wepos:tbpos]...)
	newLine = append(newLine, []rune(transposeWith)...)
	newLine = append(newLine, (*rl.line)[tepos:]...)
	rl.line.Set(newLine...)

	// And replace cursor
	rl.cursor.Set(tepos)
}

func (rl *Shell) downCaseWord() {
	rl.undo.Save()

	startPos := rl.cursor.Pos()

	// Save the current word
	rl.cursor.Inc()
	backward := rl.line.Backward(rl.line.Tokenize, rl.cursor.Pos())
	rl.cursor.Move(backward)

	rl.selection.Mark(rl.cursor.Pos())
	forward := rl.line.ForwardEnd(rl.line.Tokenize, rl.cursor.Pos())
	rl.cursor.Move(forward)

	rl.selection.ReplaceWith(unicode.ToLower)
	rl.cursor.Set(startPos)
}

func (rl *Shell) upCaseWord() {
	rl.undo.Save()

	startPos := rl.cursor.Pos()

	// Save the current word
	rl.cursor.Inc()
	backward := rl.line.Backward(rl.line.Tokenize, rl.cursor.Pos())
	rl.cursor.Move(backward)

	rl.selection.Mark(rl.cursor.Pos())
	forward := rl.line.ForwardEnd(rl.line.Tokenize, rl.cursor.Pos())
	rl.cursor.Move(forward)

	rl.selection.ReplaceWith(unicode.ToUpper)
	rl.cursor.Set(startPos)
}

func (rl *Shell) capitalizeWord() {
	rl.undo.Save()

	startPos := rl.cursor.Pos()

	rl.cursor.Inc()
	backward := rl.line.Backward(rl.line.Tokenize, rl.cursor.Pos())
	rl.cursor.Move(backward)

	letter := (*rl.line)[rl.cursor.Pos()]
	upper := unicode.ToUpper(letter)
	(*rl.line)[rl.cursor.Pos()] = upper
	rl.cursor.Set(startPos)
}

func (rl *Shell) overwriteMode() {
	// We store the current line as an undo item first, but will not
	// store any intermediate changes (in the loop below) as undo items.
	rl.undo.Save()

	done := rl.keymaps.PendingCursor()
	defer done()

	// The replace mode is quite special in that it does escape back
	// to the main readline loop: it keeps reading characters and inserts
	// them as long as the escape key is not pressed.
	for {
		// Read a new key
		keys, esc := rl.keys.ReadArgument()
		if esc {
			return
		}

		key := keys[0]

		// If the key is a backspace, we go back one character
		if key == inputrc.Backspace {
			rl.backwardDeleteChar()
		} else {
			// If the cursor is at the end of the line,
			// we insert the character instead of replacing.
			if rl.cursor.Pos() == rl.line.Len() {
				rl.line.Insert(rl.cursor.Pos(), key)
			} else {
				(*rl.line)[rl.cursor.Pos()] = key
			}

			rl.cursor.Inc()
		}

		rl.display.Refresh()
	}
}

func (rl *Shell) deleteHorizontalWhitespace() {
	rl.undo.Save()

	startPos := rl.cursor.Pos()

	rl.cursor.ToFirstNonSpace(false)

	if rl.cursor.Pos() != startPos {
		rl.cursor.Inc()
	}
	bpos := rl.cursor.Pos()

	rl.cursor.ToFirstNonSpace(true)

	if rl.cursor.Pos() != startPos {
		rl.cursor.Dec()
	}
	epos := rl.cursor.Pos()

	rl.line.Cut(bpos, epos)
	rl.cursor.Set(bpos)
}

func (rl *Shell) deleteWord() {
	rl.undo.Save()

	rl.selection.Mark(rl.cursor.Pos())
	forward := rl.line.ForwardEnd(rl.line.Tokenize, rl.cursor.Pos())
	rl.cursor.Move(forward)

	rl.selection.Cut()
}

func (rl *Shell) quoteRegion() {
	rl.undo.Save()

	rl.selection.Surround('\'', '\'')
	rl.cursor.Inc()
}

func (rl *Shell) quoteLine() {
	if rl.line.Len() == 0 {
		return
	}

	rl.line.Insert(0, '\'')

	for pos, char := range *rl.line {
		if char == '\n' {
			break
		}

		if char == '\'' {
			(*rl.line)[pos] = '"'
		}
	}

	rl.line.Insert(rl.line.Len(), '\'')
}

func (rl *Shell) keywordIncrease() {
	rl.undo.Save()
	rl.keywordSwitch(true)
}

func (rl *Shell) keywordDecrease() {
	rl.undo.Save()
	rl.keywordSwitch(false)
}

// Cursor position cases:
//
// 1. Cursor on symbol:
// 2+2   => +
// 2-2   => -
// 2 + 2 => +
// 2 +2  => +2
// 2 -2  => -2
// 2 -a  => -a
//
// 2. Cursor on number or alpha:
// 2+2   => +2
// 2-2   => -2
// 2 + 2 => 2
// 2 +2  => +2
// 2 -2  => -2
// 2 -a  => -a.
func (rl *Shell) keywordSwitch(increase bool) {
	cpos := strutil.AdjustNumberOperatorPos(rl.cursor.Pos(), *rl.line)

	// Select in word and get the selection positions
	bpos, epos := rl.line.SelectWord(cpos)
	epos++

	// Move the cursor backward if needed/possible
	if bpos != 0 && ((*rl.line)[bpos-1] == '+' || (*rl.line)[bpos-1] == '-') {
		bpos--
	}

	// Get the selection string
	selection := string((*rl.line)[bpos:epos])

	// For each of the keyword handlers, run it, which returns
	// false/none if didn't operate, then continue to next handler.
	for _, switcher := range strutil.KeywordSwitchers() {
		vii := rl.iterations.Get()

		changed, word, obpos, oepos := switcher(selection, increase, vii)
		if !changed {
			continue
		}

		// We are only interested in the end position after all runs
		epos = bpos + oepos
		bpos += obpos

		if cpos < bpos || cpos >= epos {
			continue
		}

		// Update the line and the cursor, and return
		// since we have a handler that has been ran.
		begin := string((*rl.line)[:bpos])
		end := string((*rl.line)[epos:])

		newLine := append([]rune(begin), []rune(word)...)
		newLine = append(newLine, []rune(end)...)
		rl.line.Set(newLine...)
		rl.cursor.Set(bpos + len(word) - 1)

		return
	}
}

//
// Killing & Yanking ----------------------------------------------------------
//

func (rl *Shell) killLine() {
	rl.iterations.Reset()
	rl.undo.Save()

	cut := []rune(*rl.line)[rl.cursor.Pos():]
	rl.buffers.Write(cut...)

	rl.line.Cut(rl.cursor.Pos(), rl.line.Len())
}

func (rl *Shell) backwardKillLine() {
	rl.iterations.Reset()
	rl.undo.Save()

	cut := []rune(*rl.line)[:rl.cursor.Pos()]
	rl.buffers.Write(cut...)

	rl.line.Cut(0, rl.cursor.Pos())
}

func (rl *Shell) killWholeLine() {
	rl.undo.Save()

	if rl.line.Len() == 0 {
		return
	}

	rl.buffers.Write(*rl.line...)
	rl.line.Cut(0, rl.line.Len())
}

func (rl *Shell) killBuffer() {
	rl.undo.Save()

	if rl.line.Len() == 0 {
		return
	}

	rl.buffers.Write(*rl.line...)
	rl.line.Cut(0, rl.line.Len())
}

func (rl *Shell) killWord() {
	rl.undo.Save()

	bpos := rl.cursor.Pos()

	rl.cursor.ToFirstNonSpace(true)
	forward := rl.line.Forward(rl.line.TokenizeSpace, rl.cursor.Pos())
	rl.cursor.Move(forward - 1)
	epos := rl.cursor.Pos()

	rl.selection.MarkRange(bpos, epos)
	rl.buffers.Write([]rune(rl.selection.Cut())...)
	rl.cursor.Set(bpos)
}

func (rl *Shell) backwardKillWord() {
	rl.undo.Save()
	rl.undo.SkipSave()

	rl.selection.Mark(rl.cursor.Pos())
	adjust := rl.line.Backward(rl.line.Tokenize, rl.cursor.Pos())
	rl.cursor.Move(adjust)

	rl.buffers.Write([]rune(rl.selection.Cut())...)
}

func (rl *Shell) shellKillWord() {
	startPos := rl.cursor.Pos()

	// select the shell word, and if the cursor position
	// has changed, we delete the part after the initial one.
	rl.viSelectAShellWord()

	_, epos := rl.selection.Pos()

	rl.buffers.Write([]rune((*rl.line)[startPos:epos])...)
	rl.line.Cut(startPos, epos)
	rl.cursor.Set(startPos)

	rl.selection.Reset()
}

func (rl *Shell) shellBackwardKillWord() {
	startPos := rl.cursor.Pos()

	// Always ignore the character under cursor.
	rl.cursor.Dec()
	rl.cursor.ToFirstNonSpace(false)

	// Find the beginning of a correctly formatted shellword.
	rl.viSelectAShellWord()
	bpos, _ := rl.selection.Pos()

	// But don't include any of the leading spaces.
	rl.cursor.Set(bpos)
	rl.cursor.ToFirstNonSpace(true)
	bpos = rl.cursor.Pos()

	// Find any quotes backard, and settle on the outermost one.
	outquote := -1

	squote := rl.line.Find('\'', bpos, false)
	dquote := rl.line.Find('"', bpos, false)

	if squote != -1 {
		outquote = squote
	}
	if dquote != -1 {
		if squote != -1 && dquote < squote {
			outquote = dquote
		} else if squote == -1 {
			outquote = dquote
		}
	}

	// If any is found, try to find if it's matching another one.
	if outquote != -1 {
		sBpos, sEpos := rl.line.SurroundQuotes(true, outquote)
		dBpos, dEpos := rl.line.SurroundQuotes(false, outquote)
		mark, _ := strutil.AdjustSurroundQuotes(dBpos, dEpos, sBpos, sEpos)

		// And if no matches have been found, only use the quote
		// if its backward to our currently found shellword.
		if mark == -1 && outquote < bpos {
			bpos = outquote
			rl.cursor.Set(bpos)
		}
	}

	// Remove the selection.
	rl.buffers.Write([]rune((*rl.line)[bpos:startPos])...)
	rl.line.Cut(bpos, startPos)

	rl.selection.Reset()
}

func (rl *Shell) killRegion() {
	rl.undo.Save()

	if !rl.selection.Active() {
		return
	}

	rl.buffers.Write([]rune(rl.selection.Cut())...)
}

func (rl *Shell) copyRegionAsKill() {
	rl.undo.SkipSave()

	if !rl.selection.Active() {
		return
	}

	rl.buffers.Write([]rune(rl.selection.Text())...)
	rl.selection.Reset()
}

func (rl *Shell) copyBackwardWord() {
	rl.undo.Save()

	rl.selection.Mark(rl.cursor.Pos())
	adjust := rl.line.Backward(rl.line.Tokenize, rl.cursor.Pos())
	rl.cursor.Move(adjust)

	rl.buffers.Write([]rune(rl.selection.Text())...)
	rl.selection.Reset()
}

func (rl *Shell) copyForwardWord() {
	rl.undo.Save()

	rl.selection.Mark(rl.cursor.Pos())
	adjust := rl.line.Forward(rl.line.Tokenize, rl.cursor.Pos())
	rl.cursor.Move(adjust + 1)

	rl.buffers.Write([]rune(rl.selection.Text())...)
	rl.selection.Reset()
}

func (rl *Shell) yank() {
	buf := rl.buffers.Get(rune(0))

	vii := rl.iterations.Get()

	for i := 1; i <= vii; i++ {
		rl.line.Insert(rl.cursor.Pos(), buf...)
		rl.cursor.Move(len(buf))
	}
}

func (rl *Shell) yankPop() {
	vii := rl.iterations.Get()

	for i := 1; i <= vii; i++ {
		buf := rl.buffers.Pop()
		rl.line.Insert(rl.cursor.Pos(), buf...)
		rl.cursor.Move(len(buf))
	}
}

func (rl *Shell) copyPrevShellWord() {
	rl.undo.Save()

	posInit := rl.cursor.Pos()

	// First go back to the beginning of the current word,
	// then go back again to the beginning of the previous.
	rl.backwardShellWord()
	rl.backwardShellWord()

	// Select the current shell word
	rl.viSelectAShellWord()

	word := rl.selection.Text()

	// Replace the cursor before reassembling the line.
	rl.cursor.Set(posInit)
	rl.selection.InsertAt(rl.cursor.Pos(), -1)
	rl.cursor.Move(len(word))
}

//
// Numeric Arguments -----------------------------------------------------------
//

// digitArgument is used both in Emacs and Vim modes,
// but strips the Alt modifier used in Emacs mode.
func (rl *Shell) digitArgument() {
	rl.undo.SkipSave()

	keys, empty := rl.keys.PeekAll()
	if empty {
		return
	}

	rl.iterations.Add(string(keys))
}

//
// Macros ----------------------------------------------------------------------
//

func (rl *Shell) startKeyboardMacro() {
	rl.macros.StartRecord()
}

func (rl *Shell) endKeyboardMacro() {
	rl.macros.StopRecord()
}

func (rl *Shell) callLastKeyboardMacro() {
	rl.macros.RunLastMacro()
}

func (rl *Shell) printLastKeyboardMacro() {
	rl.display.ClearHelpers()

	rl.macros.PrintLastMacro()

	rl.prompt.PrimaryPrint()
	rl.display.Refresh()
}

//
// Miscellaneous ---------------------------------------------------------------
//

func (rl *Shell) reReadInitFile() {
	config := filepath.Join(os.Getenv("HOME"), ".inputrc")

	err := inputrc.ParseFile(config, rl.opts)
	if err != nil {
		rl.hint.Set(color.FgRed + "Inputrc reload error: " + err.Error())
	} else {
		rl.hint.Set(color.FgGreen + "Inputrc reloaded: " + config)
	}
}

func (rl *Shell) abort() {
	// Reset any visual selection and iterations.
	rl.iterations.Reset()
	rl.selection.Reset()

	// Cancel completions and/or incremental search.
	rl.hint.Reset()
	rl.completer.ResetForce()
}

// func (rl *Instance) errorCtrlC() error {
// 	rl.keys = ""
//
// 	// Or return the current command line
// 	rl.clearHelpers()
// 	moveCursorDown(rl.fullY - rl.posY)
// 	fmt.Print("\r\n")
//
// 	return ErrCtrlC

func (rl *Shell) doLowercaseVersion() {
	rl.undo.SkipSave()

	keys, empty := rl.keys.PeekAll()
	if empty {
		return
	}

	escapePrefix := false

	// Get rid of the escape if it's a prefix
	if len(keys) > 1 && keys[0] == inputrc.Esc {
		escapePrefix = true
		keys = keys[1:]
	} else if len(keys) == 1 && inputrc.IsMeta(keys[0]) {
		keys = []rune{inputrc.Demeta(keys[0])}
	}

	// Undefined behavior if the key is already lowercase.
	if unicode.IsLower(keys[0]) {
		return
	}

	keys[0] = unicode.ToLower(keys[0])

	// Feed back the keys with meta prefix or encoding
	if escapePrefix {
		input := append([]rune{inputrc.Esc}, keys...)
		rl.keys.Feed(false, true, input...)
	} else {
		rl.keys.Feed(false, true, inputrc.Enmeta(keys[0]))
	}
}

func (rl *Shell) prefixMeta() {
	rl.undo.SkipSave()

	done := rl.keymaps.PendingCursor()
	defer done()

	keys, isAbort := rl.keys.ReadArgument()
	if isAbort {
		return
	}

	keys = append([]rune{inputrc.Esc}, keys...)

	// And feed them back to be used on the next loop.
	rl.keys.Feed(false, true, keys...)
}

func (rl *Shell) undoLast() {
	rl.undo.Undo(rl.line, rl.cursor)
}

func (rl *Shell) revertLine() {
	rl.undo.Revert(rl.line, rl.cursor)
}

func (rl *Shell) setMark() {
	switch {
	case rl.iterations.IsSet():
		rl.cursor.SetMark()
	default:
		cpos := rl.cursor.Pos()
		mark := rl.iterations.Get()

		if mark > rl.line.Len()-1 {
			return
		}

		rl.cursor.Set(mark)
		rl.cursor.SetMark()
		rl.cursor.Set(cpos)
	}
}

func (rl *Shell) exchangePointAndMark() {
	// Deactivate mark if out of bound
	if rl.cursor.Mark() > rl.line.Len() {
		rl.cursor.ResetMark()
	}

	// And set it to start if negative.
	if rl.cursor.Mark() < 0 {
		cpos := rl.cursor.Pos()
		rl.cursor.Set(0)
		rl.cursor.SetMark()
		rl.cursor.Set(cpos)
	} else {
		mark := rl.cursor.Mark()

		rl.cursor.SetMark()
		rl.cursor.Set(mark)

		rl.selection.MarkRange(rl.cursor.Mark(), rl.cursor.Pos())
		rl.selection.Visual(false)
	}
}

func (rl *Shell) characterSearch() {
	if rl.iterations.Get() < 0 {
		rl.viFindChar(false, false)
	} else {
		rl.viFindChar(true, false)
	}
}

func (rl *Shell) characterSearchBackward() {
	if rl.iterations.Get() < 0 {
		rl.viFindChar(true, false)
	} else {
		rl.viFindChar(false, false)
	}
}

func (rl *Shell) insertComment() {
	comment := rl.opts.GetString("comment-begin")

	switch {
	case !rl.iterations.IsSet():
		// Without numeric argument, insert comment at the beginning of the line.
		cpos := rl.cursor.Pos()
		rl.cursor.BeginningOfLine()
		rl.line.Insert(rl.cursor.Pos(), []rune(comment)...)
		rl.cursor.Set(cpos)

	default:
		// Or with one, toggle the current line commenting.
		cpos := rl.cursor.Pos()
		rl.cursor.BeginningOfLine()

		bpos := rl.cursor.Pos()
		epos := bpos + len(comment)

		rl.cursor.Set(cpos)

		commentFits := epos < rl.line.Len()

		if commentFits && string((*rl.line)[bpos:epos]) == comment {
			rl.line.Cut(bpos, epos)
			rl.cursor.Move(-1 * len(comment))
		} else {
			rl.line.Insert(bpos, []rune(comment)...)
			rl.cursor.Move(1 * len(comment))
		}
	}

	// Either case, accept the line as it is.
	rl.acceptLineWith(false, false)
}

func (rl *Shell) dumpFunctions() {
	rl.display.ClearHelpers()
	fmt.Println()

	defer func() {
		rl.prompt.PrimaryPrint()
		rl.display.Refresh()
	}()

	inputrcFormat := rl.iterations.IsSet()
	rl.keymaps.PrintBinds(inputrcFormat)
}

func (rl *Shell) dumpVariables() {
	rl.display.ClearHelpers()
	fmt.Println()

	defer func() {
		rl.prompt.PrimaryPrint()
		rl.display.Refresh()
	}()

	// Get all variables and their values, alphabetically sorted.
	var variables []string

	for variable := range rl.opts.Vars {
		variables = append(variables, variable)
	}

	sort.Strings(variables)

	// Either print in inputrc format, or wordly one.
	if rl.iterations.IsSet() {
		for _, variable := range variables {
			value := rl.opts.Vars[variable]
			fmt.Printf("set %s %v\n", variable, value)
		}
	} else {
		for _, variable := range variables {
			value := rl.opts.Vars[variable]
			fmt.Printf("%s is set to `%v'\n", variable, value)
		}
	}
}

func (rl *Shell) dumpMacros() {
	rl.display.ClearHelpers()
	fmt.Println()

	defer func() {
		rl.prompt.PrimaryPrint()
		rl.display.Refresh()
	}()

	// We print the macros bound to the current keymap only.
	binds := rl.opts.Binds[string(rl.keymaps.Main())]
	if len(binds) == 0 {
		return
	}

	var macroBinds []string

	for keys, bind := range binds {
		if bind.Macro {
			macroBinds = append(macroBinds, inputrc.Escape(keys))
		}
	}

	sort.Strings(macroBinds)

	if rl.iterations.IsSet() {
		for _, key := range macroBinds {
			action := inputrc.Escape(binds[inputrc.Unescape(key)].Action)
			fmt.Printf("\"%s\": \"%s\"\n", key, action)
		}
	} else {
		for _, key := range macroBinds {
			action := inputrc.Escape(binds[inputrc.Unescape(key)].Action)
			fmt.Printf("%s outputs %s\n", key, action)
		}
	}
}

func (rl *Shell) editAndExecuteCommand() {
	buffer := *rl.line

	// Edit in editor
	edited, err := editor.EditBuffer(buffer, "", "")
	if err != nil || (len(edited) == 0 && len(buffer) != 0) {
		rl.undo.SkipSave()

		errStr := strings.ReplaceAll(err.Error(), "\n", "")
		changeHint := fmt.Sprintf(color.FgRed+"Editor error: %s", errStr)
		rl.hint.Set(changeHint)

		return
	}

	// Update our line and return it the caller.
	rl.line.Set(edited...)
	rl.display.AcceptLine()
	rl.histories.Accept(false, false, nil)
}

func (rl *Shell) editCommandLine() {
	buffer := *rl.line
	keymapCur := rl.keymaps.Main()

	// Edit in editor
	edited, err := editor.EditBuffer(buffer, "", "")
	if err != nil || (len(edited) == 0 && len(buffer) != 0) {
		rl.undo.SkipSave()

		errStr := strings.ReplaceAll(err.Error(), "\n", "")
		changeHint := fmt.Sprintf(color.FgRed+"Editor error: %s", errStr)
		rl.hint.Set(changeHint)

		return
	}

	// Update our line
	rl.line.Set(edited...)

	// We're done with visual mode when we were in.
	switch keymapCur {
	case keymap.Emacs, keymap.EmacsStandard, keymap.EmacsMeta, keymap.EmacsCtrlX:
		rl.emacsEditingMode()
	}
}

func (rl *Shell) redo() {
	rl.undo.Redo(rl.line, rl.cursor)
}
