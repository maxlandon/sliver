package keymap

import (
	"fmt"
	"sort"
	"strings"

	"github.com/reeflective/readline/inputrc"
	"github.com/reeflective/readline/internal/core"
)

// Modes is used to manage the main and local keymaps for the shell.
type Modes struct {
	local    Mode
	main     Mode
	prefixed inputrc.Bind
	active   inputrc.Bind
	pending  []action
	skip     bool
	isCaller bool

	keys       *core.Keys
	iterations *core.Iterations
	opts       *inputrc.Config
	commands   map[string]func()
}

// NewModes is a required constructor for the keymap modes manager.
// It initializes the keymaps to their defaults or configured values.
func NewModes(keys *core.Keys, i *core.Iterations, opts *inputrc.Config) *Modes {
	modes := &Modes{
		main:       Emacs,
		keys:       keys,
		iterations: i,
		opts:       opts,
		commands:   make(map[string]func()),
	}

	defer modes.UpdateCursor()

	switch modes.opts.GetString("editing-mode") {
	case "emacs":
		modes.main = Emacs
	case "vi":
		modes.main = ViIns
	}

	// Add additional default keymaps
	modes.opts.Binds[string(Visual)] = visualKeys
	modes.opts.Binds[string(ViOpp)] = vioppKeys

	return modes
}

// Register adds commands to the list of available commands.
func (m *Modes) Register(commands map[string]func()) {
	for name, command := range commands {
		m.commands[name] = command
	}
}

// SetMain sets the main keymap of the shell.
func (m *Modes) SetMain(keymap Mode) {
	m.main = keymap
	m.UpdateCursor()
}

// Main returns the local keymap.
func (m *Modes) Main() Mode {
	return m.main
}

// SetLocal sets the local keymap of the shell.
func (m *Modes) SetLocal(keymap Mode) {
	m.local = keymap
	m.UpdateCursor()
}

// Local returns the local keymap.
func (m *Modes) Local() Mode {
	return m.local
}

// ResetLocal deactivates the local keymap of the shell.
func (m *Modes) ResetLocal() {
	m.local = ""
	m.UpdateCursor()
}

// UpdateCursor reprints the cursor corresponding to the current keymaps.
func (m *Modes) UpdateCursor() {
	switch m.local {
	case ViOpp:
		m.PrintCursor(ViOpp)
		return
	case Visual:
		m.PrintCursor(Visual)
		return
	}

	// But if not, we check for the global keymap
	switch m.main {
	case Emacs, EmacsStandard, EmacsMeta, EmacsCtrlX:
		m.PrintCursor(Emacs)
	case ViIns:
		m.PrintCursor(ViIns)
	case ViCmd:
		m.PrintCursor(ViCmd)
	}
}

// PendingCursor changes the cursor to pending mode,
// and returns a function to call once done with it.
func (m *Modes) PendingCursor() func() {
	m.PrintCursor(ViOpp)

	return func() {
		m.UpdateCursor()
	}
}

// IsEmacs returns true if the main keymap is one of the emacs modes.
func (m *Modes) IsEmacs() bool {
	switch m.main {
	case Emacs, EmacsStandard, EmacsMeta, EmacsCtrlX:
		return true
	default:
		return false
	}
}

// PrintBinds displays a list of currently bound commands (and their sequences)
// to the screen. If inputrcFormat is true, it displays it formatted such that
// the output can be reused in an .inputrc file.
func (m *Modes) PrintBinds(inputrcFormat bool) {
	var commands []string

	for command := range m.commands {
		commands = append(commands, command)
	}

	sort.Strings(commands)

	binds := m.opts.Binds[string(m.Main())]

	// Make a list of all sequences bound to each command.
	allBinds := make(map[string][]string)

	for _, command := range commands {
		for key, bind := range binds {
			if bind.Action != command {
				continue
			}

			commandBinds := allBinds[command]
			commandBinds = append(commandBinds, inputrc.Escape(key))
			allBinds[command] = commandBinds
		}
	}

	if inputrcFormat {
		for _, command := range commands {
			commandBinds := allBinds[command]
			sort.Strings(commandBinds)

			switch {
			case len(commandBinds) == 0:
				fmt.Printf("# %s (not bound)\n", command)
			default:
				for _, bind := range commandBinds {
					fmt.Printf("\"%s\": %s\n", bind, command)
				}
			}
		}
	} else {
		for _, command := range commands {
			commandBinds := allBinds[command]
			sort.Strings(commandBinds)

			switch {
			case len(commandBinds) == 0:
				fmt.Printf("%s is not bound to any keys\n", command)

			case len(commandBinds) > 5:
				var firstBinds []string

				for i := 0; i < 5; i++ {
					firstBinds = append(firstBinds, "\""+commandBinds[i]+"\"")
				}

				bindsStr := strings.Join(firstBinds, ", ")
				fmt.Printf("%s can be found on %s ...\n", command, bindsStr)

			default:
				var firstBinds []string

				for _, bind := range commandBinds {
					firstBinds = append(firstBinds, "\""+bind+"\"")
				}

				bindsStr := strings.Join(firstBinds, ", ")
				fmt.Printf("%s can be found on %s\n", command, bindsStr)
			}
		}
	}
}

// ConvertMeta recursively searches for metafied keys in a sequence,
// and replaces them with an esc prefix and their unmeta equivalent.
func (m *Modes) ConvertMeta(keys []rune) string {
	if len(keys) == 0 {
		return string(keys)
	}

	converted := make([]rune, 0)

	for i := 0; i < len(keys); i++ {
		char := keys[i]

		if !inputrc.IsMeta(char) {
			converted = append(converted, char)
			continue
		}

		// Replace the key with esc prefix and add the demetafied key.
		converted = append(converted, inputrc.Esc)
		converted = append(converted, inputrc.Demeta(char))
	}

	return string(converted)
}

// MatchMain incrementally attempts to match cached input keys against the local keymap.
// Returns the bind if matched, the corresponding command, and if we only matched by prefix.
func (m *Modes) MatchMain() (bind inputrc.Bind, command func(), prefix bool) {
	if m.main == "" {
		return
	}

	binds := m.opts.Binds[string(m.main)]
	if len(binds) == 0 {
		return
	}

	bind, command, prefix = m.matchKeymap(binds)

	// Adjusting for the ESC key: when convert-meta is enabled,
	// many binds will actually match ESC as a prefix. This makes
	// commands like vi-movement-mode unreachable, so if the bind
	// is vi-movement-mode, we return it to be ran regardless of
	// the other binds matching by prefix.
	if prefix && m.prefixed.Action == "vi-movement-mode" {
		bind = m.prefixed
		command = m.resolveCommand(bind)
		m.prefixed = inputrc.Bind{}

		return bind, command, false
	}

	return
}

// MatchMain incrementally attempts to match cached input keys against the main keymap.
// Returns the bind if matched, the corresponding command, and if we only matched by prefix.
func (m *Modes) MatchLocal() (bind inputrc.Bind, command func(), prefix bool) {
	if m.local == "" {
		return
	}

	binds := m.opts.Binds[string(m.local)]
	if len(binds) == 0 {
		return
	}

	return m.matchKeymap(binds)
}

func (m *Modes) matchKeymap(binds map[string]inputrc.Bind) (bind inputrc.Bind, cmd func(), prefix bool) {
	var keys []rune

	// Important to wrap in a defer function,
	// because the keys array is not yet populated.
	defer func() {
		m.keys.Matched(keys...)
	}()

	for {
		// Read keys one by one, and abort once exhausted.
		key, empty := m.keys.Pop()
		if empty {
			return
		}

		keys = append(keys, key)

		// Find binds (actions/macros) matching by prefix or perfectly.
		match, prefixed := m.matchCommand(keys, binds)

		// If the current keys have no matches but the previous
		// matching process found a prefix, use it with the keys.
		if match.Action == "" && len(prefixed) == 0 {
			prefix = false
			cmd = m.resolveCommand(m.prefixed)
			m.prefixed = inputrc.Bind{}

			return
		}

		// Or several matches, in which case we read another key.
		if match.Action != "" && len(prefixed) > 0 {
			prefix = true
			m.prefixed = match

			continue
		}

		// Or no exact match and only prefixes
		if len(prefixed) > 0 {
			prefix = true
			continue
		}

		// Or an exact match, so drop any prefixed one.
		m.active = match
		m.prefixed = inputrc.Bind{}

		return match, m.resolveCommand(match), false
	}
}

func (m *Modes) matchCommand(keys []rune, binds map[string]inputrc.Bind) (inputrc.Bind, []inputrc.Bind) {
	var match inputrc.Bind
	var prefixed []inputrc.Bind

	for sequence, kbind := range binds {
		// When convert-meta is on, any meta-prefixed bind should
		// be stripped and replaced with an escape meta instead.
		if m.opts.GetBool("convert-meta") {
			sequence = m.ConvertMeta([]rune(sequence))
		}

		// If the keys are a prefix of the bind, keep the bind
		if len(string(keys)) < len(sequence) && strings.HasPrefix(sequence, string(keys)) {
			prefixed = append(prefixed, kbind)
		}

		// Else if the match is perfect, keep the bind
		if string(keys) == sequence {
			match = kbind
		}
	}

	return match, prefixed
}

func (m *Modes) resolveCommand(bind inputrc.Bind) func() {
	if bind.Macro {
		return nil
	}

	if bind.Action == "" {
		return nil
	}

	return m.commands[bind.Action]
}
