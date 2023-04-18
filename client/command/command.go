package command

import (
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Flags is a convenience function to bind flags to a given command.
// name - The name of the flag set (can be empty).
// cmd  - The command to which the flags should be bound.
// flags - A function exposing the flag set through which flags are declared.
func Flags(name string, cmd *cobra.Command, flags func(f *pflag.FlagSet)) {
	flagSet := pflag.NewFlagSet(name, pflag.ContinueOnError) // Create the flag set.
	flags(flagSet)                                           // Let the user bind any number of flags to it.
	cmd.Flags().AddFlagSet(flagSet)                          // And bind to the command.
}

// FlagComps is a convenience function for adding completions to a command's flags.
// cmd - The command owning the flags to complete.
// bind - A function exposing a map["flag-name"]carapace.Action.
func FlagComps(cmd *cobra.Command, bind func(comp *carapace.ActionMap)) {
	comps := make(carapace.ActionMap)
	bind(&comps)

	carapace.Gen(cmd).FlagCompletion(comps)
}
