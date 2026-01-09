package cmd

import "github.com/spf13/cobra"

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "k8s-biscuit",
	}

	cmd.AddCommand(NewGenKeyCommand())
	cmd.AddCommand(NewGenTokenCommand())
	cmd.AddCommand(NewAttenuateCommand())
	cmd.AddCommand(NewAuthorizeCommand())
	cmd.AddCommand(NewRunCommand())

	return cmd
}
