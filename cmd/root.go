package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type exitCodeError struct {
	code int
	err  error
}

func (errorWithCode exitCodeError) Error() string { return errorWithCode.err.Error() }
func (errorWithCode exitCodeError) Unwrap() error { return errorWithCode.err }

var rootCmd = &cobra.Command{
	Use:          "guardrail",
	Short:        "GuardRail encontra riscos de segurança no seu código",
	Long:         "GuardRail é uma ferramenta rápida de análise estática focada em segredos, IaC e boas práticas de segurança.",
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var codedError exitCodeError
		if errors.As(err, &codedError) {
			os.Exit(codedError.code)
		}
		os.Exit(2)
	}
}
