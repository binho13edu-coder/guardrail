package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/binho13edu-coder/guardrail/pkg/logging"
	"github.com/binho13edu-coder/guardrail/pkg/reporter"
	"github.com/binho13edu-coder/guardrail/pkg/scanner"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var rulesFile string
var threshold string
var logFormat string
var verbose bool
var outputFormat string
var outputFile string

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Varre um arquivo ou diretório em busca de riscos de segurança",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger, err := logging.New(logFormat, verbose)
		if err != nil {
			return err
		}
		defer logger.Sync()

		targetPath, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("resolve scan path: %w", err)
		}

		rulesPath, err := filepath.Abs(rulesFile)
		if err != nil {
			return fmt.Errorf("resolve rules path: %w", err)
		}

		rules, err := scanner.LoadRules(rulesPath)
		if err != nil {
			return err
		}

		logger.Info("scan started", zap.String("path", targetPath), zap.String("rules", rulesPath), zap.String("threshold", threshold))
		findings, err := scanner.ScanPathWithOptions(targetPath, rules, scanner.ScanOptions{Logger: logger})
		if err != nil {
			return err
		}

		if err := writeReport(cmd.OutOrStdout(), findings); err != nil {
			return err
		}
		logger.Info("scan completed", zap.Int("findings", len(findings)))
		shouldFail, err := scanner.MeetsThreshold(findings, threshold)
		if err != nil {
			return err
		}
		if shouldFail {
			return exitCodeError{code: 1, err: errors.New("security findings meet the configured failure threshold")}
		}
		return nil
	},
}

func init() {
	scanCmd.Flags().StringVarP(&rulesFile, "rules", "r", "rules", "arquivo ou diretório YAML com regras de detecção")
	scanCmd.Flags().StringVar(&threshold, "threshold", "critical", "falha o processo em critical, high, medium, low ou none")
	scanCmd.Flags().StringVar(&logFormat, "log-format", "console", "formato de logs: console ou json")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "emite logs de diagnóstico")
	scanCmd.Flags().StringVar(&outputFormat, "format", "console", "formato do relatório: console ou sarif")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "arquivo de saída do relatório")
	rootCmd.AddCommand(scanCmd)
}

func writeReport(defaultWriter io.Writer, findings []scanner.Finding) error {
	writer := defaultWriter
	var file *os.File
	if outputFile != "" {
		createdFile, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		file = createdFile
		defer file.Close()
		writer = file
	}
	switch outputFormat {
	case "console":
		reporter.PrintConsole(writer, findings)
		return nil
	case "sarif":
		return reporter.WriteSARIF(writer, findings)
	default:
		return fmt.Errorf("invalid format %q: use console or sarif", outputFormat)
	}
}
