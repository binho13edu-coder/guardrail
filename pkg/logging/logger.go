// Package logging configures structured GuardRail logs for local use and CI systems.
package logging

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func New(format string, verbose bool) (*zap.Logger, error) {
	level := zap.InfoLevel
	if verbose {
		level = zap.DebugLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	var encoder zapcore.Encoder
	switch format {
	case "json":
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	case "console":
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	default:
		return nil, fmt.Errorf("invalid log format %q: use console or json", format)
	}

	core := zapcore.NewCore(encoder, zapcore.AddSync(os.Stderr), level)
	return zap.New(core), nil
}
