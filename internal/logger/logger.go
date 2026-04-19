package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	ExitSuccess      = 0
	ExitConfigError  = 1
	ExitNetworkError = 2
	ExitInterrupted  = 130
	ExitUnknownError = 99
)

var Log *zap.Logger

func InitLogger(logPath string) error {
	config := zap.NewProductionConfig()

	// Customizing the encoder for better readability in files
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	// Setup file output
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(config.EncoderConfig),
		zapcore.AddSync(file),
		zap.InfoLevel,
	)

	// Combine with console output
	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(config.EncoderConfig),
		zapcore.AddSync(os.Stdout),
		zap.InfoLevel,
	)

	Log = zap.New(zapcore.NewTee(core, consoleCore), zap.AddCaller())
	return nil
}

// Shutdown writes exit_code to the log and exits with code. We use Error (not
// zap.Fatal) because zap.Fatal always terminates with os.Exit(1), which would
// ignore non-1 exit codes such as ExitUnknownError (99).
func Shutdown(code int, message string) {
	Log.Error(message, zap.Int("exit_code", code))
	_ = Log.Sync()
	os.Exit(code)
}
