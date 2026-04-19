package main

import (
	"cf-knife/cmd"
	"cf-knife/internal/logger"
	"fmt"
	"runtime/debug"

	"go.uber.org/zap"
)

func main() {
	if err := logger.InitLogger("cf-knife.log"); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		return
	}
	logger.Log.Info("cf-knife started", zap.String("version", cmd.Version))
	defer logger.Log.Sync()

	defer func() {
		if r := recover(); r != nil {
			logger.Log.Error("Recovered from panic",
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())),
			)
			logger.Shutdown(logger.ExitUnknownError, "Application crashed due to unexpected panic")
		}
	}()

	cmd.Execute()
}
