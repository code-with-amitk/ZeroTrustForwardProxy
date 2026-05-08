package logging

import (
	"fmt"
	"os"
	"zerotrust-forward-proxy/utils"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func InitLogger() (*zap.SugaredLogger, error) {
	utils.GetFunctionName()

	var err error
	var config zap.Config
	var zapLogger *zap.Logger
	var logTo string
	var log_to string
	var logLevel zapcore.Level = zapcore.InfoLevel // Default INFO

	var loglevelFromEnv string
	loglevelFromEnv = os.Getenv("PROXY_LOG_LEVEL")
	fmt.Println("Proxy loglevelFromEnv: ", loglevelFromEnv)

	switch loglevelFromEnv {
	case "debug":
		logLevel = zapcore.DebugLevel
		fmt.Println("Log level set debug")
	// case "info":
	// 	logLevel = zapcore.InfoLevel
	case "warn":
		logLevel = zapcore.WarnLevel
	case "error":
		logLevel = zapcore.ErrorLevel
	case "dpanic":
		logLevel = zapcore.DPanicLevel
	case "panic":
		logLevel = zapcore.PanicLevel
	case "fatal":
		logLevel = zapcore.FatalLevel
	default:
		fmt.Println("Log Level not set in env file")
	}

	logTo = "stdout" // Default log on console.
	log_to = os.Getenv("APP_LOG_TO")
	if log_to != "" {
		logTo = log_to
	}
	fmt.Println("Application Logging to ", logTo)

	config = zap.Config{
		Level:       zap.NewAtomicLevelAt(logLevel),
		Development: true,   // Enable development mode for human-readable output
		Encoding:    "json", // Use JSON for structured logging (or "console" for text)
		//OutputPaths:      []string{"stdout"}, // Log to stdout
		//ErrorOutputPaths: []string{"stderr"}, // Errors to stderr
		OutputPaths:      []string{logTo}, // Log to stdout
		ErrorOutputPaths: []string{logTo}, // Errors to stderr
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:   "msg",
			LevelKey:     "level",
			TimeKey:      "time",
			EncodeLevel:  zapcore.LowercaseLevelEncoder,
			EncodeTime:   zapcore.ISO8601TimeEncoder,
			CallerKey:    "caller",
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}
	zapLogger, err = config.Build()
	return zapLogger.Sugar(), err
}
