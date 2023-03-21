package pcap

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var zapConfig zap.Config

func init() {
	zapConfig = zap.Config{
		Level:             zap.NewAtomicLevelAt(zap.InfoLevel),
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.RFC3339TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}
	zap.ReplaceGlobals(zap.Must(zapConfig.Build()))
}

func SetLogLevel(log *zap.Logger, logLevel string) {
	if level, levelErr := zap.ParseAtomicLevel(logLevel); levelErr == nil {
		zapConfig.Level.SetLevel(level.Level())
	} else {
		log.Warn("unable to parse log level, remaining at default log level", zap.Error(levelErr))
	}
}
