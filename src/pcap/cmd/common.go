package cmd

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudfoundry/pcap-release/src/pcap"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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

type CommonConfig struct {
	Listen   pcap.Listen     `yaml:"listen"`
	Buffer   pcap.BufferConf `yaml:"buffer"`
	LogLevel string          `yaml:"logLevel"`
	ID       string          `yaml:"id" validate:"required"`
}

// LoadTLSCredentials from the given Config. If CommonConfig.Listen.TLS is
// nil credentials which disable transport security will be used
// Note: the TLS version is currently hard-coded to TLSv1.3.
func LoadTLSCredentials(c CommonConfig) (credentials.TransportCredentials, error) {
	if c.Listen.TLS == nil {
		return insecure.NewCredentials(), nil
	}
	tls := c.Listen.TLS
	return pcap.LoadTLSCredentials(tls.Certificate, tls.PrivateKey, &tls.CertificateAuthority, nil, nil)
}

type genericStreamReceiver interface {
	Recv() (*pcap.CaptureResponse, error)
}

// ReadN reads a number of messages from stream
// TODO: Remove this when we have a proper CLI
func ReadN(n int, stream genericStreamReceiver) {
	for i := 0; i < n; i++ {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			zap.S().Infof("clean stop, done")
			return
		}
		code := status.Code(err)
		if code != codes.OK {
			zap.S().Infof("receive non-OK code: %s: %s\n", code.String(), err.Error())
			return
		}

		switch p := res.Payload.(type) {
		case *pcap.CaptureResponse_Message:
			zap.S().Infof("received message (%d/%d): %s: %s\n", i+1, n, p.Message.Type.String(), p.Message.Message)
		case *pcap.CaptureResponse_Packet:
			zap.S().Infof("received packet  (%d/%d): %d bytes\n", i+1, n, len(p.Packet.Data))
		}
	}
}

// WaitForSignal to tell the agent to stop processing any streams. Will first tell the agent
// to end any running streams, wait for them to terminate and gracefully stop the gRPC server
// afterwards. Currently listens for SIGUSR1 and SIGINT, SIGQUIT and SIGTERM.
func WaitForSignal(log *zap.Logger, stoppable pcap.Stoppable, server *grpc.Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	for {
		sig := <-signals
		switch sig {
		case syscall.SIGUSR1, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
			log.Info("received signal, stopping agent", zap.String("signal", sig.String()))
			stoppable.Stop()

			log.Info("waiting for stop")
			stoppable.Wait()

			log.Info("shutting down server")
			server.GracefulStop()
			return
		default:
			log.Warn("ignoring unknown signal", zap.String("signal", sig.String()))
		}
	}
}

func SetLogLevel(log *zap.Logger, logLevel string) {
	if level, levelErr := zap.ParseAtomicLevel(logLevel); levelErr == nil {
		zapConfig.Level.SetLevel(level.Level())
	} else {
		log.Warn("unable to parse log level", zap.Error(levelErr))
		log.Warn("remaining at default log level")
	}
}
