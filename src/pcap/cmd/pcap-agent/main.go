// Package pcap-agent is the entry point for running the pcap-agent.
//
// Supported platforms are darwin and linux, either as arm64 or amd64 due to the os signals being used.
//go:build unix && (amd64 || arm64)

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
)

func init() {
	zap.ReplaceGlobals(zap.Must(zap.Config{
		Level:             zap.NewAtomicLevelAt(zap.DebugLevel),
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
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
		InitialFields:    map[string]interface{}{"component": "pcap-agent"}, // TODO: this is probably already done by syslog_shipper?
	}.Build()))

	zap.NewProductionEncoderConfig()
}

func main() {
	log := zap.L()
	log.Info("init phase done, starting agent", zap.Int64("compatibilityLevel", pcap.CompatibilityLevel))

	var err error
	var config Config
	switch len(os.Args) {
	case 1:
		config = DefaultConfig
	case 2:
		config, err = parseConfig(os.Args[1])
	default:
		err = fmt.Errorf("invalid number of arguments, expected 1 or 2 but got %d", len(os.Args))
	}
	if err != nil {
		log.Fatal("unable to load config", zap.Error(err))
	}

	err = config.validate()
	if err != nil {
		log.Fatal("unable to validate config", zap.Error(err))
	}

	agent := pcap.NewAgent(config.Buffer, config.ID)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Port))
	if err != nil {
		log.Fatal("unable to create listener", zap.Error(err))
	}

	tlsCredentials, err := loadTLSCredentials(config)
	if err != nil {
		log.Fatal("unable to load provided TLS credntials", zap.Error(err))
	}

	server := grpc.NewServer(grpc.Creds(tlsCredentials))
	pcap.RegisterAgentServer(server, agent)

	go waitForSignal(log, agent, server)

	log.Info("starting server")
	err = server.Serve(lis)
	if err != nil {
		log.Fatal("serve returned unsuccessfully", zap.Error(err))
	}

	log.Info("serve returned successfully")
}

// load server certificate and private key from the given Config. If Config.Tls is
// nil a credentials which disable transport security will be used
//
// Note: the TLS version is currently hard-coded to TLSv1.3.
func loadTLSCredentials(c Config) (credentials.TransportCredentials, error) {
	if c.Tls == nil {
		return insecure.NewCredentials(), nil
	}

	cert, err := tls.LoadX509KeyPair(c.Tls.Certificate, c.Tls.PrivateKey)
	if err != nil {
		return nil, err
	}

	caFile, err := os.ReadFile(c.Tls.CertificateAuthority)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()

	// We do not use x509.CertPool.AppendCertsFromPEM because it swallows any errors.
	// We would like to now if any certificate failed (and not just if any certificate
	// could be parsed).
	for len(caFile) > 0 {
		var block *pem.Block

		block, caFile = pem.Decode(caFile)
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("ca file contains non-certificate blocks")
		}

		ca, caErr := x509.ParseCertificate(block.Bytes)
		if caErr != nil {
			return nil, caErr
		}

		caPool.AddCert(ca)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}

	return credentials.NewTLS(tlsConf), nil
}

// waitForSignal to tell the agent to stop processing any streams. Will first tell the agent
// to end any running streams, wait for them to terminate and gracefully stop the gRPC server
// afterwards. Currently listens for SIGUSR1 and SIGINT.
func waitForSignal(log *zap.Logger, agent *pcap.Agent, server *grpc.Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGINT)
	for {
		sig := <-signals
		switch sig {
		case syscall.SIGUSR1, syscall.SIGINT:
			log.Info("received signal, stopping agent", zap.String("signal", sig.String()))
			agent.Stop()

			log.Info("waiting for agent to stop")
			agent.Wait()

			log.Info("shutting down server")
			server.GracefulStop()
			return
		default:
			log.Warn("ignoring unknown signal", zap.String("signal", sig.String()))
		}
	}
}
