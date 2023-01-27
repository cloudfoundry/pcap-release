package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
		InitialFields:    map[string]interface{}{"component": "pcap-api"}, // TODO: this is probably already done by syslog_shipper?
	}.Build()))

	zap.NewProductionEncoderConfig()
}

func main() {
	log := zap.L()
	log.Info("init phase done, starting api")

	var err error
	var config = DefaultAPIConfig
	switch len(os.Args) {
	case 1:
		config = DefaultAPIConfig
	case 2:
		config, err = parseAPIConfig(os.Args[1])
	default:
		err = fmt.Errorf("invalid number of arguments, expected 1 or 2 but got %d", len(os.Args))
	}

	err = config.validate()
	if err != nil {
		log.Fatal("unable to validate config", zap.Error(err))
	}

	api, err := pcap.NewAPI(log, config.Buffer, pcap.APIConf{[]string{"localhost:8083"}})
	if err != nil {
		log.Fatal("unable to create api", zap.Error(err))
	}

	lis, err := listen(config)
	if err != nil {
		log.Fatal("unable to create listener", zap.Error(err))
	}
	server := grpc.NewServer()
	pcap.RegisterAPIServer(server, api)

	go waitForSignal(log, api, server)

	log.Info("starting server")
	err = server.Serve(lis)
	if err != nil {
		log.Fatal("serve returned unsuccessfully", zap.Error(err))
	}

	log.Info("serve returned successfully")
}

// listen creates a new listener based off of the given Config. If Config.TLS is
// nil a TCP listener is returned, otherwise a TLS listener is returned.
//
// Note: the TLS version is currently hard-coded to TLSv1.3.
func listen(c APIConfig) (net.Listener, error) {
	if c.TLS == nil {
		return net.Listen("tcp", fmt.Sprintf(":%d", c.Port))
	}

	cert, err := tls.LoadX509KeyPair(c.TLS.Certificate, c.TLS.PrivateKey)
	if err != nil {
		return nil, err
	}

	caFile, err := os.ReadFile(c.TLS.CertificateAuthority)
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

		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		caPool.AddCert(ca)
	}

	tlsConf := tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}

	return tls.Listen("tcp", fmt.Sprintf(":%d", c.Port), &tlsConf)
}

func waitForSignal(log *zap.Logger, api *pcap.API, server *grpc.Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGINT)
	for {
		sig := <-signals
		switch sig {
		case syscall.SIGUSR1, syscall.SIGINT:
			/*log.Info("received signal, stopping agent", zap.String("signal", sig.String()))
			api.Stop()

			log.Info("waiting for agent to stop")
			api.Wait()*/

			log.Info("shutting down server")
			server.GracefulStop()
			return
		default:
			log.Warn("ignoring unknown signal", zap.String("signal", sig.String()))
		}
	}
}
