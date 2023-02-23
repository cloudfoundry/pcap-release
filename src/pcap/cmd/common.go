package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"io"
	"os"
)

func InitZapLogger() {
	var zapConfig zap.Config

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
		//InitialFields:    map[string]interface{}{"component": "pcap-agent"}, // TODO: this is probably already done by syslog_shipper?
	}
	zap.ReplaceGlobals(zap.Must(zapConfig.Build()))

	zap.NewProductionEncoderConfig()
}

type CommonConfig struct {
	Listen   pcap.Listen     `yaml:"listen"`
	Buffer   pcap.BufferConf `yaml:"buffer"`
	LogLevel string          `yaml:"logLevel"`
	ID       string          `yaml:"id" validate:"required"`
}

// load server certificate and private key from the given Config. If Config.Tls is
// nil a credentials which disable transport security will be used
//
// Note: the TLS version is currently hard-coded to TLSv1.3.
func LoadTLSCredentials(c CommonConfig) (credentials.TransportCredentials, error) {
	if c.Listen.TLS == nil {
		return insecure.NewCredentials(), nil
	}

	cert, err := tls.LoadX509KeyPair(c.Listen.TLS.Certificate, c.Listen.TLS.PrivateKey)
	if err != nil {
		return nil, err
	}

	caFile, err := os.ReadFile(c.Listen.TLS.CertificateAuthority)
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

type genericStreamReceiver interface {
	Recv() (*pcap.CaptureResponse, error)
}

func ReadN(n int, stream genericStreamReceiver) {
	for i := 0; i < n; i++ {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			fmt.Println("clean stop, done")
			return
		}
		code := status.Code(err)
		if code != codes.OK {
			fmt.Printf("receive non-OK code: %s: %s\n", code.String(), err.Error())
			return
		}

		switch p := res.Payload.(type) {
		case *pcap.CaptureResponse_Message:
			fmt.Printf("received message (%d/%d): %s: %s\n", i+1, n, p.Message.Type.String(), p.Message.Message)
		case *pcap.CaptureResponse_Packet:
			fmt.Printf("received packet  (%d/%d): %d bytes\n", i+1, n, len(p.Packet.Data))
		}
	}
}

func P(err error) {
	if err != nil {
		panic(err.Error())
	}
}
