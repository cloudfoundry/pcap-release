package pcap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
)

// newTLSConfig is used to set common defaults on newly created TLS
// configurations.
func newTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
}

type ServerTLS struct {
	// Certificate holds the path to the PEM encoded certificate (chain) that
	// is presented by the client / server to its peer.
	Certificate string `yaml:"certificate" validate:"omitempty,file"`
	// PrivateKey is the private key matching the certificate.
	PrivateKey string `yaml:"private_key" validate:"omitempty,file"`
	ClientCas  string `yaml:"client_cas"`
	// Verify controls how the peer certificate is verified:
	//
	// 0: tls.NoClientCert
	//
	// 1: tls.RequestClientCert
	//
	// 2: tls.RequireAnyClientCert
	//
	// 3: tls.VerifyClientCertIfGiven
	//
	// 4: tls.RequireAndVerifyClientCert
	Verify tls.ClientAuthType `yaml:"verify"`
}

func (c *ServerTLS) Config() (*tls.Config, error) {
	if c == nil {
		return nil, fmt.Errorf("server TLS config must be non-nil")
	}

	tlsConf := newTLSConfig()

	cert, err := tls.LoadX509KeyPair(c.Certificate, c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load x509 key pair: %w", err)
	}
	tlsConf.Certificates = []tls.Certificate{cert}

	if c.ClientCas == "" && tlsConf.ClientAuth > 0 {
		return nil, fmt.Errorf("tls config: configuered client certificate authentication without client CA list")
	}

	if c.ClientCas == "" {
		// no mTLS
		return tlsConf, nil
	}

	// configure mTLS
	tlsConf.ClientAuth = c.Verify

	trustedCas, err := createCAPool(c.ClientCas)
	if err != nil {
		return nil, fmt.Errorf("create CA pool: %w", err)
	}
	tlsConf.ClientCAs = trustedCas

	return tlsConf, nil
}

type ClientTLS struct {
	// Certificate holds the path to the PEM encoded certificate (chain) that
	// is presented by the client / server to its peer.
	Certificate string `yaml:"certificate" validate:"omitempty,file"`
	// PrivateKey is the private key matching the certificate.
	PrivateKey string `yaml:"private_key" validate:"omitempty,file"`
	// RootCas holds the path to the PEM encoded CA bundle which
	// is used to validate the certificate presented by the server if acting as
	// the client.
	RootCas string `yaml:"ca" validate:"omitempty,file"`
	// SkipVerify can be set to disable verification of the peer certificate if
	// acting as the client.
	SkipVerify bool `yaml:"skip_verify"`
	// ServerName that the certificate presented by the server must be signed
	// for.
	ServerName string `yaml:"server_name"`
}

func (c *ClientTLS) Config() (*tls.Config, error) {
	tlsConf := newTLSConfig()
	if c == nil {
		return tlsConf, nil
	}

	if c.Certificate != "" || c.PrivateKey != "" {
		cert, err := tls.LoadX509KeyPair(c.Certificate, c.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("load x509 key pair: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	tlsConf.InsecureSkipVerify = c.SkipVerify

	if c.RootCas != "" {
		trustedCas, err := createCAPool(c.RootCas)
		if err != nil {
			return nil, fmt.Errorf("create CA pool: %w", err)
		}
		tlsConf.RootCAs = trustedCas
	}

	return tlsConf, nil
}

// BufferConf allows to specify the behaviour of buffers.
//
// The recommendation is to set the upper limit slightly below the size
// to account for data put into the buffer while checking the fill condition
// or performing work. The lower limit should be low enough to make some room
// for new data but not too low (which would cause a lot of data to be
// discarded). After all the buffer should mainly soften short spikes in data
// transfer and these limits only protect against uncontrolled back pressure.
type BufferConf struct {
	// Size is the number of responses that can be buffered per stream.
	Size int `yaml:"size" validate:"gte=0"`
	// UpperLimit tells the manager of the buffer to start discarding messages
	// once the limit is exceeded. The condition looks like this:
	//   len(buf) >= UpperLimit
	UpperLimit int `yaml:"upper_limit" validate:"gte=0,ltefield=Size"`
	// LowerLimit tells the manager of the buffer to stop discarding messages
	// once the limit is reached/undercut. The condition looks like this:
	//   len(buf) <= LowerLimit
	LowerLimit int `yaml:"lower_limit" validate:"gte=0,ltefield=UpperLimit"`
}

// Listen defines the port and optional TLS configuration for the listening socket.
type Listen struct {
	Port int        `yaml:"port" validate:"gt=0,lte=65535"`
	TLS  *ServerTLS `yaml:"tls,omitempty"`
}

type NodeConfig struct {
	Listen   Listen     `yaml:"listen"`
	Buffer   BufferConf `yaml:"buffer"`
	LogLevel string     `yaml:"log_level"`
	ID       string     `yaml:"id" validate:"required"`
}

func createCAPool(certificateAuthorityFile string) (*x509.CertPool, error) {
	caFile, err := os.ReadFile(certificateAuthorityFile)
	if err != nil {
		return nil, err
	}

	// remove all empty lines so pem.Decode can parse the file
	re := regexp.MustCompile(`(?m)^\s*$[\r\n]*`)
	blocks := re.ReplaceAll(caFile, []byte{})

	caPool := x509.NewCertPool()

	// We do not use x509.CertPool.AppendCertsFromPEM because it swallows any errors.
	// We would like to know if any certificate failed (and not just if any certificate
	// could be parsed).
	for len(blocks) > 0 {
		var block *pem.Block

		block, blocks = pem.Decode(blocks)
		if block == nil {
			return nil, fmt.Errorf("could not parse ca-file %s: %v", certificateAuthorityFile, blocks)
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("ca file contains non-certificate blocks")
		}

		ca, caErr := x509.ParseCertificate(block.Bytes)
		if caErr != nil {
			return nil, caErr
		}

		caPool.AddCert(ca)
	}
	return caPool, nil
}
