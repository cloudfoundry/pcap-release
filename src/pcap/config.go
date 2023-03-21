package pcap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TLS configures the server side of (m)TLS.
type TLS struct {
	// Certificate holds the path to the PEM encoded certificate (chain).
	Certificate string `yaml:"certificate" validate:"file"`
	// PrivateKey holds the path to the PEM encoded private key.
	PrivateKey string `yaml:"private_key" validate:"file"`
	// CertificateAuthority holds the path to the PEM encoded CA bundle which is used
	// to request and verify client certificates.
	CertificateAuthority string `yaml:"ca" validate:"file"`
}

// MutualTLS defines the client-side configuration for an mTLS connection.
//
// Certificate and PrivateKey are for the mTLS client certificate
// The CertificateAuthority is a file containing the server's CA that should be trusted when connecting to the server.
type MutualTLS struct {
	TLS `yaml:"-,inline"`
	// SkipVerify can disable the server certificate verification when connecting.
	SkipVerify bool `yaml:"skip_verify"`
	// CommonName is used as part of the certificate verification, together with CertificateAuthority.
	CommonName string `yaml:"common_name"`
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
	Port int  `yaml:"port" validate:"gt=0,lte=65535"`
	TLS  *TLS `yaml:"tls,omitempty"`
}

type NodeConfig struct {
	Listen   Listen     `yaml:"listen"`
	Buffer   BufferConf `yaml:"buffer"`
	LogLevel string     `yaml:"log_level"`
	ID       string     `yaml:"id" validate:"required"`
}

// TLSCredentials creates the necessary credentials from this Config. If NodeConfig.Listen.TLS is
// nil, credentials which disable transport security, will be used.
//
// Note: the TLS version is currently hard-coded to TLSv1.3.
func (c NodeConfig) TLSCredentials() (credentials.TransportCredentials, error) {
	if tls := c.Listen.TLS; tls != nil {
		// FIXME: peerCommonName should be known for mTLS?
		return LoadTLSCredentials(tls.Certificate, tls.PrivateKey, &tls.CertificateAuthority, nil, nil)
	}
	return insecure.NewCredentials(), nil

}

// LoadTLSCredentials creates TLS transport credentials from the given parameters.
func LoadTLSCredentials(certFile, keyFile string, caFile *string, peerCAFile *string, peerCommonName *string) (credentials.TransportCredentials, error) {
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate or private key failed: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	if caFile != nil {
		caPool, err := createCAPool(*caFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate authority file failed: %w", err)
		}
		tlsConf.ClientCAs = caPool
	}

	if peerCAFile != nil {
		caPool, err := createCAPool(*peerCAFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate authority file failed: %w", err)
		}
		tlsConf.RootCAs = caPool
	}

	if peerCommonName != nil {
		tlsConf.ServerName = *peerCommonName
	}

	return credentials.NewTLS(tlsConf), nil
}

func createCAPool(certificateAuthorityFile string) (*x509.CertPool, error) {
	caFile, err := os.ReadFile(certificateAuthorityFile)
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
	return caPool, nil
}
