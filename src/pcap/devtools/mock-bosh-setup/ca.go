package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"time"
)

// Some helper tools to generate x509 CAs and Certificates

const RootCABits = 4096
const ServerCertBits = 2048
const ClientCertBits = 2048
const RootCASerial = 1337
const ServerCertSerial = 3141
const ClientCertSerial = 2718

type CA struct {
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
	CertPEM *bytes.Buffer
	KeyPEM  *bytes.Buffer
}

type ClientCert struct {
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
	CertPEM *bytes.Buffer
	KeyPEM  *bytes.Buffer
}

type ServerCert struct {
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
	CertPEM *bytes.Buffer
	KeyPEM  *bytes.Buffer
}

// certPEM returns a given x509 certificate binary in PEM format.
func certPEM(certBytes []byte) *bytes.Buffer {
	certPEM := new(bytes.Buffer)
	err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		panic(err)
	}
	return certPEM
}

// keyPEM returns a given RSA private key in PEM format.
func keyPEM(key *rsa.PrivateKey) *bytes.Buffer {
	keyPEM := new(bytes.Buffer)
	err := pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		panic(err)
	}
	return keyPEM
}

// writePem writes a pem to disk.
func writePem(filename string, pem *bytes.Buffer) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	_, _ = io.Copy(file, pem)
	return nil
}

// newCA creates a new CA for testing purposes.
func newCA(cn string) (*CA, error) {
	ca := &CA{}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(RootCASerial),
		Subject: pkix.Name{
			Organization:  []string{"Cloud Foundry"},
			Country:       []string{"DE"},
			Province:      []string{""},
			Locality:      []string{"Walldorf"},
			StreetAddress: []string{},
			PostalCode:    []string{},
			CommonName:    cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, RootCABits)
	if err != nil {
		return nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	caPEM := certPEM(caBytes)
	caPrivKeyPEM := keyPEM(caPrivKey)

	ca.Cert = cert
	ca.Key = caPrivKey
	ca.CertPEM = caPEM
	ca.KeyPEM = caPrivKeyPEM

	return ca, nil
}

// ClientCert issues a new client certificate signed by the given CA.
func (ca *CA) ClientCert(cn string) (*ClientCert, error) {
	clientCert := &ClientCert{}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(ClientCertSerial),
		Subject: pkix.Name{
			Organization:  ca.Cert.Subject.Organization,
			Country:       ca.Cert.Subject.Country,
			Province:      ca.Cert.Subject.Province,
			Locality:      ca.Cert.Subject.Locality,
			StreetAddress: ca.Cert.Subject.StreetAddress,
			PostalCode:    ca.Cert.Subject.PostalCode,
			CommonName:    cn,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, ClientCertBits)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.Cert, &certPrivKey.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}

	certPEM := certPEM(certBytes)
	keyPEM := keyPEM(certPrivKey)

	clientCert.CertPEM = certPEM
	clientCert.KeyPEM = keyPEM
	clientCert.Cert = cert
	clientCert.Key = certPrivKey

	return clientCert, nil
}

// ServerCert issues a new server certificate signed by the given CA.
func (ca *CA) ServerCert(cn string) (*ServerCert, error) {
	serverCert := &ServerCert{}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(ServerCertSerial),
		Subject: pkix.Name{
			Organization:  ca.Cert.Subject.Organization,
			Country:       ca.Cert.Subject.Country,
			Province:      ca.Cert.Subject.Province,
			Locality:      ca.Cert.Subject.Locality,
			StreetAddress: ca.Cert.Subject.StreetAddress,
			PostalCode:    ca.Cert.Subject.PostalCode,
			CommonName:    cn,
		},
		DNSNames:     []string{cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, ServerCertBits)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.Cert, &certPrivKey.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}

	certPEM := certPEM(certBytes)
	keyPEM := keyPEM(certPrivKey)

	serverCert.CertPEM = certPEM
	serverCert.KeyPEM = keyPEM
	serverCert.Cert = cert
	serverCert.Key = certPrivKey

	return serverCert, nil
}
