//nolint:mnd // These test tools include a lot of magic numbers that are part of the test scenarios.
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	gopcap "github.com/gopacket/gopacket/pcap"
	. "github.com/onsi/ginkgo/v2" //nolint:revive,stylecheck // this is the common way to import ginkgo and gomega
	. "github.com/onsi/gomega"    //nolint:revive,stylecheck // this is the common way to import ginkgo and gomega
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// boshRequest prepares the properly contained gRPC request for bosh with options.
func boshRequest(bosh *pcap.BoshRequest, options *pcap.CaptureOptions) *pcap.CaptureRequest {
	return &pcap.CaptureRequest{
		Operation: &pcap.CaptureRequest_Start{
			Start: &pcap.StartCapture{
				Request: &pcap.EndpointRequest{
					Request: &pcap.EndpointRequest_Bosh{
						Bosh: bosh,
					},
				},
				Options: options,
			},
		},
	}
}

// findLoopback finds the first identified loopback interface.
func findLoopback() *gopcap.Interface {
	devs, err := gopcap.FindAllDevs()
	if err == nil {
		for _, dev := range devs {
			// find device with the loopback flag. Loopback devices are called differently on the various OSes.

			// libpcap/pcap/pcap.h
			// #define PCAP_IF_LOOPBACK				0x00000001	/* interface is loopback */
			if dev.Flags&0x00000001 > 0 {
				return &dev
			}
		}
	}
	zap.L().Panic("no loopback device found")
	return nil
}

// validatePcapFile validates the packets read from fileName via the function validate.
func validatePcapFile(fileName string, validate func([]gopacket.Packet)) {
	Expect(fileName).To(BeAnExistingFile())
	handle, err := gopcap.OpenOffline(fileName)
	Expect(err).ToNot(HaveOccurred())

	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Loop through packets in file
	var packets []gopacket.Packet
	for packet := range packetSource.Packets() {
		packets = append(packets, packet)
	}

	validate(packets)
}

// readAndExpectCleanEnd reads up to 1000 capture responses and expects an OK termination code.
func readAndExpectCleanEnd(stream pcap.API_CaptureClient) []*pcap.CaptureResponse {
	code, messages, err := recvCapture(10_000, stream)
	Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")
	Expect(code).To(Equal(codes.OK))

	return messages
}

func readAndExpectFirstMessages(stream pcap.API_CaptureClient) {
	statusCode, messages, err := recvCapture(10, stream)

	Expect(err).NotTo(HaveOccurred(), "Receiving the first 10 messages")
	Expect(statusCode).To(Equal(codes.OK))
	Expect(messages).To(HaveLen(10), func() string { return fmt.Sprintf("Messages: %+v", messages) })
}

func createStreamAndStartCapture(defaultOptions *pcap.CaptureOptions) (pcap.API_CaptureClient, error) {
	requestVcapID := uuid.Must(uuid.NewRandom()).String()

	var md = metadata.MD{pcap.HeaderVcapID.String(): []string{requestVcapID}}

	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, md)
	stream, err := apiClient.Capture(ctx)
	if stream == nil {
		return nil, err
	}

	request := boshRequest(&pcap.BoshRequest{
		Token:      "123",
		Deployment: "cf",
		Groups:     []string{"router"},
	}, defaultOptions)
	err = stream.Send(request)
	return stream, err
}

func generateCerts(commonName string, dir string) (string, string, string, error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Company, INC."},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 30),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caKey, _, caPEM, err := generateCertAndKey(ca, ca, nil)
	if err != nil {
		return "", "", "", err
	}

	// set up our server certificate
	dns := []string{commonName}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Company, INC."},
			Country:      []string{"US"},
			CommonName:   commonName,
		},
		DNSNames:     dns,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 30),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	_, certPrivKeyPEM, certPEM, err := generateCertAndKey(cert, ca, caKey)
	if err != nil {
		return "", "", "", err
	}

	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return "", "", "", err
	}

	certPath := path.Join(dir, "cert.pem")
	keyPath := path.Join(dir, "private.key")
	caPath := path.Join(dir, "ca.pem")
	err = os.WriteFile(certPath, certPEM.Bytes(), os.ModePerm)
	if err != nil {
		return "", "", "", err
	}

	err = os.WriteFile(keyPath, certPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return "", "", "", err
	}

	err = os.WriteFile(caPath, caPEM.Bytes(), os.ModePerm)
	if err != nil {
		return "", "", "", err
	}

	return certPath, keyPath, caPath, nil
}

func generateCertAndKey(cert *x509.Certificate, ca *x509.Certificate, issuerKey *rsa.PrivateKey) (*rsa.PrivateKey, *bytes.Buffer, *bytes.Buffer, error) {
	// create our private and public key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, err
	}

	if issuerKey == nil {
		issuerKey = privateKey
	}
	// create the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &privateKey.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// pem encode
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	privateKeyPEM := new(bytes.Buffer)
	err = pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return privateKey, privateKeyPEM, certPEM, nil
}

func configureServer(certFile string, keyFile string, clientCAFile string) (credentials.TransportCredentials, error) {
	tlsConf, err := (&pcap.ServerTLS{
		Certificate: certFile,
		PrivateKey:  keyFile,
		ClientCas:   clientCAFile,
		Verify:      tls.RequireAndVerifyClientCert,
	}).Config()
	return credentials.NewTLS(tlsConf), err
}

func createAgent(port int, id string, tlsCreds credentials.TransportCredentials) (*grpc.Server, pcap.AgentEndpoint, *pcap.Agent) {
	var err error
	var server *grpc.Server

	agent := pcap.NewAgent(pcap.BufferConf{Size: 10000, UpperLimit: 9800, LowerLimit: 8000}, id)

	listener := localNodeListener(port)
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	Expect(ok).To(BeTrue())
	GinkgoWriter.Printf("create agent with listener  %s\n", listener.Addr())

	target := pcap.AgentEndpoint{IP: tcpAddr.IP.String(), Port: tcpAddr.Port, Identifier: id}
	if tlsCreds != nil {
		server = grpc.NewServer(grpc.Creds(tlsCreds))
	} else {
		server = grpc.NewServer()
	}
	pcap.RegisterAgentServer(server, agent)
	go func() {
		err = server.Serve(listener)
		if err != nil {
			return
		}
	}()

	cc, err := grpc.Dial(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))

	Expect(err).NotTo(HaveOccurred())
	Expect(cc).ShouldNot(BeNil())

	_ = pcap.NewAgentClient(cc)
	return server, target, agent
}

func createAPI(resolver pcap.AgentResolver, bufConf pcap.BufferConf, mTLSConfig *pcap.ClientTLS, id string) (pcap.APIClient, *grpc.Server, *pcap.API, net.Addr) {
	var server *grpc.Server
	api, err := pcap.NewAPI(bufConf, mTLSConfig, id, MaxConcurrentCaptures)
	Expect(err).NotTo(HaveOccurred())

	api.RegisterResolver(resolver)

	listener := localNodeListener(APIPort)

	GinkgoWriter.Printf("create api with listener  %s\n", listener.Addr())

	server = grpc.NewServer()
	pcap.RegisterAPIServer(server, api)

	go func() {
		err = server.Serve(listener)
		if err != nil {
			GinkgoWriter.Printf("error occurred during api creation: %v", err)
		}
	}()

	cc, err := grpc.Dial(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	Expect(err).NotTo(HaveOccurred())

	client := pcap.NewAPIClient(cc)
	return client, server, api, listener.Addr()
}

func recvCapture(n int, stream pcap.API_CaptureClient) (codes.Code, []*pcap.CaptureResponse, error) {
	messages := make([]*pcap.CaptureResponse, 0, n)

	for i := 0; i < n; i++ {
		message, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			GinkgoWriter.Println("clean stop, done")
			return codes.OK, messages, nil
		}
		code := status.Code(err)
		if code != codes.OK {
			return code, messages, fmt.Errorf("receive code: %s: %w", code.String(), err)
		}
		messages = append(messages, message)
		logCaptureResponse(GinkgoWriter, message)
	}
	GinkgoWriter.Printf("done")
	return codes.OK, messages, nil
}

func logCaptureResponse(writer GinkgoWriterInterface, response *pcap.CaptureResponse) {
	if message := response.GetMessage(); message != nil {
		writer.Printf("\n{message: %s}\n", message)
	}

	if packet := response.GetPacket(); packet != nil {
		writer.Printf("{data: %d bytes} ", len(packet.GetData()))
	}
}

// containsMsgTypeWithOrigin checks if a string is present in a slice and with the given origin.
func containsMsgTypeWithOrigin(messages []*pcap.CaptureResponse, msgType pcap.MessageType, origin string) bool {
	for _, msg := range messages {
		if msg.GetPacket() == nil && msg.GetMessage().GetType() == msgType && msg.GetMessage().GetOrigin() == origin {
			return true
		}
	}

	return false
}

func NewMemoryMessageWriter() *MemoryMessageWriter {
	return &MemoryMessageWriter{Messages: make([]*pcap.Message, 0, 10)} //nolint:mnd // Default configuration
}

type MemoryMessageWriter struct {
	Messages []*pcap.Message
}

func (m *MemoryMessageWriter) WriteMessage(message *pcap.Message) {
	m.Messages = append(m.Messages, message)
}

func (m *MemoryMessageWriter) Filter(messageType pcap.MessageType) (result []*pcap.Message) {
	for _, msg := range m.Messages {
		if msg.Type == messageType {
			result = append(result, msg)
		}
	}
	return result
}
