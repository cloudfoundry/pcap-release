package integration_tests

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

	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	gopcap "github.com/google/gopacket/pcap"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

var lis net.Listener

var apiClient pcap.APIClient

func boshRequest(bosh *pcap.BoshCapture, options *pcap.CaptureOptions) *pcap.CaptureRequest {
	return &pcap.CaptureRequest{
		Operation: &pcap.CaptureRequest_Start{
			Start: &pcap.StartCapture{
				Capture: &pcap.Capture{
					Capture: &pcap.Capture_Bosh{
						Bosh: bosh,
					},
				},
				Options: options,
			},
		},
	}
}

func findLoopback() (*gopcap.Interface, error) {
	devs, err := gopcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	for _, dev := range devs {
		// find device with the loopback flag. Loopback devices are called differently on the various OSes.

		// libpcap/pcap/pcap.h
		// #define PCAP_IF_LOOPBACK				0x00000001	/* interface is loopback */
		if dev.Flags&0x00000001 > 0 {
			return &dev, nil
		}
	}

	return nil, fmt.Errorf("no loopback device found")
}

var _ = Describe("IntegrationTests", func() {
	var agentServer1 *grpc.Server
	var agentServer2 *grpc.Server
	var apiServer *grpc.Server
	var apiID = "123asd"
	var agentID1 = "router/123asd"
	var agentID2 = "router/123asd"
	var stop *pcap.CaptureRequest
	var defaultOptions *pcap.CaptureOptions

	Describe("Starting a capture", func() {
		BeforeEach(func() {
			var targets []pcap.AgentEndpoint
			var target pcap.AgentEndpoint

			_, agentServer1, target = createAgent(8082, agentID1, nil)
			targets = append(targets, target)

			_, agentServer2, target = createAgent(8083, agentID2, nil)
			targets = append(targets, target)

			agentTLSConf := pcap.AgentTLSConf{AgentTLSSkipVerify: true}
			apiClient, apiServer = createAPI(8080, targets, nil, agentTLSConf, apiID)

			stop = &pcap.CaptureRequest{
				Operation: &pcap.CaptureRequest_Stop{},
			}

			loopback, err := findLoopback()
			Expect(err).ToNot(HaveOccurred())

			defaultOptions = &pcap.CaptureOptions{
				Device:  loopback.Name,
				Filter:  "",
				SnapLen: 65000,
			}
		})

		AfterEach(func() {
			agentServer1.GracefulStop()
			agentServer2.GracefulStop()
			apiServer.GracefulStop()
		})

		Context("with two agents and one API", func() {
			It("finished without errors", func() {
				ctx := context.Background()
				stream, _ := apiClient.Capture(ctx)
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"},
				}, defaultOptions)
				err := stream.Send(request)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				capture, messages, err := recvCapture(10, stream)
				Expect(err).NotTo(HaveOccurred(), "Receiving the first 10 messages")
				Expect(capture).NotTo(BeNil())
				Expect(messages).To(HaveLen(10), func() string { return fmt.Sprintf("Messages: %+v", messages) })
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")

				code, _, err := recvCapture(10_000, stream)
				Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")

				// FIXME: Should not be Unknown/EOF
				Expect(code).To(Equal(codes.Unknown))

			})
			It("finished with errors due to invalid start capture request", func() {
				ctx := context.Background()

				stream, err := apiClient.Capture(ctx)

				request := boshRequest(&pcap.BoshCapture{
					Token:  "123",
					Groups: []string{"router"},
				}, defaultOptions)

				err = stream.Send(request)

				Expect(err).NotTo(HaveOccurred())

				errCode, _, err := recvCapture(10, stream)
				Expect(errCode).To(Equal(codes.InvalidArgument))
			})
			It("one agent unavailable", func() {
				agentServer2.GracefulStop()
				ctx := context.Background()

				stream, err := apiClient.Capture(ctx)

				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"}},
					defaultOptions)
				err = stream.Send(request)
				Expect(err).NotTo(HaveOccurred())
				errCode, messages, err := recvCapture(10, stream)
				Expect(err).NotTo(HaveOccurred())
				Expect(errCode).To(Equal(codes.OK))
				Expect(containsMsgType(messages, pcap.MessageType_INSTANCE_UNAVAILABLE)).To(BeTrue())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")
				code, _, err := recvCapture(10_000, stream)
				Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")

				// FIXME: Should not be Unknown/EOF
				Expect(code).To(Equal(codes.Unknown))

			})
			It("No pcap-agents available", func() {
				agentServer1.GracefulStop()
				agentServer2.GracefulStop()
				ctx := context.Background()
				stream, err := apiClient.Capture(ctx)
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"}}, defaultOptions)

				err = stream.Send(request)
				Expect(err).NotTo(HaveOccurred())
				errCode, messages, err := recvCapture(10, stream)
				fmt.Print(errCode)
				Expect(errCode).To(Equal(codes.FailedPrecondition))
				//FixMe expected message type
				Expect(containsMsgType(messages, pcap.MessageType_START_CAPTURE_FAILED)).To(BeTrue())
			})
			It("One pcap-agent crashes", func() {
				ctx := context.Background()
				stream, _ := apiClient.Capture(ctx)
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"}}, defaultOptions)

				err := stream.Send(request)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				go func() {
					time.Sleep(1 * time.Second)
					agentServer2.Stop()
				}()
				time.Sleep(2 * time.Second)
				errCode, messages, err := recvCapture(500, stream)
				fmt.Printf("receive non-OK code: %s\n", errCode.String())
				//TODO change message type > instance disconnected
				Expect(containsMsgType(messages, pcap.MessageType_INSTANCE_UNAVAILABLE)).To(BeTrue())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")
				code, _, err := recvCapture(10_000, stream)
				Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")

				// FIXME: Should not be Unknown/EOF
				Expect(code).To(Equal(codes.Unknown))

			})
			It("One pcap-agent drains", func() {
				ctx := context.Background()
				stream, _ := apiClient.Capture(ctx)
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"}}, defaultOptions)

				err := stream.Send(request)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				go func() {
					time.Sleep(3 * time.Second)
					agentServer2.GracefulStop()
				}()
				time.Sleep(2 * time.Second)
				errCode, _, err := recvCapture(200, stream)
				fmt.Printf("receive non-OK code: %s\n", errCode.String())
				Expect(err).NotTo(HaveOccurred())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")
				code, _, err := recvCapture(10_000, stream)
				Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")

				// FIXME: Should not be Unknown/EOF
				Expect(code).To(Equal(codes.Unknown))

			})
			It("One pcap-agent is congested", func() {
				ctx := context.Background()
				stream, _ := apiClient.Capture(ctx)
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"}}, defaultOptions)

				err := stream.Send(request)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				errCode, messages, err := recvCapture(10000, stream)
				fmt.Printf("receive non-OK code: %s\n", errCode.String())
				Expect(err).NotTo(HaveOccurred())
				Expect(containsMsgType(messages, pcap.MessageType_CONGESTED)).To(BeTrue())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")
				code, _, err := recvCapture(10_000, stream)
				Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")

				// FIXME: Should not be Unknown/EOF
				Expect(code).To(Equal(codes.Unknown))

			})
		})
		Context("with one agent and one API", func() {
			BeforeEach(func() {
				agentServer1.GracefulStop()
			})
			It("pcap-agent crashes", func() {
				ctx := context.Background()
				stream, _ := apiClient.Capture(ctx)
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"}}, defaultOptions)

				err := stream.Send(request)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				go func() {
					time.Sleep(3 * time.Second)
					agentServer2.Stop()
				}()
				time.Sleep(3 * time.Second)
				errCode, messages, err := recvCapture(500, stream)
				//TODO check why it returns unknown
				//Expect(errCode).To(Equal(codes.Unavailable))
				fmt.Printf("receive non-OK code: %s\n", errCode.String())
				//TODO change message type > instance disconnected
				Expect(containsMsgType(messages, pcap.MessageType_INSTANCE_UNAVAILABLE)).To(BeTrue())
			})
		})
	})
	Describe("Starting a capture use mTLS", func() {
		BeforeEach(func() {
			var targets []pcap.AgentEndpoint
			var target pcap.AgentEndpoint
			agentID1 := "router/123asd"
			agentServerCertCN := "pcap-agent.service.cf.internal"
			certPath, keyPath, caPath, err := generateCerts(agentServerCertCN, "agent")
			Expect(err).ToNot(HaveOccurred())

			apiCertCN := "pcap-api.service.cf.internal"
			clientCertFile, clientKeyFile, clientCAFile, err := generateCerts(apiCertCN, "api")
			Expect(err).ToNot(HaveOccurred())

			mTLSConfig, err := configureServer(certPath, keyPath, clientCAFile)
			Expect(err).ToNot(HaveOccurred())

			_, agentServer1, target = createAgent(8082, agentID1, mTLSConfig)
			targets = append(targets, target)

			agentTLSConf := pcap.AgentTLSConf{AgentTLSSkipVerify: false, AgentCommonName: agentServerCertCN, AgentCA: caPath}
			clientCert := &pcap.ClientCert{ClientCertFile: clientCertFile, ClientPrivateKeyFile: clientKeyFile}

			apiClient, apiServer = createAPI(8080, targets, clientCert, agentTLSConf, agentID1)

			stop = &pcap.CaptureRequest{
				Operation: &pcap.CaptureRequest_Stop{},
			}

			loopback, err := findLoopback()
			Expect(err).ToNot(HaveOccurred())

			defaultOptions = &pcap.CaptureOptions{
				Device:  loopback.Name,
				Filter:  "",
				SnapLen: 65000,
			}
		})
		AfterEach(func() {
			agentServer1.GracefulStop()
			apiServer.GracefulStop()
			os.RemoveAll("api")
			os.RemoveAll("agent")
		})
		Context("with one agents and one API", func() {
			It("finished without errors", func() {
				ctx := context.Background()

				stream, _ := apiClient.Capture(ctx)

				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"},
				}, defaultOptions)
				err := stream.Send(request)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				capture, messages, err := recvCapture(10, stream)
				Expect(err).NotTo(HaveOccurred(), "Receiving the first 10 messages")
				Expect(capture).NotTo(BeNil())
				Expect(messages).To(HaveLen(10))
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")

				code, messages, err := recvCapture(10_000, stream)
				Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")

				// FIXME: Should not be Unknown/EOF
				Expect(code).To(Equal(codes.Unknown))

			})
		})
	})
})

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

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", "", err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return "", "", "", err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

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

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", "", err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return "", "", "", err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

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

func configureServer(certFile string, keyFile string, clientCAFile string) (credentials.TransportCredentials, error) {

	pemClientCA, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, err
	}

	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(pemClientCA)

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	return credentials.NewTLS(config), nil
}

func createAgent(port int, id string, tlsCreds credentials.TransportCredentials) (pcap.AgentClient, *grpc.Server, pcap.AgentEndpoint) {
	var server *grpc.Server
	agent := pcap.NewAgent(pcap.BufferConf{100, 98, 80}, id)

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	Expect(err).NotTo(HaveOccurred())
	tcpAddr, ok := lis.Addr().(*net.TCPAddr)
	Expect(ok).To(BeTrue())
	fmt.Printf("create agent with listener  %s\n", lis.Addr().String())

	target := pcap.AgentEndpoint{IP: tcpAddr.IP.String(), Port: tcpAddr.Port}
	server = grpc.NewServer()
	if tlsCreds != nil {
		server = grpc.NewServer(grpc.Creds(tlsCreds))
	} else {
		server = grpc.NewServer()
	}
	pcap.RegisterAgentServer(server, agent)
	go func() {
		server.Serve(lis)
	}()

	cc, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))

	Expect(err).NotTo(HaveOccurred())
	Expect(cc).ShouldNot(BeNil())

	agentClient := pcap.NewAgentClient(cc)
	return agentClient, server, target
}

func createAPI(port int, targets []pcap.AgentEndpoint, mTLSConfig *pcap.ClientCert, agentTLSConf pcap.AgentTLSConf, id string) (pcap.APIClient, *grpc.Server) {
	var server *grpc.Server
	api := pcap.NewAPI(pcap.BufferConf{Size: 100, UpperLimit: 98, LowerLimit: 80}, mTLSConfig, agentTLSConf, id)
	api.RegisterHandler(&pcap.BoshHandler{Config: pcap.ManualEndpoints{Targets: targets}})

	var err error
	lis, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	Expect(err).NotTo(HaveOccurred())

	server = grpc.NewServer()
	pcap.RegisterAPIServer(server, api)

	go func() {
		server.Serve(lis)
	}()

	cc, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	Expect(err).NotTo(HaveOccurred())

	client := pcap.NewAPIClient(cc)
	return client, server
}

func recvCapture(n int, stream pcap.API_CaptureClient) (codes.Code, []*pcap.CaptureResponse, error) {
	messages := make([]*pcap.CaptureResponse, 0, n)

	for i := 0; i < n; i++ {
		message, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			fmt.Println("EOF")
			return codes.Unknown, messages, nil
		}
		code := status.Code(err)
		if code != codes.OK {
			return code, messages, fmt.Errorf("receive code: %s: %s\n", code.String(), err.Error())
		}
		messages = append(messages, message)
	}
	return codes.OK, messages, nil
}

// contains checks if a string is present in a slice
func containsMsgType(messages []*pcap.CaptureResponse, msgType pcap.MessageType) bool {
	for _, msg := range messages {
		if msg.GetPacket() == nil && msg.GetMessage().GetType() == msgType {
			return true
		}
	}

	return false
}
