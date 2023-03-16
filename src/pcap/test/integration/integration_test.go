package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path"
	"time"

	"github.com/google/gopacket"
	gopcap "github.com/google/gopacket/pcap"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/test"
)

var apiClient pcap.APIClient

var MaxConcurrentCaptures = 2

var port = 8110 // used for various server listen ports, automatically incremented

var APIPort = 8080

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
	log.Panic("no loopback device found")
	return nil
}

var _ = Describe("Using LocalResolver", func() {
	var agentServer1 *grpc.Server
	var agentServer2 *grpc.Server
	var apiServer *grpc.Server
	var apiID = "123asd"
	var agentID1 = "router/1abc"
	var agentID2 = "router/2abc"
	var agentTarget1 pcap.AgentEndpoint
	var agentTarget2 pcap.AgentEndpoint
	var stop *pcap.CaptureRequest
	var defaultOptions *pcap.CaptureOptions
	var api *pcap.API
	var agent1 *pcap.Agent
	loopback := findLoopback().Name

	Context("Starting a capture", func() {

		Context("with two agents and one API", func() {
			BeforeEach(func() {
				var targets []pcap.AgentEndpoint
				agentServer1, agentTarget1, agent1 = createAgent(nextFreePort(), agentID1, nil) //fixme: The BoshResolver can't support agent-specific Ports, as that information is not returned by the bosh director. We need to find another way to integration test multiple agents
				targets = append(targets, agentTarget1)

				agentServer2, agentTarget2, _ = createAgent(nextFreePort(), agentID2, nil)
				targets = append(targets, agentTarget2)

				agentTLSConf := pcap.AgentMTLS{MTLS: &pcap.MutualTLS{SkipVerify: true}}
				apiBuffConf := pcap.BufferConf{Size: 200, UpperLimit: 198, LowerLimit: 180}
				apiClient, apiServer, api = createAPI(targets, apiBuffConf, agentTLSConf, apiID)

				stop = &pcap.CaptureRequest{
					Operation: &pcap.CaptureRequest_Stop{},
				}

				defaultOptions = &pcap.CaptureOptions{
					Device:  loopback,
					Filter:  "",
					SnapLen: 65000,
				}
			})

			AfterEach(func() {
				agentServer1.GracefulStop()
				agentServer2.GracefulStop()
				apiServer.GracefulStop()
			})
			It("finished without errors", func() {
				stream, err := createStreamAndStartCapture(defaultOptions)

				Expect(err).NotTo(HaveOccurred(), "Sending the request")

				readAndExpectFirstMessages(stream)

				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")

				_ = readAndExpectCleanEnd(stream)
			})
			It("many concurrent captures from the same client", func() {
				streams := make([]pcap.API_CaptureClient, 2)
				for i := 0; i < 2; i++ {
					stream, err := createStreamAndStartCapture(defaultOptions)

					Expect(err).NotTo(HaveOccurred(), "Sending the request")
					streams[i] = stream

					readAndExpectFirstMessages(stream)
				}

				streamLimitReached, err := createStreamAndStartCapture(defaultOptions)

				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				errCode, _, err := recvCapture(1, streamLimitReached)
				Expect(err).To(HaveOccurred())
				Expect(errCode).To(Equal(codes.ResourceExhausted))

				for _, stream := range streams {
					err = stream.Send(stop)
					Expect(err).NotTo(HaveOccurred(), "Sending stop message")

					_ = readAndExpectCleanEnd(stream)
				}
			})

			It("one agent unavailable", func() {
				agentServer2.GracefulStop()

				stream, err := createStreamAndStartCapture(defaultOptions)

				Expect(err).NotTo(HaveOccurred())

				errCode, messages, _ := recvCapture(10, stream)
				Expect(errCode).To(Equal(codes.OK))

				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget2.Identifier)).To(BeTrue())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")
				_ = readAndExpectCleanEnd(stream)
			})
			It("No pcap-agents available", func() {
				agentServer1.GracefulStop()
				agentServer2.GracefulStop()

				stream, err := createStreamAndStartCapture(defaultOptions)

				Expect(err).NotTo(HaveOccurred())
				errCode, messages, err := recvCapture(10, stream)
				Expect(err).To(HaveOccurred(), "Error occurred due to failed precondition")
				Expect(errCode).To(Equal(codes.FailedPrecondition))
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget1.Identifier)).To(BeTrue())
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget2.Identifier)).To(BeTrue())
			})
			It("One pcap-agent crashes", func() {
				stream, err := createStreamAndStartCapture(defaultOptions)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")

				readAndExpectFirstMessages(stream)

				go func() {
					agentServer2.Stop()
				}()

				code, messages, _ := recvCapture(500, stream)
				Expect(code).To(Equal(codes.OK))
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget2.Identifier)).To(BeTrue())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")

				_ = readAndExpectCleanEnd(stream)
			})
			It("One pcap-agent drains", func() {
				stream, err := createStreamAndStartCapture(defaultOptions)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")

				readAndExpectFirstMessages(stream)

				go func() {
					agent1.Stop()
					agent1.Wait()
				}()

				_, messages, _ := recvCapture(500, stream)
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget1.Identifier)).To(BeTrue())

				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")

				messages = readAndExpectCleanEnd(stream)
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_CAPTURE_STOPPED, agentTarget2.Identifier)).To(BeTrue())
			})
			It("api drains", func() {
				stream, err := createStreamAndStartCapture(defaultOptions)

				Expect(err).NotTo(HaveOccurred(), "Sending the request")

				readAndExpectFirstMessages(stream)

				go func() {
					api.Stop()
					api.Wait()
				}()

				time.Sleep(1 * time.Second)
				_, messages, _ := recvCapture(100_000, stream)

				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_CAPTURE_STOPPED, agentTarget1.Identifier)).To(BeTrue())
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_CAPTURE_STOPPED, agentTarget2.Identifier)).To(BeTrue())

				statusResponse, err := apiClient.Status(context.Background(), &pcap.StatusRequest{})
				Expect(err).ToNot(HaveOccurred())
				Expect(statusResponse.Healthy).To(BeFalse())

			})
		})

		Context("with one agent and one API", func() {
			var apiPort = 8090
			BeforeEach(func() {
				var targets []pcap.AgentEndpoint

				agentServer1, agentTarget1, agent1 = createAgent(nextFreePort(), agentID1, nil)
				targets = append(targets, agentTarget1)

				agentTLSConf := pcap.AgentMTLS{MTLS: &pcap.MutualTLS{SkipVerify: true}}
				apiBuffConf := pcap.BufferConf{Size: 100, UpperLimit: 98, LowerLimit: 90}
				apiClient, apiServer, _ = createAPI(targets, apiBuffConf, agentTLSConf, apiID)
				apiPort++

				stop = &pcap.CaptureRequest{
					Operation: &pcap.CaptureRequest_Stop{},
				}

				defaultOptions = &pcap.CaptureOptions{
					Device:  loopback,
					Filter:  "",
					SnapLen: 65000,
				}
			})

			AfterEach(func() {
				agentServer1.GracefulStop()
				apiServer.GracefulStop()
			})
			It("pcap-agent crashes", func() {
				stream, err := createStreamAndStartCapture(defaultOptions)

				Expect(err).NotTo(HaveOccurred(), "Sending the request")

				readAndExpectFirstMessages(stream)

				go func() {
					agentServer1.Stop()
				}()

				errCode, messages, err := recvCapture(10_000, stream)
				Expect(err).To(HaveOccurred(), "Error occurred due to agent crash")
				Expect(errCode).To(Equal(codes.Aborted))
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget1.Identifier)).To(BeTrue())
			})
		})

		Context("with two agents and one API and a smaller buffer", func() {
			var apiPort = 8090
			BeforeEach(func() {
				var targets []pcap.AgentEndpoint

				agentServer1, agentTarget1, agent1 = createAgent(nextFreePort(), agentID1, nil)
				targets = append(targets, agentTarget1)

				agentServer2, agentTarget2, _ = createAgent(nextFreePort(), agentID2, nil)
				targets = append(targets, agentTarget2)
				agentTLSConf := pcap.AgentMTLS{MTLS: &pcap.MutualTLS{SkipVerify: true}}
				apiBuffConf := pcap.BufferConf{Size: 7, UpperLimit: 6, LowerLimit: 4}
				apiClient, apiServer, _ = createAPI(targets, apiBuffConf, agentTLSConf, apiID)
				apiPort++

				stop = &pcap.CaptureRequest{
					Operation: &pcap.CaptureRequest_Stop{},
				}

				defaultOptions = &pcap.CaptureOptions{
					Device:  loopback,
					Filter:  "",
					SnapLen: 65000,
				}
			})

			AfterEach(func() {
				agentServer1.GracefulStop()
				agentServer2.GracefulStop()
				apiServer.GracefulStop()
			})
			It("pcap-api is congested", func() {
				stream, err := createStreamAndStartCapture(defaultOptions)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")

				errCode, messages, err := recvCapture(200, stream)
				GinkgoWriter.Printf("receive non-OK code: %s\n", errCode.String())
				Expect(err).NotTo(HaveOccurred())
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_CONGESTED, apiID)).To(BeTrue())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")

				_ = readAndExpectCleanEnd(stream)
			})
		})

		Context("using mTLS with one agents and one API", func() {
			BeforeEach(func() {
				var targets []pcap.AgentEndpoint
				var target pcap.AgentEndpoint
				agentServerCertCN := "pcap-agent.service.cf.internal"
				certPath, keyPath, caPath, err := generateCerts(agentServerCertCN, "agent")
				Expect(err).ToNot(HaveOccurred())

				apiCertCN := "pcap-api.service.cf.internal"
				clientCertFile, clientKeyFile, clientCAFile, err := generateCerts(apiCertCN, "api")
				Expect(err).ToNot(HaveOccurred())

				mTLSConfig, err := configureServer(certPath, keyPath, clientCAFile)
				Expect(err).ToNot(HaveOccurred())

				agentServer1, target, agent1 = createAgent(nextFreePort(), agentID1, mTLSConfig)
				targets = append(targets, target)

				agentTLSConf := pcap.AgentMTLS{
					MTLS: &pcap.MutualTLS{
						SkipVerify: false,
						CommonName: agentServerCertCN,
						TLS: pcap.TLS{
							Certificate: clientCertFile,
							PrivateKey:  clientKeyFile, CertificateAuthority: caPath,
						},
					},
				}
				apiBuffConf := pcap.BufferConf{Size: 100, UpperLimit: 98, LowerLimit: 80}
				apiClient, apiServer, _ = createAPI(targets, apiBuffConf, agentTLSConf, agentID1)

				stop = &pcap.CaptureRequest{
					Operation: &pcap.CaptureRequest_Stop{},
				}

				defaultOptions = &pcap.CaptureOptions{
					Device:  loopback,
					Filter:  "",
					SnapLen: 65000,
				}
			})
			AfterEach(func() {
				var err error
				agentServer1.GracefulStop()
				apiServer.GracefulStop()

				err = os.RemoveAll("api")
				Expect(err).ToNot(HaveOccurred())

				err = os.RemoveAll("agent")
				Expect(err).ToNot(HaveOccurred())
			})
			It("finished without errors", func() {
				stream, err := createStreamAndStartCapture(defaultOptions)

				Expect(err).NotTo(HaveOccurred(), "Sending the request")

				readAndExpectFirstMessages(stream)

				err = stream.Send(stop)

				Expect(err).NotTo(HaveOccurred(), "Sending stop message")

				_ = readAndExpectCleanEnd(stream)
			})
			It("without external vcapID finished without errors", func() {
				ctx := context.Background()
				stream, _ := apiClient.Capture(ctx)

				request := boshRequest(&pcap.BoshRequest{
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

				_ = readAndExpectCleanEnd(stream)
			})
		})
	})

	Context("From client to agent", func() {

		BeforeEach(func() {

			var targets []pcap.AgentEndpoint

			agentServer1, agentTarget1, agent1 = createAgent(nextFreePort(), agentID1, nil)
			targets = append(targets, agentTarget1)

			agentTLSConf := pcap.AgentMTLS{MTLS: &pcap.MutualTLS{SkipVerify: true}}
			apiBuffConf := pcap.BufferConf{Size: 100, UpperLimit: 98, LowerLimit: 90}
			apiClient, apiServer, api = createAPI(targets, apiBuffConf, agentTLSConf, apiID)

		})

		AfterEach(func() {
			agentServer1.GracefulStop()
			apiServer.GracefulStop()
		})
		Context("with client sending SIGINT after 5 seconds", func() {
			It("handles capture stop gracefully", func() {
				file := "bosh_e2e_integration_test.pcap"
				_ = os.Remove(file) // remove test-file

				logger, _ := zap.NewDevelopment()
				client, err := pcap.NewClient(file, logger)
				Expect(err).To(BeNil())
				apiURL := test.MustParseURL(fmt.Sprintf("http://localhost:%d", APIPort))
				err = client.ConnectToAPI(apiURL)
				Expect(err).To(BeNil())

				ctx := context.Background()
				ctx, cancel := pcap.WithCancelCause(ctx)

				endpointRequest := &pcap.EndpointRequest{
					Request: &pcap.EndpointRequest_Bosh{
						Bosh: &pcap.BoshRequest{
							Token:      "",
							Deployment: "",
							Groups:     []string{""},
						},
					},
				}

				captureOptions := &pcap.CaptureOptions{
					Device:  findLoopback().Name,
					Filter:  "",
					SnapLen: 65000,
				}

				go func() {
					time.Sleep(5 * time.Second)
					fmt.Printf("sending cancel\n")
					cancel(nil)
				}()

				err = client.HandleRequest(ctx, endpointRequest, captureOptions, cancel)
				Expect(err).To(BeNil())

				validatePcapFile(file)
			})
		})

	})

})

func validatePcapFile(fileName string) {
	Expect(fileName).To(BeAnExistingFile())
	handle, err := gopcap.OpenOffline(fileName)
	Expect(err).To(BeNil())

	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Loop through packets in file
	var packets []gopacket.Packet
	for packet := range packetSource.Packets() {
		packets = append(packets, packet)
	}

	Expect(packets).ToNot(BeEmpty())

	actualTimestamp := packets[0].Metadata().Timestamp
	Expect(actualTimestamp).ToNot(BeNil())
	delta := time.Since(actualTimestamp)
	Expect(delta).To(BeNumerically(">", 5*time.Second))

	//transportLayer := packets[0].TransportLayer()
	//dstPort := transportLayer.TransportFlow().Dst().String()
	//if dstPort != "80" {
	//	t.Errorf("unexpected destination port %v", dstPort)
	//}
}

// readAndExpectCleanEnd reads up to 1000 capture responses and expects an OK termination code.
func readAndExpectCleanEnd(stream pcap.API_CaptureClient) []*pcap.CaptureResponse {
	code, messages, err := recvCapture(10_000, stream)
	Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")
	Expect(code).To(Equal(codes.OK))

	return messages
}

func nextFreePort() int {
	port++
	return port
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
	return pcap.LoadTLSCredentials(certFile, keyFile, &clientCAFile, nil, nil)
}

func createAgent(port int, id string, tlsCreds credentials.TransportCredentials) (*grpc.Server, pcap.AgentEndpoint, *pcap.Agent) {
	var err error
	var server *grpc.Server

	agent := pcap.NewAgent(pcap.BufferConf{Size: 100, UpperLimit: 98, LowerLimit: 80}, id)

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	Expect(err).NotTo(HaveOccurred())
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

func createAPI(targets []pcap.AgentEndpoint, bufConf pcap.BufferConf, mTLSConfig pcap.AgentMTLS, id string) (pcap.APIClient, *grpc.Server, *pcap.API) {
	var server *grpc.Server
	api, err := pcap.NewAPI(bufConf, mTLSConfig, id, MaxConcurrentCaptures)
	Expect(err).NotTo(HaveOccurred())

	resolver := NewLocalResolver(targets)
	api.RegisterResolver(resolver)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", APIPort))
	Expect(err).NotTo(HaveOccurred())
	GinkgoWriter.Printf("create api with listener  %s\n", lis.Addr())

	server = grpc.NewServer()
	pcap.RegisterAPIServer(server, api)

	go func() {
		err = server.Serve(lis)
		if err != nil {
			GinkgoWriter.Printf("error occurred during api creation: %v", err)
		}
	}()

	cc, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	Expect(err).NotTo(HaveOccurred())

	client := pcap.NewAPIClient(cc)
	return client, server, api
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

// contains checks if a string is present in a slice.
func containsMsgTypeWithOrigin(messages []*pcap.CaptureResponse, msgType pcap.MessageType, origin string) bool {
	for _, msg := range messages {
		if msg.GetPacket() == nil && msg.GetMessage().GetType() == msgType && msg.GetMessage().GetOrigin() == origin {
			return true
		}
	}

	return false
}
