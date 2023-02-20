package integrationtests

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
	gopcap "github.com/google/gopacket/pcap"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
	var drainTimeout = 15 * time.Second
	var apiID = "123asd"
	var agentID1 = "router/1abc"
	var agentID2 = "router/2abc"
	var agentTarget1 pcap.AgentEndpoint
	var agentTarget2 pcap.AgentEndpoint
	var stop *pcap.CaptureRequest
	var defaultOptions *pcap.CaptureOptions
	var api *pcap.API

	Describe("Starting a capture", func() {
		BeforeEach(func() {
			var targets []pcap.AgentEndpoint
			//var target pcap.AgentEndpoint

			_, agentServer1, agentTarget1 = createAgent(8082, agentID1, nil)
			targets = append(targets, agentTarget1)

			_, agentServer2, agentTarget2 = createAgent(8083, agentID2, nil)
			targets = append(targets, agentTarget2)

			agentTLSConf := pcap.AgentMTLS{MTLS: &pcap.MutualTLS{SkipVerify: true}}
			apiBuffConf := pcap.BufferConf{Size: 200, UpperLimit: 198, LowerLimit: 180}
			apiClient, apiServer, api = createAPI(8080, targets, apiBuffConf, agentTLSConf, apiID, 2, drainTimeout)

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
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})
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
				Expect(code).To(Equal(codes.OK))

			})
			It("many concurrent captures from the same client", func() {
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"},
				}, defaultOptions)

				ctx := context.Background()
				streams := make([]pcap.API_CaptureClient, 2)
				for i := 0; i < 2; i++ {
					requestVcapID := uuid.Must(uuid.NewRandom()).String()
					ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{requestVcapID}})

					stream, _ := apiClient.Capture(ctx)
					streams[i] = stream

					err := stream.Send(request)
					Expect(err).NotTo(HaveOccurred(), "Sending the request")

					capture, messages, err := recvCapture(10, stream)
					Expect(err).NotTo(HaveOccurred(), "Receiving the first 10 messages")
					Expect(capture).NotTo(BeNil())
					Expect(messages).To(HaveLen(10))
				}

				requestVcapID := uuid.Must(uuid.NewRandom()).String()
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{requestVcapID}})

				streamLimitReached, _ := apiClient.Capture(ctx)
				err := streamLimitReached.Send(request)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				errCode, _, err := recvCapture(1, streamLimitReached)

				GinkgoWriter.Printf("\nError code: %v\n", errCode)
				Expect(errCode).To(Equal(codes.ResourceExhausted))

				for _, stream := range streams {
					err = stream.Send(stop)
					Expect(err).NotTo(HaveOccurred(), "Sending stop message")

					code, _, err := recvCapture(10_000, stream)
					Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")
					Expect(code).To(Equal(codes.OK))
				}
			})
			It("finished with errors due to invalid start capture request", func() {
				ctx := context.Background()
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})

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
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})

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

				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget2.Identifier)).To(BeTrue())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")
				code, _, err := recvCapture(10_000, stream)
				Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")
				Expect(code).To(Equal(codes.OK))

			})
			It("No pcap-agents available", func() {
				agentServer1.GracefulStop()
				agentServer2.GracefulStop()
				ctx := context.Background()
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})

				stream, err := apiClient.Capture(ctx)
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"}}, defaultOptions)

				err = stream.Send(request)
				Expect(err).NotTo(HaveOccurred())
				errCode, messages, err := recvCapture(10, stream)
				GinkgoWriter.Printf("Error code: %v\n", errCode)
				Expect(errCode).To(Equal(codes.FailedPrecondition))
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget1.Identifier)).To(BeTrue())
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget2.Identifier)).To(BeTrue())
			})
			It("One pcap-agent crashes", func() {
				ctx := context.Background()
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})

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
				GinkgoWriter.Printf("receive non-OK code: %s\n", errCode.String())
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget2.Identifier)).To(BeTrue())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")
				code, _, err := recvCapture(10_000, stream)
				Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")
				Expect(code).To(Equal(codes.OK))

			})
			It("One pcap-agent drains", func() {
				ctx := context.Background()
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})

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
				_, _, err = recvCapture(200, stream)
				Expect(err).NotTo(HaveOccurred())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")
				code, _, err := recvCapture(10_000, stream)
				Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")
				Expect(code).To(Equal(codes.OK))
			})
			It("api drains", func() {
				ctx := context.Background()
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})
				stream, _ := apiClient.Capture(ctx)
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"},
				}, defaultOptions)
				err := stream.Send(request)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				_, messages, err := recvCapture(10, stream)
				Expect(err).NotTo(HaveOccurred())
				Expect(messages).To(HaveLen(10), func() string { return fmt.Sprintf("Messages: %+v", messages) })

				go func() {
					GinkgoWriter.Printf("\ndraining\n")
					api.Drain()
				}()

				_, messages, err = recvCapture(50_000, stream)
				Expect(err).NotTo(HaveOccurred())
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_CAPTURE_STOPPED, agentTarget1.Identifier)).To(BeTrue())
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_CAPTURE_STOPPED, agentTarget2.Identifier)).To(BeTrue())
				statusResponse, err := apiClient.Status(ctx, &pcap.StatusRequest{})
				Expect(statusResponse.Healthy).To(BeFalse())

			})
		})
		Context("with one agent and one API", func() {
			BeforeEach(func() {
				agentServer1.GracefulStop()
			})
			It("pcap-agent crashes", func() {
				ctx := context.Background()
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})

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
				GinkgoWriter.Printf("receive non-OK code: %s\n", errCode.String())
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_INSTANCE_UNAVAILABLE, agentTarget1.Identifier)).To(BeTrue())
			})
		})
	})

	Describe("Staring a capture with an API with a smaller buffer", func() {
		BeforeEach(func() {
			var targets []pcap.AgentEndpoint
			//var target pcap.AgentEndpoint

			_, agentServer1, agentTarget1 = createAgent(8082, agentID1, nil)
			targets = append(targets, agentTarget1)

			_, agentServer2, agentTarget2 = createAgent(8083, agentID2, nil)
			targets = append(targets, agentTarget2)
			agentTLSConf := pcap.AgentMTLS{MTLS: &pcap.MutualTLS{SkipVerify: true}}
			apiBuffConf := pcap.BufferConf{Size: 7, UpperLimit: 6, LowerLimit: 4}
			apiClient, apiServer, _ = createAPI(8080, targets, apiBuffConf, agentTLSConf, apiID, 2, drainTimeout)

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
			It("pcap-api is congested", func() {
				ctx := context.Background()
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})

				stream, _ := apiClient.Capture(ctx)
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"}}, defaultOptions)

				err := stream.Send(request)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				errCode, messages, err := recvCapture(200, stream)
				GinkgoWriter.Printf("receive non-OK code: %s\n", errCode.String())
				Expect(err).NotTo(HaveOccurred())
				Expect(containsMsgTypeWithOrigin(messages, pcap.MessageType_CONGESTED, apiID)).To(BeTrue())
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")
				code, _, err := recvCapture(10_000, stream)
				Expect(err).ToNot(HaveOccurred(), "Receiving the remaining messages")
				Expect(code).To(Equal(codes.OK))

			})
		})

	})

	Describe("Staring a capture with an API with very small draining timeout", func() {
		BeforeEach(func() {
			var targets []pcap.AgentEndpoint
			//var target pcap.AgentEndpoint

			_, agentServer1, agentTarget1 = createAgent(8082, agentID1, nil)
			targets = append(targets, agentTarget1)

			_, agentServer2, agentTarget2 = createAgent(8083, agentID2, nil)
			targets = append(targets, agentTarget2)
			agentTLSConf := pcap.AgentMTLS{MTLS: &pcap.MutualTLS{SkipVerify: true}}
			apiBuffConf := pcap.BufferConf{Size: 100, UpperLimit: 98, LowerLimit: 90}
			drainTimeout = 0 * time.Millisecond
			apiClient, apiServer, api = createAPI(8080, targets, apiBuffConf, agentTLSConf, apiID, 2, drainTimeout)

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
			It("api drainTimeout exceeded", func() {
				ctx := context.Background()
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})
				stream, _ := apiClient.Capture(ctx)
				request := boshRequest(&pcap.BoshCapture{
					Token:      "123",
					Deployment: "cf",
					Groups:     []string{"router"},
				}, defaultOptions)
				err := stream.Send(request)
				Expect(err).NotTo(HaveOccurred(), "Sending the request")
				_, messages, err := recvCapture(10, stream)
				Expect(err).NotTo(HaveOccurred())
				Expect(messages).To(HaveLen(10), func() string { return fmt.Sprintf("Messages: %+v", messages) })

				err = api.Drain()
				Expect(err).To(BeEquivalentTo(context.DeadlineExceeded))

				_, _, err = recvCapture(50_000, stream)
				Expect(err).NotTo(HaveOccurred())
				statusResponse, err := apiClient.Status(ctx, &pcap.StatusRequest{})
				Expect(statusResponse.Healthy).To(BeFalse())

			})
		})

	})

	Describe("Starting a capture use mTLS", func() {
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

			_, agentServer1, target = createAgent(8082, agentID1, mTLSConfig)
			targets = append(targets, target)

			agentTLSConf := pcap.AgentMTLS{
				DefaultPort: 9494,
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
			apiClient, apiServer, _ = createAPI(8080, targets, apiBuffConf, agentTLSConf, agentID1, 2, drainTimeout)

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
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123abc"}})

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
				Expect(code).To(Equal(codes.OK))

			})
			It("without external vcapID finished without errors", func() {
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
				Expect(code).To(Equal(codes.OK))

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
	GinkgoWriter.Printf("create agent with listener  %s\n", lis.Addr())

	target := pcap.AgentEndpoint{IP: tcpAddr.IP.String(), Port: tcpAddr.Port, Identifier: id}
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

func createAPI(port int, targets []pcap.AgentEndpoint, bufconf pcap.BufferConf, mTLSConfig pcap.AgentMTLS, id string, maxConcurrentCaptures int, drainTimeout time.Duration) (pcap.APIClient, *grpc.Server, *pcap.API) {
	var server *grpc.Server
	api := pcap.NewAPI(bufconf, mTLSConfig, id, maxConcurrentCaptures, drainTimeout)
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
			return code, messages, fmt.Errorf("receive code: %s: %s\n", code.String(), err.Error())
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

// contains checks if a string is present in a slice
func containsMsgTypeWithOrigin(messages []*pcap.CaptureResponse, msgType pcap.MessageType, origin string) bool {
	for _, msg := range messages {
		if msg.GetPacket() == nil && msg.GetMessage().GetType() == msgType && msg.GetMessage().GetOrigin() == origin {
			return true
		}
	}

	return false
}
