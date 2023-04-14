//nolint:gomnd // These tests include a lot of magic numbers that are part of the test scenarios.
package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/test/mock"

	"github.com/gopacket/gopacket"
	. "github.com/onsi/ginkgo/v2" //nolint:revive,stylecheck // this is the common way to import ginkgo and gomega
	. "github.com/onsi/gomega"    //nolint:revive,stylecheck // this is the common way to import ginkgo and gomega
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var apiClient pcap.APIClient

var MaxConcurrentCaptures uint = 2

// port is used for creating agents.
var port = 9494

var APIPort = 8080

func createAPIwithLocalResolver(targets []pcap.AgentEndpoint, bufConf pcap.BufferConf, mTLSConfig *pcap.MutualTLS, id string) (pcap.APIClient, *grpc.Server, *pcap.API, net.Addr) {
	resolver := NewLocalResolver(targets)
	return createAPI(resolver, bufConf, mTLSConfig, id)
}

var _ = Describe("Using LocalResolver", func() {
	var agentServer1 *grpc.Server
	var agentServer2 *grpc.Server
	var apiServer *grpc.Server
	var apiID = "pcap-api/1234-5678-9000"
	var agentID1 = "router/1abc"
	var agentID2 = "router/2abc"
	var agentTarget1 pcap.AgentEndpoint
	var agentTarget2 pcap.AgentEndpoint
	var defaultOptions *pcap.CaptureOptions
	var api *pcap.API
	var apiAddr net.Addr
	var agent1 *pcap.Agent
	loopback := findLoopback().Name

	Context("Starting a capture", func() {

		Context("with two agents and one API", func() {
			BeforeEach(func() {
				var targets []pcap.AgentEndpoint
				agentServer1, agentTarget1, agent1 = createAgent(9494, agentID1, nil)
				targets = append(targets, agentTarget1)

				agentServer2, agentTarget2, _ = createAgent(9494, agentID2, nil)
				targets = append(targets, agentTarget2)

				agentTLSConf := &pcap.MutualTLS{SkipVerify: true}
				apiBuffConf := pcap.BufferConf{Size: 200, UpperLimit: 198, LowerLimit: 180} //nolint:gomnd // Values for a test
				apiClient, apiServer, api, _ = createAPIwithLocalResolver(targets, apiBuffConf, agentTLSConf, apiID)

				defaultOptions = &pcap.CaptureOptions{
					Device:  loopback,
					Filter:  "",
					SnapLen: 65000, //nolint:gomnd // Value for a test
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

				err = stream.Send(pcap.MakeStopRequest())
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
					err = stream.Send(pcap.MakeStopRequest())
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
				err = stream.Send(pcap.MakeStopRequest())
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
				err = stream.Send(pcap.MakeStopRequest())
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

				err = stream.Send(pcap.MakeStopRequest())
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

				agentServer1, agentTarget1, agent1 = createAgent(port, agentID1, nil)
				targets = append(targets, agentTarget1)

				agentTLSConf := &pcap.MutualTLS{SkipVerify: true}
				apiBuffConf := pcap.BufferConf{Size: 100, UpperLimit: 98, LowerLimit: 90}
				apiClient, apiServer, _, _ = createAPIwithLocalResolver(targets, apiBuffConf, agentTLSConf, apiID)
				apiPort++

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

				agentServer1, agentTarget1, agent1 = createAgent(port, agentID1, nil)
				targets = append(targets, agentTarget1)

				agentServer2, agentTarget2, _ = createAgent(port, agentID2, nil)
				targets = append(targets, agentTarget2)
				agentTLSConf := &pcap.MutualTLS{SkipVerify: true}
				apiBuffConf := pcap.BufferConf{Size: 7, UpperLimit: 6, LowerLimit: 4}
				apiClient, apiServer, _, _ = createAPIwithLocalResolver(targets, apiBuffConf, agentTLSConf, apiID)
				apiPort++

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
				err = stream.Send(pcap.MakeStopRequest())
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

				agentServer1, target, agent1 = createAgent(port, agentID1, mTLSConfig)
				targets = append(targets, target)

				agentTLSConf := &pcap.MutualTLS{
					SkipVerify: false,
					CommonName: agentServerCertCN,
					TLS: pcap.TLS{
						Certificate: clientCertFile,
						PrivateKey:  clientKeyFile, CertificateAuthority: caPath,
					},
				}
				apiBuffConf := pcap.BufferConf{Size: 100, UpperLimit: 98, LowerLimit: 80}
				apiClient, apiServer, _, _ = createAPIwithLocalResolver(targets, apiBuffConf, agentTLSConf, agentID1)

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

				err = stream.Send(pcap.MakeStopRequest())

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
				err = stream.Send(pcap.MakeStopRequest())
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")

				_ = readAndExpectCleanEnd(stream)
			})
		})
	})

	Context("From client to agent", func() {

		BeforeEach(func() {

			var targets []pcap.AgentEndpoint

			agentServer1, agentTarget1, agent1 = createAgent(port, agentID1, nil)
			targets = append(targets, agentTarget1)

			agentTLSConf := &pcap.MutualTLS{SkipVerify: true}
			apiBuffConf := pcap.BufferConf{Size: 100000, UpperLimit: 99000, LowerLimit: 90000}
			apiClient, apiServer, api, apiAddr = createAPIwithLocalResolver(targets, apiBuffConf, agentTLSConf, apiID)

		})

		AfterEach(func() {
			agentServer1.GracefulStop()
			apiServer.GracefulStop()
		})
		Context("with client sending SIGINT after 5 seconds", func() {
			It("handles capture stop gracefully", func() {
				file := "bosh_e2e_integration_test.pcap"
				_ = os.Remove(file) // remove test-file

				logger, _ := zap.NewDevelopment(zap.IncreaseLevel(zap.InfoLevel))
				client, err := pcap.NewClient(file, logger, pcap.LogMessageWriter{Log: logger})
				Expect(err).To(BeNil())

				apiURL := mock.MustParseURL(fmt.Sprintf("http://%s", apiAddr.String()))
				err = client.ConnectToAPI(apiURL)
				Expect(err).To(BeNil())

				ctx := context.Background()
				ctx, cancel := context.WithCancelCause(ctx)

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
					GinkgoWriter.Println("sending Stop")
					client.StopRequest()
				}()

				err = client.ProcessCapture(ctx, endpointRequest, captureOptions, cancel)
				Expect(err).To(BeNil())
				validateAge := func(packets []gopacket.Packet) {
					maxAge := 10 * time.Second
					Expect(packets).ToNot(BeEmpty())

					firstTimestamp := packets[0].Metadata().Timestamp
					Expect(firstTimestamp).ToNot(BeNil())
					delta := time.Since(firstTimestamp)
					Expect(delta).To(BeNumerically("<", maxAge), "Expected %s to be %s before %s", firstTimestamp, maxAge, time.Now())
				}
				validatePcapFile(file, validateAge)
			})
		})
	})
})
