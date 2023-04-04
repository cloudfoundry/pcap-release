package integration

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/test/mock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// Start API with BOSH resolver and
// - wrong config
// - correct config
// Start API with BOSH resolver and start capturing
// - one node
//   - without token
//   - with wrong token
//   - with correct token
// - two nodes
// everything with a client requesting things and checking that the response messages or pcap files are as expected.
// TODO: test for MTLS

var _ = Describe("Client to API with Bosh Resolver", func() {
	var agentServer1 *grpc.Server
	var agentServer2 *grpc.Server
	var apiServer *grpc.Server
	var apiID = "pcap-api/1234-5678-9000"
	var agentID1 = "router/1abc"
	var agentID2 = "other/2abc"
	var agentTarget1 pcap.AgentEndpoint
	var agentTarget2 pcap.AgentEndpoint
	var api *pcap.API
	var apiURL *url.URL
	var agent1 *pcap.Agent
	var agentPort = 9494
	var deploymentName = "test-deployment"
	var boshDirectorServer *httptest.Server
	var boshResolver *pcap.BoshResolver
	var boshEnvironment = "bosh"
	var messageWriter *MemoryMessageWriter
	var captureDuration = 2 * time.Second
	var mockUAA *httptest.Server

	var defaultOptions = &pcap.CaptureOptions{
		Device:  findLoopback().Name,
		Filter:  "",
		SnapLen: 65000,
	}

	Context("with mock BOSH Director", func() {
		BeforeEach(func() {
			agentServer1, agentTarget1, _ /*agent1*/ = createAgent(agentPort, agentID1, nil)
			agentServer2, agentTarget2, _ = createAgent(agentPort, agentID2, nil)

			// boshConfig.RawDirectorURL is populated when creating the mock server.
			boshConfig := pcap.BoshResolverConfig{
				EnvironmentAlias: "bosh",
				AgentPort:        agentPort,
				TokenScope:       "bosh.admin",
				MTLS:             nil,
			}

			var err error
			boshResolver, boshDirectorServer, mockUAA, err = mock.NewResolverWithMockBoshAPIWithEndpoints([]pcap.AgentEndpoint{agentTarget1, agentTarget2}, boshConfig, deploymentName)
			Expect(err).ShouldNot(HaveOccurred())

			messageWriter = NewMemoryMessageWriter()

			agentTLSConf := &pcap.MutualTLS{SkipVerify: true}
			apiBuffConf := pcap.BufferConf{Size: 200, UpperLimit: 198, LowerLimit: 180}

			var apiAddr net.Addr
			apiClient, apiServer, api, apiAddr = createAPIwithBoshResolver(boshResolver, apiBuffConf, agentTLSConf, apiID)

			apiURL = mock.MustParseURL(fmt.Sprintf("http://%s", apiAddr.String()))
		})

		AfterEach(func() {
			agentServer1.GracefulStop()
			agentServer2.GracefulStop()
			apiServer.GracefulStop()
			boshDirectorServer.Close()
			mockUAA.Close()
		})

		Context("and PCAP Client", func() {
			var client *pcap.Client

			BeforeEach(func() {
				_, err := apiClient.Status(context.Background(), &pcap.StatusRequest{})
				Expect(err).ShouldNot(HaveOccurred(), "failed getting API status")

				logger, _ := zap.NewDevelopment()
				client, err = pcap.NewClient("test.pcap", logger, messageWriter)
				Expect(err).ShouldNot(HaveOccurred(), "failed initializing client")

				client.ConnectToAPI(apiURL)
				Expect(err).ShouldNot(HaveOccurred(), "failed to connect to API")
			})

			AfterEach(func() {
				client = nil
			})

			It("resolves a valid BOSH environment handler", func() {
				err := client.CheckAPIHandler(fmt.Sprintf("bosh/%s", boshEnvironment))
				Expect(err).ShouldNot(HaveOccurred(), "expected handler is not supported")
			})

			It("rejects an invalid BOSH environment handler", func() {
				err := client.CheckAPIHandler("bosh/something_made_up")
				Expect(err).Should(HaveOccurred(), "Wrong handler should not be marked as supported")
			})

			Context("with a valid token", func() {

				var endpointRequest *pcap.EndpointRequest

				BeforeEach(func() {
					validToken, err := mock.GetValidToken(boshResolver.UaaURLs[0])
					Expect(err).ShouldNot(HaveOccurred(), "failed getting valid token")

					endpointRequest = &pcap.EndpointRequest{
						Request: &pcap.EndpointRequest_Bosh{
							Bosh: &pcap.BoshRequest{
								Environment: boshEnvironment,
								Token:       validToken,
								Deployment:  deploymentName,
								// The group names are taken from the prefixes defined in agentID1, agentID2.
								Groups: []string{"router", "other"},
							},
						},
					}

					// automatically stop capture after captureDuration
					sendDeferredStop(client, captureDuration)
				})

				It("completes successfully for two agents in different instance groups", func() {
					err := client.CaptureRequest(endpointRequest, defaultOptions)
					Expect(err).ShouldNot(HaveOccurred(), "capture request failed")

					Expect(messageWriter.Filter(pcap.MessageType_CAPTURE_STOPPED)).Should(HaveLen(2))
				})

				It("completes successfully for one agent in an instance group", func() {
					endpointRequest.GetBosh().Groups = []string{"router"}

					err := client.CaptureRequest(endpointRequest, defaultOptions)
					Expect(err).ShouldNot(HaveOccurred(), "capture request failed")

					Expect(messageWriter.Filter(pcap.MessageType_CAPTURE_STOPPED)).Should(HaveLen(1))
				})

				It("fails for a request with an unknown instance group", func() {
					endpointRequest.GetBosh().Groups = []string{"unknown"}

					err := client.CaptureRequest(endpointRequest, defaultOptions)
					Expect(err).Should(HaveOccurred(), "capture request should have failed")
					Expect(err.Error()).To(ContainSubstring(pcap.ErrNoEndpoints.Error()))
				})

				It("fails for a request without instance group", func() {
					endpointRequest.GetBosh().Groups = []string{""}

					err := client.CaptureRequest(endpointRequest, defaultOptions)
					Expect(err).Should(HaveOccurred(), "capture request should have failed")
					Expect(err.Error()).To(ContainSubstring(pcap.ErrNoEndpoints.Error()))
				})

				It("requests only for the selected instance ID", func() {
					// instance IDs are taken from agentID1 and agentID2
					endpointRequest.GetBosh().Instances = []string{"2abc"}

					err := client.CaptureRequest(endpointRequest, defaultOptions)
					Expect(err).ShouldNot(HaveOccurred(), "capture request failed")

					messages := messageWriter.Filter(pcap.MessageType_CAPTURE_STOPPED)
					Expect(messages).Should(HaveLen(1))
					Expect(messages[0].Origin).Should(Equal(agentID2))
				})

				It("fails when selecting a non-existent instance ID", func() {
					// instance IDs are taken from agentID1 and agentID2
					endpointRequest.GetBosh().Instances = []string{"this-id-does-not-exist"}

					err := client.CaptureRequest(endpointRequest, defaultOptions)
					Expect(err).Should(HaveOccurred(), "capture should have failed")
				})
			})
			Context("with an invalid token", func() {

				var endpointRequest *pcap.EndpointRequest

				BeforeEach(func() {
					endpointRequest = &pcap.EndpointRequest{
						Request: &pcap.EndpointRequest_Bosh{
							Bosh: &pcap.BoshRequest{
								Environment: boshEnvironment,
								Token:       "this-is-not-a-valid-token",
								Deployment:  deploymentName,
								// The group names are taken from the prefixes defined in agentID1, agentID2.
								Groups: []string{"router", "other"},
							},
						},
					}

					// automatically stop capture after captureDuration
					sendDeferredStop(client, captureDuration)
				})

				It("fails with invalid token", func() {
					err := client.CaptureRequest(endpointRequest, defaultOptions)
					Expect(err).Should(HaveOccurred(), "capture request should fail")

					Expect(err.Error()).To(ContainSubstring("could not verify token"))
				})

				It("fails with empty token", func() {

					endpointRequest.GetBosh().Token = ""
					err := client.CaptureRequest(endpointRequest, defaultOptions)
					Expect(err).Should(HaveOccurred(), "capture request should fail")

					Expect(err.Error()).To(ContainSubstring(pcap.ErrValidationFailed.Error()))
				})
			})

		})
		Context("that is shut down and a PCAP Client", func() {
			var client *pcap.Client
			var validToken string

			BeforeEach(func() {
				var err error
				validToken, err = mock.GetValidToken(boshResolver.UaaURLs[0])
				Expect(err).ShouldNot(HaveOccurred(), "failed getting valid token")

				// shut down the Bosh Director Mock Server
				err = boshDirectorServer.Listener.Close()
				Expect(err).ShouldNot(HaveOccurred())

				time.Sleep(1 * time.Second)

				_, err = apiClient.Status(context.Background(), &pcap.StatusRequest{})
				Expect(err).ShouldNot(HaveOccurred(), "failed getting API status")

				logger, _ := zap.NewDevelopment()
				client, err = pcap.NewClient("test.pcap", logger, messageWriter)
				Expect(err).ShouldNot(HaveOccurred(), "failed initializing client")

				client.ConnectToAPI(apiURL)
				Expect(err).ShouldNot(HaveOccurred(), "failed to connect to API")

				// automatically stop capture after captureDuration
				sendDeferredStop(client, captureDuration)
			})

			It("breaks with a valid token", func() {
				endpointRequest := &pcap.EndpointRequest{
					Request: &pcap.EndpointRequest_Bosh{
						Bosh: &pcap.BoshRequest{
							Environment: boshEnvironment,
							Token:       validToken,
							Deployment:  deploymentName,
							// The group names are taken from the prefixes defined in agentID1, agentID2.
							Groups: []string{"router", "other"},
						},
					},
				}

				err := client.CaptureRequest(endpointRequest, defaultOptions)
				Expect(err).Should(HaveOccurred(), "capture request should have failed")
				Expect(err.Error()).To(ContainSubstring("resolver unhealthy"))
			})
		})

		Context("that with shut down UAA and a PCAP Client", func() {
			var client *pcap.Client
			var validToken string

			BeforeEach(func() {
				var err error
				validToken, err = mock.GetValidToken(boshResolver.UaaURLs[0])
				Expect(err).ShouldNot(HaveOccurred(), "failed getting valid token")

				err = mockUAA.Listener.Close()
				Expect(err).ShouldNot(HaveOccurred())

				_, err = apiClient.Status(context.Background(), &pcap.StatusRequest{})
				Expect(err).ShouldNot(HaveOccurred(), "failed getting API status")

				logger, _ := zap.NewDevelopment()
				client, err = pcap.NewClient("test.pcap", logger, messageWriter)
				Expect(err).ShouldNot(HaveOccurred(), "failed initializing client")

				client.ConnectToAPI(apiURL)
				Expect(err).ShouldNot(HaveOccurred(), "failed to connect to API")

				// automatically stop capture after captureDuration
				sendDeferredStop(client, captureDuration)
			})

			It("breaks with a valid token", func() {
				endpointRequest := &pcap.EndpointRequest{
					Request: &pcap.EndpointRequest_Bosh{
						Bosh: &pcap.BoshRequest{
							Environment: boshEnvironment,
							Token:       validToken,
							Deployment:  deploymentName,
							// The group names are taken from the prefixes defined in agentID1, agentID2.
							Groups: []string{"router", "other"},
						},
					},
				}

				err := client.CaptureRequest(endpointRequest, defaultOptions)
				Expect(err).Should(HaveOccurred(), "capture request should have failed")
				Expect(err.Error()).To(ContainSubstring("could not verify token"))
			})
		})

		_ = api
		_ = agent1
	})
})

func createAPIwithBoshResolver(resolver *pcap.BoshResolver, bufConf pcap.BufferConf, mTLSConfig *pcap.MutualTLS, id string) (pcap.APIClient, *grpc.Server, *pcap.API, net.Addr) {
	return createAPI(resolver, bufConf, mTLSConfig, id)
}

func sendDeferredStop(client *pcap.Client, duration time.Duration) {
	go func(client *pcap.Client) {
		time.Sleep(duration)
		if client != nil {
			client.StopRequest()
		}
	}(client)
}
