package integration_tests

import (
	"context"
	"errors"
	"fmt"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"io"
	"net"

	gopcap "github.com/google/gopacket/pcap"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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

	var stop *pcap.CaptureRequest
	var defaultOptions *pcap.CaptureOptions

	BeforeEach(func() {
		var targets []pcap.AgentEndpoint
		var target pcap.AgentEndpoint

		_, agentServer1, target = createAgent(8082)
		targets = append(targets, target)

		_, agentServer2, target = createAgent(8083)
		targets = append(targets, target)

		apiClient, apiServer = createAPI(8080, targets)

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
	Describe("Starting a capture", func() {

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
				Expect(messages).To(HaveLen(10))
				err = stream.Send(stop)
				Expect(err).NotTo(HaveOccurred(), "Sending stop message")

				code, messages, err := recvCapture(10_000, stream)
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
				recvCapture(10, stream)

				err = stream.Send(stop)

				Expect(err).NotTo(HaveOccurred())

				recvCapture(10_000, stream)

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
				errCode, _, err := recvCapture(10, stream)
				Expect(errCode).To(Equal(codes.FailedPrecondition))
			})
		})
	})
})

func createAgent(port int) (pcap.AgentClient, *grpc.Server, pcap.AgentEndpoint) {
	var server *grpc.Server
	agent, err := pcap.NewAgent(nil, pcap.BufferConf{100, 98, 80})
	Expect(err).NotTo(HaveOccurred())

	lis, err = net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	Expect(err).NotTo(HaveOccurred())
	tcpAddr, ok := lis.Addr().(*net.TCPAddr)
	Expect(ok).To(BeTrue())
	fmt.Printf("create agent with listener  %s\n", lis.Addr().String())

	target := pcap.AgentEndpoint{Ip: tcpAddr.IP.String(), Port: tcpAddr.Port}
	server = grpc.NewServer()

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

func createAPI(port int, targets []pcap.AgentEndpoint) (pcap.APIClient, *grpc.Server) {
	var server *grpc.Server
	api, err := pcap.NewAPI(nil, pcap.BufferConf{100, 98, 80}, pcap.APIConf{targets})
	Expect(err).NotTo(HaveOccurred())

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
			return code, messages, fmt.Errorf("receive non-OK code: %s: %s\n", code.String(), err.Error())
		}
		messages = append(messages, message)
	}
	return codes.OK, messages, nil
}
