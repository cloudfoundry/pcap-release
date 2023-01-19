package integration_tests

import (
	"context"
	"errors"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"io"
	"net"
)

var lis net.Listener

var apiClient pcap.APIClient

var _ = Describe("IntegrationTests", func() {
	var agentServer1 *grpc.Server
	var agentServer2 *grpc.Server
	var apiServer *grpc.Server

	BeforeEach(func() {
		var targets []string
		var target string

		_, agentServer1, target = createAgent(8082)
		targets = append(targets, target)

		_, agentServer2, target = createAgent(8083)
		targets = append(targets, target)

		apiClient, apiServer = createApi(8080, targets)
	})
	AfterEach(func() {
		agentServer1.GracefulStop()
		agentServer2.GracefulStop()
		apiServer.GracefulStop()
	})
	Describe("Running", func() {

		Context("two agents and one api", func() {
			It("finished without errors", func() {
				ctx := context.Background()

				stream, err := apiClient.CaptureBosh(ctx)
				err = stream.Send(&pcap.BoshRequest{Payload: &pcap.BoshRequest_Start{
					Start: &pcap.StartBoshCapture{
						Token:      "123",
						Deployment: "cf",
						Groups:     []string{"router"},
						Capture: &pcap.CaptureOptions{
							Device:  "en0",
							Filter:  "",
							SnapLen: 65000,
						},
					}}})
				Expect(err).NotTo(HaveOccurred())
				readN(10, stream)

				err = stream.Send(&pcap.BoshRequest{
					Payload: &pcap.BoshRequest_Stop{},
				})
				Expect(err).NotTo(HaveOccurred())

				readN(10_000, stream)

			})
			It("finished with errors due to invalid request", func() {
				ctx := context.Background()

				stream, err := apiClient.CaptureBosh(ctx)
				err = stream.Send(&pcap.BoshRequest{Payload: &pcap.BoshRequest_Start{
					Start: &pcap.StartBoshCapture{
						Token:  "123",
						Groups: []string{"router"},
						Capture: &pcap.CaptureOptions{
							Device:  "en0",
							Filter:  "",
							SnapLen: 65000,
						},
					}}})
				Expect(err).NotTo(HaveOccurred())

				err, errCode := readN(10, stream)
				Expect(errCode).To(Equal(codes.InvalidArgument))
			})
			It("one agent unavailable", func() {
				agentServer2.GracefulStop()
				ctx := context.Background()

				stream, err := apiClient.CaptureBosh(ctx)
				err = stream.Send(&pcap.BoshRequest{Payload: &pcap.BoshRequest_Start{
					Start: &pcap.StartBoshCapture{
						Token:      "123",
						Deployment: "cf",
						Groups:     []string{"router"},
						Capture: &pcap.CaptureOptions{
							Device:  "en0",
							Filter:  "",
							SnapLen: 65000,
						},
					}}})
				Expect(err).NotTo(HaveOccurred())
				readN(10, stream)

				err = stream.Send(&pcap.BoshRequest{
					Payload: &pcap.BoshRequest_Stop{},
				})
				Expect(err).NotTo(HaveOccurred())

				readN(10_000, stream)

			})
		})
	})
})

func createAgent(port int) (pcap.AgentClient, *grpc.Server, string) {
	var server *grpc.Server
	agent, err := pcap.NewAgent(nil, pcap.BufferConf{100, 98, 80})
	Expect(err).NotTo(HaveOccurred())

	lis, err = net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("create agent with listener  %s\n", lis.Addr().String())

	target := lis.Addr().String()

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

func createApi(port int, targets []string) (pcap.APIClient, *grpc.Server) {
	var server *grpc.Server
	api, err := pcap.NewApi(nil, pcap.BufferConf{100, 98, 80}, pcap.ApiConf{targets})
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

	apiClient := pcap.NewAPIClient(cc)
	return apiClient, server
}

func readN(n int, stream pcap.API_CaptureBoshClient) (error, codes.Code) {
	for i := 0; i < n; i++ {
		_, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			fmt.Println("clean stop, done")
			return nil, codes.Unknown
		}
		code := status.Code(err)
		if code != codes.OK {
			return fmt.Errorf("receive non-OK code: %s: %s\n", code.String(), err.Error()), code
		}
	}
	return nil, codes.OK
}
