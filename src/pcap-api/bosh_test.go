package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap-api/test"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Bosh api basic Tests", func() {

	Context("When the bosh Pcap API is started without any config", func() {
		_, err := NewApi(nil)
		It("can't be created", func() {
			Expect(err).NotTo(BeNil())
		})
	})

	Context("When the bosh Pcap API is started with the default config", func() {

		jwtapi, _ := test.MockjwtAPI()
		boshAPI := test.MockBoshDirectorAPI(nil, jwtapi.URL)
		var pcapApi *Api
		var err error

		cfg := DefaultConfig
		cfg.BoshDirectorAPI = boshAPI.URL
		cfg.CfAPI = ""
		BeforeEach(func() {
			pcapApi, err = NewApi(&cfg)
			Expect(err).To(BeNil())
			go pcapApi.Run()
			time.Sleep(100 * time.Millisecond)
		})
		AfterEach(func() {
			pcapApi.Stop()
		})
		It("can be started", func() {
			r, err := http.Get("http://localhost:8080/health")
			Expect(err).To(BeNil())
			Expect(r.StatusCode).To(Equal(http.StatusOK))
		})
		It("can be stopped again", func() {
			_, err := http.Get("http://localhost:8080/health")
			Expect(err).To(BeNil())
			pcapApi.Stop()
			_, err = http.Get("http://localhost:8080/health")
			Expect(err).To(Not(BeNil()))
		})
	})
})

var _ = Describe("Single Instances capture validation errors", func() {

	Context("When the bosh Pcap API is started with the default config", func() {

		jwtapi, _ := test.MockjwtAPI()
		boshAPI := test.MockBoshDirectorAPI(nil, jwtapi.URL)
		var pcapApi *Api
		var err error

		cfg := DefaultConfig
		cfg.BoshDirectorAPI = boshAPI.URL
		cfg.CfAPI = ""
		BeforeEach(func() {
			pcapApi, err = NewApi(&cfg)
			Expect(err).To(BeNil())
			go pcapApi.Run()
			time.Sleep(100 * time.Millisecond)
		})
		AfterEach(func() {
			pcapApi.Stop()
		})

		It("requires deployment parameter to start capturing", func() {
			r, err := http.Get("http://localhost:8080/capture/bosh")
			Expect(err).To(BeNil())
			Expect(r.StatusCode).To(Equal(http.StatusBadRequest))
		})
		It("requires group parameter to start capturing", func() {

			r, err := http.Get("http://localhost:8080/capture/bosh?deployment=haproxy")
			Expect(err).To(BeNil())
			Expect(r.StatusCode).To(Equal(http.StatusBadRequest))
		})

		It("requires authorization header to contain the auth token", func() {

			r, err := http.Get("http://localhost:8080/capture/bosh?deployment=haproxy&group=ha_proxy_z1")
			Expect(err).To(BeNil())
			Expect(r.StatusCode).To(Equal(http.StatusUnauthorized))
		})

		It("requires authorization header to contain a valid token", func() {
			client := http.DefaultClient
			url, _ := url.Parse("http://localhost:8080/capture/bosh?deployment=haproxy&group=ha_proxy_z1")
			req := &http.Request{
				URL: url,
				Header: map[string][]string{
					"Authorization": {"not a token"},
				},
			}

			r, err := client.Do(req)
			Expect(err).To(BeNil())
			Expect(r.StatusCode).To(Equal(http.StatusUnauthorized))
		})
	})
})

var _ = Describe("Single deployment Capture Tests", func() {
	var pcapApi *Api
	var err error
	pcapResponses := map[string]string{
		"/capture/bosh?deployment=haproxy&device=eth0&filter=": "test/sample-1.pcap",
	}
	pcapAgent := test.NewMockPcapAgent(pcapResponses)

	timeString := "2022-09-26T21:28:39Z"
	timestamp, err := time.Parse(time.RFC3339, timeString)
	if err != nil {
		panic(err.Error())
	}

	haproxyInstances := []boshInstance{
		{
			AgentId:     "a9c3cda6-9cd9-457f-aad4-143405bf69db",
			Cid:         "agent_id:a9c3cda6-9cd9-457f-aad4-143405bf69db;resource_group_name:rg-azure-cfn01",
			Job:         "ha_proxy_z1",
			Index:       0,
			Id:          "d8361024-c7bf-4931-b0c9-a152b09510e6",
			Az:          "z1",
			Ips:         []string{pcapAgent.Host},
			VmCreatedAt: timestamp,
			ExpectsVm:   true,
		},
	}

	instances, err := json.Marshal(haproxyInstances)

	if err != nil {
		panic(err.Error())
	}

	responses := map[string]string{
		"/deployments/haproxy/instances": string(instances),
	}

	jwtapi, token := test.MockjwtAPI()

	boshAPI := test.MockBoshDirectorAPI(responses, jwtapi.URL)

	cfg := DefaultConfig
	cfg.BoshDirectorAPI = boshAPI.URL
	cfg.CfAPI = ""
	cfg.AgentPort = pcapAgent.Port

	BeforeEach(func() {
		pcapApi, err = NewApi(&cfg)
		Expect(err).To(BeNil())
		go pcapApi.Run()
		time.Sleep(100 * time.Millisecond)
	})
	AfterEach(func() {
		pcapApi.Stop()
	})

	Context("Getting pcap stream for an deployment", func() {

		It("Returns an stream for the target instances", func() {

			selectedInstances, status, err := pcapApi.bosh.getInstances("haproxy", "my-token")
			if err != nil {
				fmt.Println(err.Error())
			}
			Expect(err).To(BeNil())
			Expect(status).To(Equal(http.StatusOK))
			Expect(selectedInstances).To(Equal(haproxyInstances))

			for _, instance := range selectedInstances {
				ip := instance.Ips[0]
				resp, err := NewPcapStreamer(pcapApi.config).getPcapStream(fmt.Sprintf("https://%s:%s/capture/bosh?deployment=haproxy&device=eth0&filter=", ip, pcapAgent.Port))
				if err != nil {
					fmt.Println(err.Error())
				}

				Expect(err).To(BeNil())
				Expect(resp).NotTo(BeNil())
			}

		})

		It("Returns an stream for the target instances", func() {

			client := http.DefaultClient
			agentURL, _ := url.Parse("http://localhost:8080/capture/bosh?deployment=haproxy&group=ha_proxy_z1")
			req := &http.Request{
				URL: agentURL,
				Header: map[string][]string{
					"Authorization": {fmt.Sprintf("Bearer %s", token)},
				},
			}

			res, err := client.Do(req)

			Expect(err).To(BeNil())
			io.ReadAll(res.Body)

			selectedInstances, status, err := pcapApi.bosh.getInstances("haproxy", "Bearer")
			if err != nil {
				fmt.Println(err.Error())
			}
			Expect(err).To(BeNil())
			Expect(status).To(Equal(http.StatusOK))
			Expect(selectedInstances).To(Equal(haproxyInstances))

			for _, instance := range selectedInstances {
				ip := instance.Ips[0]
				resp, err := NewPcapStreamer(pcapApi.config).getPcapStream(fmt.Sprintf("https://%s:%s/capture/bosh?deployment=haproxy&device=eth0&filter=", ip, pcapAgent.Port))
				if err != nil {
					fmt.Println(err.Error())
				}

				Expect(err).To(BeNil())
				Expect(resp).NotTo(BeNil())
			}

		})

		It("Returns an error for the wrong instances", func() {

			selectedInstances, status, err := pcapApi.bosh.getInstances("gorouter", "mytoken")
			Expect(err).NotTo(BeNil())
			Expect(status).To(Equal(http.StatusNotFound))
			Expect(selectedInstances).ShouldNot(Equal(haproxyInstances))
		})
	})

	Context("Streaming pcap to disk for an instances", func() {
		client := http.DefaultClient
		agentURL, _ := url.Parse("http://localhost:8080/capture/bosh?deployment=haproxy&group=ha_proxy_z1")
		req := &http.Request{
			URL: agentURL,
			Header: map[string][]string{
				"Authorization": {"my-token"},
			},
		}

		It("Allows GET requests only", func() {
			req.Method = "DELETE"
			res, err := client.Do(req)
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusMethodNotAllowed))
		})
	})
})
