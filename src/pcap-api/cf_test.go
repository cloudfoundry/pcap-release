package main

import (
	"fmt"
	"github.com/cloudfoundry/pcap-release/pcap-api/test"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPcapApi(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Pcap Api API")
}

var _ = Describe("Basic Tests", func() {
	cfAPI := test.MockCfAPI(nil)
	var pcapApi *Api
	var err error

	Context("When the Pcap API is started without any config", func() {
		_, err := NewApi(nil)
		It("can't be created", func() {
			Expect(err).NotTo(BeNil())
		})
	})

	Context("When the Pcap API is started with the default config", func() {
		cfg := DefaultConfig
		cfg.CfAPI = cfAPI.URL
		BeforeEach(func() {
			pcapApi, err = NewApi(&cfg)
			Expect(err).To(BeNil())
			go pcapApi.Run()
			time.Sleep(100 * time.Millisecond)
		})
		AfterEach(func() {
			pcapApi.Stop()
		})

		It("can be created", func() {
			_, err := NewApi(&cfg)
			Expect(err).To(BeNil())
		})
		It("can be started", func() {
			r, err := http.Get("http://localhost:8080/health")
			Expect(err).To(BeNil())
			Expect(r.StatusCode).To(Equal(200))
			Expect(pcapApi.cf.ccBaseURL).To(Equal(cfAPI.URL + "/v3"))
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

var _ = Describe("Single Target Capture Tests", func() {
	var pcapApi *Api
	var err error
	pcapResponses := map[string]string{
		"/capture?appid=1234&index=0&device=eth0&filter=": "test/sample-1.pcap",
	}
	pcapAgent := test.NewMockPcapAgent(pcapResponses)
	responses := map[string]string{
		"/v3/apps/1234": "{\n\"guid\": \"1234\",\n  \"name\": \"my-app\",\n  \"state\": \"STARTED\" \n}",
		"/v3/apps/1234/processes/web/stats": fmt.Sprintf("{\n\"resources\": [\n {\n \"type\": \"web\",\n \"index\": 0,"+
			"\n \"state\": \"RUNNING\","+
			"\n \"host\": \"%s\"\n}]}", pcapAgent.Host),
	}
	cfAPI := test.MockCfAPI(responses)
	cfg := DefaultConfig
	cfg.CfAPI = cfAPI.URL
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

	Context("Checking if token can see an app", func() {
		It("Can see apps that belong to the token", func() {
			visible, err := pcapApi.cf.isAppVisibleByToken("1234", "mytoken")
			Expect(err).To(BeNil())
			Expect(visible).To(BeTrue())
		})
		It("Can't see apps that do not belong to the token", func() {
			visible, err := pcapApi.cf.isAppVisibleByToken("9999", "mytoken")
			Expect(err).NotTo(BeNil())
			Expect(visible).To(BeFalse())
		})
	})
	Context("Getting app location", func() {
		It("Returns an address that hosts the target app", func() {
			location, err := pcapApi.cf.getAppLocation("1234", 0, "web", "mytoken")
			Expect(err).To(BeNil())
			Expect(location).To(Equal(pcapAgent.Host))
		})
		It("Returns an error for invisible apps", func() {
			location, err := pcapApi.cf.getAppLocation("9999", 0, "web", "mytoken")
			Expect(err).NotTo(BeNil())
			Expect(location).To(Equal(""))
		})
	})
	Context("Getting pcap stream for an app", func() {
		It("Returns an stream for the target app", func() {
			location, err := pcapApi.cf.getAppLocation("1234", 0, "web", "mytoken")
			Expect(err).To(BeNil())
			Expect(location).To(Equal(pcapAgent.Host))
			pcapStream, err := NewPcapStreamer(pcapApi.config).getPcapStream(
				fmt.Sprintf("https://%s:%s/capture?appid=1234&index=0&device=eth0&filter=", location, pcapAgent.Port))
			Expect(err).To(BeNil())
			Expect(pcapStream).NotTo(BeNil())
		})
		It("Returns an error for streams of invisible apps", func() {
			location, err := pcapApi.cf.getAppLocation("9999", 0, "web", "mytoken")
			Expect(err).NotTo(BeNil())
			Expect(location).To(Equal(""))
			pcapStream, err := NewPcapStreamer(pcapApi.config).getPcapStream(
				fmt.Sprintf("https://%s:%s/capture?appid=9999&index=0&filter=", pcapAgent.Host, pcapAgent.Port))
			Expect(err).NotTo(BeNil())
			Expect(pcapStream).To(Equal(http.NoBody))
		})
	})
	Context("Streaming pcap to disk for an app", func() {
		client := http.DefaultClient
		appURL, _ := url.Parse("http://localhost:8080/capture?appid=1234&filter=")
		req := &http.Request{
			URL: appURL,
			Header: map[string][]string{
				"Authorization": {"myToken"},
			},
		}

		It("Allows GET requests only", func() {
			req.Method = "DELETE"
			res, err := client.Do(req)
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusMethodNotAllowed))
		})
		It("Streams the correct pcap data to disk", func() {
			req.Method = "GET"
			res, err := client.Do(req)
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusOK))
			tempFile, err := os.CreateTemp("", "")
			Expect(err).To(BeNil())
			_, err = io.Copy(tempFile, res.Body)
			Expect(err).To(BeNil())
			err = tempFile.Close()
			Expect(err).To(BeNil())
			infoSrc, err := os.Stat("test/sample-1.pcap")
			Expect(err).To(BeNil())
			infoDst, err := os.Stat(tempFile.Name())
			Expect(err).To(BeNil())
			Expect(infoDst.Size()).To(Equal(infoSrc.Size()))
		})
	})

})

var _ = Describe("Multiple Target Capture Tests", func() {
	var pcapApi *Api
	var err error
	pcapResponses := map[string]string{
		"/capture?appid=1234&index=0&device=eth0&filter=": "test/sample-1.pcap",
		"/capture?appid=1234&index=1&device=eth0&filter=": "test/sample-2.pcap",
	}
	pcapAgent := test.NewMockPcapAgent(pcapResponses)
	responses := map[string]string{
		"/v3/apps/1234": "{\n\"guid\": \"1234\",\n  \"name\": \"my-app\",\n  \"state\": \"STARTED\" \n}",
		"/v3/apps/1234/processes/web/stats": fmt.Sprintf(
			"{\n\"resources\": "+
				"[\n "+
				"{\n \"type\": \"web\",\n \"index\": 0,"+
				"\n \"state\": \"RUNNING\","+
				"\n \"host\": \"%s\"\n},"+
				"{\n \"type\": \"web\",\n \"index\": 1,"+
				"\n \"state\": \"RUNNING\","+
				"\n \"host\": \"%s\"\n}"+
				"]}", pcapAgent.Host, pcapAgent.Host),
	}
	cfAPI := test.MockCfAPI(responses)
	cfg := DefaultConfig
	cfg.CfAPI = cfAPI.URL
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

	Context("Streaming pcap to disk for an app with multiple instances", func() {
		client := http.DefaultClient
		appURL, _ := url.Parse("http://localhost:8080/capture?appid=1234&index=0&index=1&filter=")
		req := &http.Request{
			URL: appURL,
			Header: map[string][]string{
				"Authorization": {"myToken"},
			},
		}

		It("Streams the correct pcap data to disk", func() {
			req.Method = "GET"
			res, err := client.Do(req)
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusOK))
			tempFile, err := os.CreateTemp("", "")
			Expect(err).To(BeNil())
			_, err = io.Copy(tempFile, res.Body)
			Expect(err).To(BeNil())
			err = tempFile.Close()
			Expect(err).To(BeNil())
			infoSrc1, err := os.Stat("test/sample-1.pcap")
			Expect(err).To(BeNil())
			infoSrc2, err := os.Stat("test/sample-2.pcap")
			Expect(err).To(BeNil())
			infoDst, err := os.Stat(tempFile.Name())
			Expect(err).To(BeNil())
			// have to subtract 1 pcap file header as it is written only once but read twice
			Expect(infoDst.Size()).To(Equal(infoSrc1.Size() + infoSrc2.Size() - 24))
		})
	})
})
