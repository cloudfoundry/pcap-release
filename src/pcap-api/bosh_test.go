package main

import (
	"github.com/cloudfoundry/pcap-release/pcap-api/test"
	"net/http"
	"net/url"
	"time"

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
		boshAPI := test.MockBoshDirectorAPI(nil)
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
		boshAPI := test.MockBoshDirectorAPI(nil)
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
