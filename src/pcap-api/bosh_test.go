package main

import (
	"github.com/cloudfoundry/pcap-release/pcap-api/test"
	"time"
	"net/http"

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

		It("can be created", func() {
			_, err := NewApi(&cfg)
			Expect(err).To(BeNil())
		})
		It("can be started", func() {
			r, err := http.Get("http://localhost:8080/health")
			Expect(err).To(BeNil())
			Expect(r.StatusCode).To(Equal(200))
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
