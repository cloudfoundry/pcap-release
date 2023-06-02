package acceptance_tests

import (
	"encoding/json"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAcceptanceTests(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "AcceptanceTests Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	// Load config once, and pass to other
	// threads as JSON-encoded byte array
	var err error
	config, err = loadConfig()
	Expect(err).NotTo(HaveOccurred())

	// Deploy pcap-api deployment

	deployPcap(baseManifestVars{
		deploymentName: deploymentNameForTestNode(),
	}, map[string]interface{}{}, true)

	configBytes, err := json.Marshal(&config)
	Expect(err).NotTo(HaveOccurred())

	return configBytes
}, func(configBytes []byte) {
	// populate thread-local variable `config` in each thread
	err := json.Unmarshal(configBytes, &config)
	Expect(err).NotTo(HaveOccurred())
})

var _ = SynchronizedAfterSuite(func() {
	// Clean up deployments on each thread
	deleteDeployment(deploymentNameForTestNode())
}, func() {})

func deploymentNameForTestNode() string {
	return fmt.Sprintf("pcap-api%d", GinkgoParallelProcess())
}
