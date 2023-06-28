package acceptance_tests

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"os"
	"os/exec"
	"time"
)

var _ = Describe("Pcap Deployment", func() {
	It("Deploys successfully", func() {

		info, _ := deployPcap(
			baseManifestVars{
				deploymentName: deploymentNameForTestNode(),
			},
			[]string{},
			map[string]interface{}{},
			true,
		)

		By("Logging on to BOSH director to get a refresh token")
		login(config.BoshClient, config.BoshClientSecret)

		pcapBoshCliFile, err := os.CreateTemp("", "pcap-bosh-cli-*")
		Expect(err).NotTo(HaveOccurred())
		pcapBoshCli := pcapBoshCliFile.Name()

		By("Downloading remote pcap-bosh-cli-linux-amd64 to " + pcapBoshCli)
		err = downloadFile(info, "/var/vcap/packages/pcap-api/bin/cli/build/pcap-bosh-cli-linux-amd64", pcapBoshCli, 0755)
		Expect(err).NotTo(HaveOccurred())

		time.Sleep(2 * time.Hour)

		cmd := exec.Command(pcapBoshCli, "--help")

		helpTest, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred())

		writeLog(string(helpTest))
	})
})
