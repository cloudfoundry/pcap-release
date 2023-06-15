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

		boshCliFile, err := os.CreateTemp("", "pcap-bosh-cli-*")
		Expect(err).NotTo(HaveOccurred())

		boshCli := boshCliFile.Name()

		By("Downloading remote pcap-bosh-cli-linux-amd64 to " + boshCli)
		err = downloadFile(info, "/var/vcap/packages/pcap-api/bin/cli/build/pcap-bosh-cli-linux-amd64", boshCli, 0755)
		Expect(err).NotTo(HaveOccurred())

		time.Sleep(2 * time.Hour)

		cmd := exec.Command(boshCli, "--help")

		helpTest, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred())

		writeLog(string(helpTest))
	})
})
