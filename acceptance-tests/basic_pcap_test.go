package acceptance_tests

import (
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
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

		By("Starting capture of traffic on pcap-agent instance")
		pcapFile, err := os.CreateTemp("", "test-*.pcap")
		Expect(err).NotTo(HaveOccurred())
		cmdPcap := exec.Command(
			pcapBoshCli,
			fmt.Sprintf("-d %s", deploymentNameForTestNode()),
			"-g pcap-agent",
			fmt.Sprintf("-o %s", pcapFile.Name()),
			fmt.Sprintf("-u http://%s:8080/", info.PcapAPIPublicIP),
			"-v",
			"-F")

		sessionPcap, err := gexec.Start(cmdPcap, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())

		By("Starting ping against pcap-agent instance to produce some traffic")
		cmdPing := exec.Command("ping", "-c 10", fmt.Sprintf("%s", info.PcapAgentPublicIP))
		sessionPing, err := gexec.Start(cmdPing, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())

		By("Stopping capture after ping has finished")
		Eventually(sessionPing, time.Minute, time.Second).Should(gexec.Exit(0))
		sessionPcap.Interrupt()
		Eventually(sessionPcap, time.Minute, time.Second).Should(gexec.Exit(0))

		By("Checking that the capture has produced a valid pcap file")
		_ = pcapFile.Close()
		pcapFileStat, err := pcapFile.Stat()
		Expect(err).NotTo(HaveOccurred())
		Expect(pcapFileStat.Size()).To(BeNumerically(">", 0))
	})
})
