package acceptance_tests

import (
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"net/http"
	"os"
	"os/exec"
	"time"
)

var _ = Describe("Pcap Deployment", func() {

	var info pcapInfo

	AfterEach(func() {
		// Get pcap logs in case of failure
		if CurrentSpecReport().Failed() {
			pcapApiOut, _, _ := runOnRemote(info.SSHUser, info.PcapAPIPublicIP, info.SSHPrivateKey, "cat /var/vcap/sys/log/pcap-api/pcap-api.stdout.log")
			pcapApiErr, _, _ := runOnRemote(info.SSHUser, info.PcapAPIPublicIP, info.SSHPrivateKey, "cat /var/vcap/sys/log/pcap-api/pcap-api.stderr.log")

			writeLog(fmt.Sprintf("%s: PCAP-API LOGS:\nSTDOUT: %s\nSTDERR: %s\n", deploymentNameForTestNode(), pcapApiOut, pcapApiErr))
		}
	})

	It("Deploys and Captures Traffic Successfully", func() {

		info, _ = deployPcap(
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
		err = downloadFile(info, "/var/vcap/packages/pcap-api/bin/cli/build/pcap-bosh-cli-linux-amd64", pcapBoshCliFile, 0755)
		Expect(err).NotTo(HaveOccurred())
		err = pcapBoshCliFile.Close()
		Expect(err).NotTo(HaveOccurred())

		pcapFile := fmt.Sprintf("%s-capture.pcap", pcapBoshCli)
		By("Starting capture of traffic on pcap-agent instance to file " + pcapFile)
		cmdPcap := exec.Command(
			pcapBoshCli,
			"-d", deploymentNameForTestNode(),
			"-g", "pcap-agent",
			"-o", pcapFile,
			"-u", fmt.Sprintf("http://%s:8080/", info.PcapAPIPublicIP), //TODO: make URL configurable in tests
			"-v")
		sessionPcap, err := gexec.Start(cmdPcap, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())

		By("Calling apache on pcap-agent instance to produce some traffic")
		for request := 1; request <= 10; request++ {
			time.Sleep(time.Second)
			response, err := http.Get(fmt.Sprintf("http://%s:80/", info.PcapAgentPublicIP))
			Expect(err).NotTo(HaveOccurred())
			Expect(response.StatusCode).To(Equal(200))
		}

		By("Stopping capture after curl has finished")
		sessionPcap.Interrupt()
		Eventually(sessionPcap, time.Minute, time.Second).Should(gexec.Exit())

		By("Checking that the capture has produced a valid pcap file")
		pcapFileStat, err := os.Stat(pcapFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(pcapFileStat.Size()).To(BeNumerically(">", 24)) // 24 bytes == pcap header only
	})
})
