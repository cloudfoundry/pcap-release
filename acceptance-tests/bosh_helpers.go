package acceptance_tests

// Helper method for deploying pcap.
import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"gopkg.in/yaml.v3"
)

type pcapInfo struct {
	SSHPrivateKey           string
	SSHPublicKey            string
	SSHPublicKeyFingerprint string
	SSHUser                 string
	PcapAPIPublicIP         string
	PcapAgentPublicIP       string
}

type baseManifestVars struct {
	deploymentName string
}

type varsStoreReader func(interface{}) error

var opsfileChangeName string = `---
# change deployment name to allow multiple simultaneous deployments
- type: replace
  path: /name
  value: ((deployment-name))
`

var opsfileChangeVersion string = `---
# Deploy dev version we just compiled
- type: replace
  path: /releases/name=pcap
  value:
    name: pcap
    version: ((release-version))
`

var opsfileAddSSHUser string = `---
# Install OS conf so that we can SSH into VM to inspect configuration
- type: replace
  path: /releases/-
  value:
    name: os-conf
    version: latest

# Add an SSH user
- type: replace
  path: /instance_groups/name=pcap-api/jobs/-
  value:
    name: user_add
    release: os-conf
    properties:
      users:
      - name: ((ssh_user))
        public_key: ((ssh_key.public_key))
        sudo: true

- type: replace
  path: /instance_groups/name=pcap-agent/jobs/-
  value:
    name: user_add
    release: os-conf
    properties:
      users:
      - name: ((ssh_user))
        public_key: ((ssh_key.public_key))
        sudo: true

# Generate an SSH key-pair
- type: replace
  path: /variables?/-
  value:
    name: ssh_key
    type: ssh
`

// opsfiles that need to be set for all tests
var defaultOpsfiles = []string{opsfileChangeName, opsfileChangeVersion, opsfileAddSSHUser}
var defaultSSHUser string = "ginkgo"

func buildManifestVars(baseManifestVars baseManifestVars, customVars map[string]interface{}) map[string]interface{} {
	vars := map[string]interface{}{
		"release-version":   config.ReleaseVersion,
		"director_ssl_ca":   config.BoshDirectorCA,
		"bosh_director_api": config.BoshDirectorAPI,
		"director_ssl_cert": config.BoshDirectorCert,
		"director_ssl_key":  config.BoshDirectorKey,
		"deployment-name":   baseManifestVars.deploymentName,
		"ssh_user":          defaultSSHUser,
	}
	for k, v := range customVars {
		vars[k] = v
	}

	return vars
}

func buildPcapInfo(baseManifestVars baseManifestVars, varsStoreReader varsStoreReader) pcapInfo {
	var creds struct {
		SSHKey struct {
			PrivateKey           string `yaml:"private_key"`
			PublicKey            string `yaml:"public_key"`
			PublicKeyFingerprint string `yaml:"public_key_fingerprint"`
		} `yaml:"ssh_key"`
	}
	err := varsStoreReader(&creds)
	Expect(err).NotTo(HaveOccurred())

	Expect(creds.SSHKey.PrivateKey).NotTo(BeEmpty())
	Expect(creds.SSHKey.PublicKey).NotTo(BeEmpty())

	By("Fetching the Pcap public IPs")
	instances := boshInstances(baseManifestVars.deploymentName)

	var pcapAPIPublicIP, pcapAgentPublicIP string
	for i, vm := range instances {
		if strings.Contains(vm.Instance, "pcap-api") {
			pcapAPIPublicIP = instances[i].ParseIPs()[0]
		}
		if strings.Contains(vm.Instance, "pcap-agent") {
			pcapAgentPublicIP = instances[i].ParseIPs()[0]
		}

	}

	Expect(pcapAPIPublicIP).ToNot(BeEmpty())
	Expect(pcapAgentPublicIP).ToNot(BeEmpty())

	return pcapInfo{
		PcapAPIPublicIP:         pcapAPIPublicIP,
		PcapAgentPublicIP:       pcapAgentPublicIP,
		SSHPrivateKey:           creds.SSHKey.PrivateKey,
		SSHPublicKey:            creds.SSHKey.PublicKey,
		SSHPublicKeyFingerprint: creds.SSHKey.PublicKeyFingerprint,
		SSHUser:                 defaultSSHUser,
	}
}

func deployPcap(baseManifestVars baseManifestVars, customOpsfiles []string, customVars map[string]interface{}, expectSuccess bool) (pcapInfo, varsStoreReader) {
	manifestVars := buildManifestVars(baseManifestVars, customVars)
	opsfiles := append(defaultOpsfiles, customOpsfiles...)
	cmd, varsStoreReader := deployBaseManifestCmd(baseManifestVars.deploymentName, opsfiles, manifestVars)

	dumpCmd(cmd)
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())

	const timeout = 20
	if expectSuccess {
		Eventually(session, timeout*time.Minute, time.Second).Should(gexec.Exit(0))
	} else {
		Eventually(session, timeout*time.Minute, time.Second).Should(gexec.Exit())
		Expect(session.ExitCode()).NotTo(BeZero())
	}

	pcapInfo := buildPcapInfo(baseManifestVars, varsStoreReader)

	// Dump Pcap config to help debugging
	dumpPcapConfig(pcapInfo)

	return pcapInfo, varsStoreReader
}

func dumpCmd(cmd *exec.Cmd) {
	writeLog("---------- Command to run ----------")
	writeLog(cmd.String())
	writeLog("------------------------------------")
}

func dumpPcapConfig(pcapInfo pcapInfo) {
	By("Checking /var/vcap/jobs/pcap-api/config/pcap-api.yml")
	pcapAPIConfig, _, err := runOnRemote(pcapInfo.SSHUser, pcapInfo.PcapAPIPublicIP, pcapInfo.SSHPrivateKey, "cat /var/vcap/jobs/pcap-api/config/pcap-api.yml")
	Expect(err).NotTo(HaveOccurred())
	writeLog("---------- PcapAPI Config ----------")
	writeLog(pcapAPIConfig)
	writeLog("------------------------------------")

	By("Checking /var/vcap/jobs/pcap-agent/config/pcap-agent.yml")
	pcapAgentConfig, _, err := runOnRemote(pcapInfo.SSHUser, pcapInfo.PcapAgentPublicIP, pcapInfo.SSHPrivateKey, "cat /var/vcap/jobs/pcap-agent/config/pcap-agent.yml")
	Expect(err).NotTo(HaveOccurred())
	writeLog("---------- PcapAPI Config ----------")
	writeLog(pcapAgentConfig)
	writeLog("------------------------------------")
}

// Takes bosh deployment name, ops files and vars.
// Returns a cmd object and a callback to deserialise the bosh-generated vars store after cmd has executed.gofmt -w
func deployBaseManifestCmd(boshDeployment string, opsFilesContents []string, vars map[string]interface{}) (*exec.Cmd, varsStoreReader) {
	By(fmt.Sprintf("Deploying pcap (deployment name: %s)", boshDeployment))
	args := []string{"deploy"}

	// ops files
	for _, opsFileContents := range opsFilesContents {
		opsFile, err := os.CreateTemp("", "pcap-tests-ops-file-*.yml")
		Expect(err).NotTo(HaveOccurred())

		writeLog(fmt.Sprintf("Writing ops file to %s\n", opsFile.Name()))
		writeLog("------------------------------------")
		writeLog(opsFileContents)
		writeLog("------------------------------------")

		_, err = opsFile.WriteString(opsFileContents)
		Expect(err).NotTo(HaveOccurred())
		err = opsFile.Close()
		Expect(err).NotTo(HaveOccurred())

		args = append(args, "--ops-file", opsFile.Name())
	}

	// vars file
	if vars != nil {
		varsFile, err := os.CreateTemp("", "pcap-tests-vars-file-*.json")
		Expect(err).NotTo(HaveOccurred())

		bytes, err := json.Marshal(vars)
		Expect(err).NotTo(HaveOccurred())

		writeLog(fmt.Sprintf("Writing vars file to %s\n", varsFile.Name()))
		writeLog("------------------------------------")
		writeLog(string(bytes))
		writeLog("------------------------------------")

		_, err = varsFile.Write(bytes)
		Expect(err).NotTo(HaveOccurred())
		err = varsFile.Close()
		Expect(err).NotTo(HaveOccurred())

		args = append(args, "--vars-file", varsFile.Name())
	}

	// vars store
	varsStore, err := os.CreateTemp("", "pcap-tests-vars-store-*.yml")
	Expect(err).NotTo(HaveOccurred())

	_, err = varsStore.WriteString("{}")
	Expect(err).NotTo(HaveOccurred())
	err = varsStore.Close()
	Expect(err).NotTo(HaveOccurred())

	args = append(args, "--vars-store", varsStore.Name())
	args = append(args, config.BaseManifestPath)

	varsStoreReader := func(target interface{}) error {
		varsStoreBytes, err := os.ReadFile(varsStore.Name())
		if err != nil {
			return err
		}

		return yaml.Unmarshal(varsStoreBytes, target)
	}

	return config.boshCmd(boshDeployment, args...), varsStoreReader
}

type boshInstance struct {
	AgentID           string `json:"agent_id"`
	Az                string `json:"az"`
	Bootstrap         string `json:"bootstrap"`
	Deployment        string `json:"deployment"`
	DiskCids          string `json:"disk_cids"`
	Ignore            string `json:"ignore"`
	Index             string `json:"index"`
	Instance          string `json:"instance"`
	CommaSeparatedIPs string `json:"ips"`
	ProcessState      string `json:"process_state"`
	State             string `json:"state"`
	VMCid             string `json:"vm_cid"`
	VMType            string `json:"vm_type"`
}

func (instance boshInstance) ParseIPs() []string {
	return strings.Split(instance.CommaSeparatedIPs, ",")
}

func boshInstances(boshDeployment string) []boshInstance {
	writeLog("Fetching Bosh instances")
	cmd := config.boshCmd(boshDeployment, "--json", "instances", "--details")
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, time.Minute, time.Second).Should(gexec.Exit(0))

	output := struct {
		Tables []struct {
			Rows []boshInstance `json:"Rows"`
		} `json:"Tables"`
	}{}

	err = json.Unmarshal(session.Out.Contents(), &output)
	Expect(err).NotTo(HaveOccurred())

	return output.Tables[0].Rows
}

func deleteDeployment(boshDeployment string) {
	By(fmt.Sprintf("Deleting pcap deployment (deployment name: %s)", boshDeployment))
	cmd := config.boshCmd(boshDeployment, "delete-deployment")
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	const timeout = 10
	Eventually(session, timeout*time.Minute, time.Second).Should(gexec.Exit(0))
}

func login(username, password string) {
	By(fmt.Sprintf("Calling bosh login (user: %s)", username))
	cmd := config.boshInteractiveCmd("login")

	stdin, err := cmd.StdinPipe()
	Expect(err).NotTo(HaveOccurred())

	stdin.Write([]byte(fmt.Sprintf("%s\n", username)))
	stdin.Write([]byte(fmt.Sprintf("%s\n", password)))
	stdin.Close()

	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	const timeout = 10
	Eventually(session, timeout*time.Minute, time.Second).Should(gexec.Exit(0))
}

func writeLog(s string) {
	ginkgoConfig, _ := GinkgoConfiguration()
	for _, line := range strings.Split(s, "\n") {
		fmt.Printf("node %d/%d: %s\n", ginkgoConfig.ParallelProcess, ginkgoConfig.ParallelTotal, line)
	}
}

func downloadFile(info pcapInfo, remotePath, localPath string, permissions os.FileMode) error {
	return copyFileFromRemote(info.SSHUser, info.PcapAPIPublicIP, info.SSHPrivateKey, remotePath, localPath, permissions)
}
