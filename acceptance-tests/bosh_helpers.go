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

type baseManifestVars struct {
	deploymentName string
}

type varsStoreReader func(interface{}) error

func buildManifestVars(baseManifestVars baseManifestVars, customVars map[string]interface{}) map[string]interface{} {
	vars := map[string]interface{}{
		"release-version":   config.ReleaseVersion,
		"bosh_director_ca":  config.BoshCACert,
		"bosh_director_api": config.BoshDirectorIP,
		"deployment-name":   baseManifestVars.deploymentName,
	}
	for k, v := range customVars {
		vars[k] = v
	}

	return vars
}

func deployPcap(baseManifestVars baseManifestVars, customVars map[string]interface{}, expectSuccess bool) {
	manifestVars := buildManifestVars(baseManifestVars, customVars)
	cmd, _ := deployBaseManifestCmd(baseManifestVars.deploymentName, manifestVars)

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
}

func deleteDeployment(boshDeployment string) {
	By(fmt.Sprintf("Deleting pcap deployment (deployment name: %s)", boshDeployment))
	cmd := config.boshCmd(boshDeployment, "delete-deployment")
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	const timeout = 10
	Eventually(session, timeout*time.Minute, time.Second).Should(gexec.Exit(0))
}

func dumpCmd(cmd *exec.Cmd) {
	writeLog("---------- Command to run ----------")
	writeLog(cmd.String())
	writeLog("------------------------------------")
}

// Takes bosh deployment name, ops files and vars.
// Returns a cmd object and a callback to deserialise the bosh-generated vars store after cmd has executed.gofmt -w
func deployBaseManifestCmd(boshDeployment string, vars map[string]interface{}) (*exec.Cmd, varsStoreReader) {
	By(fmt.Sprintf("Deploying pcap (deployment name: %s)", boshDeployment))
	args := []string{"deploy"}

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

func writeLog(s string) {
	ginkgoConfig, _ := GinkgoConfiguration()
	for _, line := range strings.Split(s, "\n") {
		fmt.Printf("node %d/%d: %s\n", ginkgoConfig.ParallelProcess, ginkgoConfig.ParallelTotal, line)
	}
}
