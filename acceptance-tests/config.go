package acceptance_tests

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
)

var config Config

type Config struct {
	ReleaseRepoPath    string `json:"releaseRepoPath"`
	ReleaseVersion     string `json:"releaseVersion"`
	BoshDirectorAPI    string `json:"boshDirectorAPI"`
	BoshDirectorCertCN string `json:"boshDirectorCertCN"`
	BoshDirectorCert   string `json:"boshDirectorCert"`
	BoshDirectorKey    string `json:"boshDirectorKey"`
	BoshDirectorCA     string `json:"boshDirectorCA"`
	BoshClient         string `json:"boshClient"`
	BoshClientSecret   string `json:"boshClientSecret"`
	BoshEnvironment    string `json:"boshEnvironment"`
	BoshPath           string `json:"boshPath"`
	BaseManifestPath   string `json:"baseManifestPath"`
	HomePath           string `json:"homePath"`
}

func loadConfig() (Config, error) {
	releaseRepoPath, err := getEnvOrFail("REPO_ROOT")
	if err != nil {
		return Config{}, err
	}

	releaseVersion, err := getEnvOrFail("RELEASE_VERSION")
	if err != nil {
		return Config{}, err
	}

	boshDirectorCA, err := getEnvOrFail("BOSH_DIRECTOR_CA")
	if err != nil {
		return Config{}, err
	}

	boshDirectorCert, err := getEnvOrFail("BOSH_DIRECTOR_CERT")
	if err != nil {
		return Config{}, err
	}

	boshDirectorKey, err := getEnvOrFail("BOSH_DIRECTOR_KEY")
	if err != nil {
		return Config{}, err
	}

	boshClient, err := getEnvOrFail("BOSH_CLIENT")
	if err != nil {
		return Config{}, err
	}

	boshClientSecret, err := getEnvOrFail("BOSH_CLIENT_SECRET")
	if err != nil {
		return Config{}, err
	}

	boshDirectorAPI, err := getEnvOrFail("BOSH_DIRECTOR_API")
	if err != nil {
		return Config{}, err
	}

	boshEnvironment, err := getEnvOrFail("BOSH_ENVIRONMENT")
	if err != nil {
		return Config{}, err
	}

	boshPath, err := getEnvOrFail("BOSH_PATH")
	if err != nil {
		return Config{}, err
	}

	baseManifestPath, err := getEnvOrFail("BASE_MANIFEST_PATH")
	if err != nil {
		return Config{}, err
	}

	// BOSH commands require HOME is set
	homePath, err := getEnvOrFail("HOME")
	if err != nil {
		return Config{}, err
	}
	// extract Bosh Director SSL Certificate Common Name
	block, _ := pem.Decode([]byte(boshDirectorCert))
	if block == nil {
		return Config{}, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	cert, _ := x509.ParseCertificate(block.Bytes) // handle error

	boshDirectorCertCN := cert.Subject.CommonName

	return Config{
		ReleaseRepoPath:    releaseRepoPath,
		ReleaseVersion:     releaseVersion,
		BoshDirectorAPI:    boshDirectorAPI,
		BoshDirectorCertCN: boshDirectorCertCN,
		BoshDirectorCert:   boshDirectorCert,
		BoshDirectorKey:    boshDirectorKey,
		BoshDirectorCA:     boshDirectorCA,
		BoshClient:         boshClient,
		BoshClientSecret:   boshClientSecret,
		BoshEnvironment:    boshEnvironment,
		BoshPath:           boshPath,
		BaseManifestPath:   baseManifestPath,
		HomePath:           homePath,
	}, nil
}

func (config *Config) boshCmd(boshDeployment string, args ...string) *exec.Cmd {
	cmd := exec.Command(config.BoshPath, append([]string{"--tty", "--no-color"}, args...)...)
	cmd.Env = []string{
		fmt.Sprintf("BOSH_DIRECTOR_IP=%s", config.BoshDirectorAPI),
		fmt.Sprintf("BOSH_DIRECTOR_CA=%s", config.BoshDirectorCA),
		fmt.Sprintf("BOSH_DIRECTOR_CERT=%s", config.BoshDirectorCert),
		fmt.Sprintf("BOSH_CLIENT=%s", config.BoshClient),
		fmt.Sprintf("BOSH_CLIENT_SECRET=%s", config.BoshClientSecret),
		fmt.Sprintf("BOSH_ENVIRONMENT=%s", config.BoshEnvironment),
		fmt.Sprintf("HOME=%s", config.HomePath),
		fmt.Sprintf("BOSH_DEPLOYMENT=%s", boshDeployment),
		"BOSH_NON_INTERACTIVE=true",
	}

	return cmd
}

func (config *Config) boshInteractiveCmd(args ...string) *exec.Cmd {
	cmd := exec.Command(config.BoshPath, append([]string{"--tty", "--no-color"}, args...)...)
	cmd.Env = []string{
		fmt.Sprintf("BOSH_DIRECTOR_IP=%s", config.BoshDirectorAPI),
		fmt.Sprintf("BOSH_DIRECTOR_CA=%s", config.BoshDirectorCA),
		fmt.Sprintf("BOSH_DIRECTOR_CERT=%s", config.BoshDirectorCert),
		fmt.Sprintf("BOSH_ENVIRONMENT=%s", config.BoshEnvironment),
		fmt.Sprintf("HOME=%s", config.HomePath),
	}

	return cmd
}

func getEnvOrFail(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("required env var %s not found", key)
	}

	return value, nil
}
