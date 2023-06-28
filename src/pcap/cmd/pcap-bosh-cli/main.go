package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/cloudfoundry/pcap-release/src/pcap"

	"github.com/jessevdk/go-flags"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
)

const BoshDefaultPort = 25555
const BoshAuthTypeUAA = "uaa"

var (
	logger         *zap.Logger
	atomicLogLevel zap.AtomicLevel

	// schemaPattern defines a regular expression pattern that matches a URI scheme
	// followed by an authority delimiter, e.g. 'https://' or `ftp://`.
	schemaPattern = regexp.MustCompile(`^([\w+.-_]+://)`)
)

type options struct {
	File               string   `short:"o" long:"file" description:"The output file. Written in binary pcap format." required:"true"`
	ForceOverwriteFile bool     `short:"F" long:"force-overwrite" description:"Overwrites the output file if it already exists."`
	PcapAPIURL         string   `short:"u" long:"pcap-api-url" description:"The URL of the PCAP API, e.g. pcap.cf.$LANDSCAPE_DOMAIN" env:"PCAP_API" required:"true"`
	Filter             string   `short:"f" long:"filter" description:"Allows to provide a filter expression in pcap filter format." required:"false"`
	Interface          string   `short:"i" long:"interface" description:"Specifies the network interface to listen on." default:"eth0" required:"false"`
	Type               string   `short:"t" long:"type" description:"Specifies the type of process to capture for the app." default:"web" required:"false"`
	BoshConfigFilename string   `short:"c" long:"bosh-config" description:"Path to the BOSH config file, used for the UAA Token" default:"${HOME}/.bosh/config" required:"false"`
	BoshEnvironment    string   `short:"e" long:"bosh-environment" description:"The BOSH environment to use for retrieving the BOSH UAA token from the BOSH config file" env:"BOSH_ENVIRONMENT" required:"false"`
	Deployment         string   `short:"d" long:"deployment" description:"The name of the deployment in which you would like to capture." required:"true"`
	InstanceGroups     []string `short:"g" long:"instance-group" description:"The name of an instance group in the deployment in which you would like to capture. Can be defined multiple times." required:"true"`
	InstanceIds        []string `positional-arg-name:"ids" description:"The instance IDs of the deployment to capture." required:"false"`
	SnapLength         uint16   `short:"l" long:"snaplen" description:"Snap Length, defining the captured length of the packet, with the remainder truncated. The real packet length is recorded." default:"65535"`
	Verbose            bool     `short:"v" long:"verbose" description:"Show verbose debug information"`
	Quiet              bool     `short:"q" long:"quiet" description:"Show only warnings and errors"`
}

// init sets up the zap.Logger. Currently outputs to stderr in Console format.
func init() {
	atomicLogLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	outputPaths := []string{"stderr"}
	zapConfig := zap.Config{
		Level:             atomicLogLevel,
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          "console",
		EncoderConfig:     encoderConfig,
		OutputPaths:       outputPaths,
		ErrorOutputPaths:  outputPaths,
	}
	logger = zap.Must(zapConfig.Build())
	zap.ReplaceGlobals(logger)
	logger.Debug("successfully set up logger", zap.Strings("output-paths", outputPaths))
}

func main() {
	var (
		err         error
		opts        options
		apiURL      *url.URL
		client      *pcap.Client
		environment *Environment
	)

	defer func() {
		if err != nil {
			var flagsError *flags.Error
			if !errors.As(err, &flagsError) {
				// The flags package prints out an error message about missing / incorrect flags already.
				// Printing out the error via logger duplicates the information and looks messy.
				// So only log the error if it's not a flags.Error.
				logger.Error("execution failed", zap.Error(err))
			}
			os.Exit(1)
		}
	}()

	// Parse command-line arguments
	_, err = flags.Parse(&opts)
	if err != nil {
		return
	}

	// we cannot log to Debug before this point
	err = setLogLevel(opts.Verbose, opts.Quiet)
	if err != nil {
		return
	}

	logger.Debug("pcap-bosh-cli initialized", zap.Int64("compatibilityLevel", pcap.CompatibilityLevel))

	apiURL, environment, err = initFromOptions(opts)
	if err != nil {
		return
	}

	logger.Debug("bosh-config and tokens successfully updated")

	// set up pcap-client/pcap-api connection
	client, err = pcap.NewClient(opts.File, logger, pcap.LogMessageWriter{Log: logger})
	if err != nil {
		err = fmt.Errorf("could not set up pcap-client: %w", err)
		return
	}
	err = client.ConnectToAPI(apiURL)
	if err != nil {
		err = fmt.Errorf("could not connect to pcap-api: %w", err)
		return
	}
	err = checkAPIHealth(client)
	if err != nil {
		return
	}

	logger.Debug("pcap-client successfully initialized and connected to pcap-api")

	go pcap.StopOnSignal(logger, client, nil, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	endpointRequest := createEndpointRequest(environment.AccessToken, opts.Deployment, opts.InstanceGroups)
	captureOptions := createCaptureOptions(opts.Interface, opts.Filter, uint32(opts.SnapLength))

	err = client.CaptureRequest(endpointRequest, captureOptions)
	if err != nil {
		return
	}

	logger.Info("capture finished successfully")
}

func initFromOptions(opts options) (*url.URL, *Environment, error) {
	var (
		boshConfig  *Config
		apiURL      *url.URL
		environment *Environment
	)
	err := checkOutputFile(opts.File, opts.ForceOverwriteFile)
	if err != nil {
		return nil, nil, err
	}

	// update bosh tokens/config
	apiURL, err = parseAPIURL(urlWithScheme(opts.PcapAPIURL))
	if err != nil {
		return nil, nil, err
	}

	boshConfig, err = configFromFile(opts.BoshConfigFilename)
	if err != nil {
		return nil, nil, err
	}

	environment, err = connectToEnvironment(opts.BoshEnvironment, boshConfig)
	if err != nil {
		return nil, nil, err
	}

	err = environment.UpdateTokens()
	if err != nil {
		return nil, nil, err
	}

	err = writeBoshConfig(boshConfig, opts.BoshConfigFilename)
	if err != nil {
		return nil, nil, err
	}

	return apiURL, environment, nil
}

// checkOutputFile checks if the specified output-file already exists.
// If it does exist and overwrite is specified, it will be deleted.
// If it doesn't exist and the parent-directory is invalid an error is returned.
func checkOutputFile(file string, overwrite bool) error {
	// Check if the file already exists
	_, err := os.Stat(file)

	// File already exists
	if err == nil {
		if overwrite {
			return os.Remove(file)
		}
		return fmt.Errorf("outputfile %s already exists (Use option '-F' to overwrite file)", file)
	}
	// File doesn't exist, check if path is valid
	fileInfo, err := os.Stat(filepath.Dir(file))
	if err != nil || !fileInfo.IsDir() {
		return fmt.Errorf("cannot write file %s. %s does not exist", file, fileInfo.Name())
	}
	return nil
}

// checkAPIHealth accepts a Client with working client-connection and an environmentAlias.
//
// Using the clients connection to the pcap-api it checks whether the api endpoint is healthy in general
// and if it supports requests to the Bosh Environment specified in environmentAlias.
func checkAPIHealth(c *pcap.Client) error {
	err := c.CheckAPIHandler(pcap.BoshResolverName)
	if err != nil {
		return fmt.Errorf("pcap-api does not support BOSH resolver: %w", err)
	}
	return nil
}

// setLogLevel sets the log level of the zap.Logger created in setupLogging via atomicLogLevel
//
// It accepts bool values of the verbose and quiet options.
//
// verbose sets the loglevel to Debug, quiet to Warn. The default is Info. If both verbose and quiet are specified, we return an error.
func setLogLevel(verbose bool, quiet bool) error {
	if verbose && quiet {
		return fmt.Errorf("options verbose and quiet are mutually exclusive")
	}

	logLevel := zapcore.InfoLevel
	if verbose {
		logLevel = zapcore.DebugLevel
	} else if quiet {
		logLevel = zapcore.WarnLevel
	}
	atomicLogLevel.SetLevel(logLevel)
	logger.Debug("set log-level", zap.String("log-level", logLevel.String()))
	return nil
}

// configFromFile fetches the content of the specified bosh-config file under path configFilename
// and returns a Config struct.
func configFromFile(configFilename string) (*Config, error) {
	configReader, err := os.Open(os.ExpandEnv(configFilename))
	if err != nil {
		return nil, fmt.Errorf("could not open bosh-config: %w", err)
	}
	defer func() {
		_ = configReader.Close()
	}()

	var config Config
	err = yaml.NewDecoder(configReader).Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("could not parse the provided bosh-config %w", err)
	}

	logger.Debug("read bosh-config")
	return &config, nil
}

// urlWithScheme prepends url with https:// if no scheme is specified.
//
// Returns url with scheme prefix.
func urlWithScheme(url string) string {
	if !schemaPattern.MatchString(url) {
		logger.Debug("URL has no scheme. Defaulting to https.", zap.String("url", url))
		return "https://" + url
	}
	return url
}

// parseAPIURL parses the provided urlString into a URL.
//
// Returns an error if the URL could not be parsed or is not a http(s) URL.
func parseAPIURL(urlString string) (*url.URL, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return nil, fmt.Errorf("invalid URL, must start with http or https: %s", parsedURL)
	}
	return parsedURL, nil
}

// connectToEnvironment searches the provided Config for the environmentAlias, and when found connects to this environment.
//
// Returns a matching environment if one exists and the connection works, and an error indicating the cause otherwise.
func connectToEnvironment(environmentAlias string, config *Config) (*Environment, error) {
	for _, environment := range config.Environments {
		if environment.Alias == environmentAlias {
			logger.Debug("found matching bosh-environment", zap.String("environment-alias", environment.Alias))

			err := environment.connect()
			if err != nil {
				return nil, err
			}

			return &environment, nil
		}
	}
	return nil, fmt.Errorf("could not find bosh-environment %s in BOSH CLI config", environmentAlias)
}

// createEndpointRequest is a helper function to create a pcap.EndpointRequest from parameters.
func createEndpointRequest(token string, deployment string, instanceGroups []string) *pcap.EndpointRequest {
	endpointRequest := &pcap.EndpointRequest{
		Request: &pcap.EndpointRequest_Bosh{
			Bosh: &pcap.BoshRequest{
				Token:      token,
				Deployment: deployment,
				Groups:     instanceGroups,
			},
		},
	}
	logger.Debug("created endpoint-request", zap.Any("endpoint-request", endpointRequest))
	return endpointRequest
}

// createCaptureOptions is a helper function to create a pcap.CaptureOptions struct from parameters.
func createCaptureOptions(device string, filter string, snaplen uint32) *pcap.CaptureOptions {
	captureOptions := &pcap.CaptureOptions{
		Device:  device,
		Filter:  filter,
		SnapLen: snaplen,
	}
	logger.Debug("created capture-options", zap.Any("capture-options", captureOptions))
	return captureOptions
}

// writeBoshConfig writes the Config to the config-file under configFileName.
func writeBoshConfig(config *Config, configFileName string) error {
	configWriter, err := os.Create(os.ExpandEnv(configFileName))
	if err != nil {
		return fmt.Errorf("failed to create bosh-config file: %w", err)
	}

	err = yaml.NewEncoder(configWriter).Encode(config)
	if err != nil {
		return fmt.Errorf("failed to update bosh-config file: %w", err)
	}
	logger.Info("wrote updated bosh config/tokens to file", zap.String("config-file", configFileName))
	return nil
}

// Config represents the content of the bosh config-file (default location: ~/.bosh/config).
//
// It contains a list of bosh Environments.
type Config struct {
	Environments []Environment `yaml:"environments"`
}

// Environment contains all the necessary information to connect to a specific bosh-director.
//
// Must be initialized using `Environment.connect()`.
type Environment struct {
	AccessToken     string       `yaml:"access_token" validate:"required"`
	AccessTokenType string       `yaml:"access_token_type" validate:"required"`
	Alias           string       `yaml:"alias" validate:"required"`
	CaCert          string       `yaml:"ca_cert" validate:"required"`
	RefreshToken    string       `yaml:"refresh_token" validate:"required"`
	URL             string       `yaml:"url" validate:"required,url"`
	DirectorURL     *url.URL     `yaml:"-"`
	UaaURL          *url.URL     `yaml:"-"`
	client          *http.Client `yaml:"-"`
}

// UpdateTokens refreshes the bosh authentication token obtained from the BOSH CLI config.
//
// connect(env, opts) must be called before calling UpdateTokens!
func (e *Environment) UpdateTokens() error {
	if e.client == nil {
		return pcap.ErrBoshNotConnected
	}

	err := e.refreshTokens()
	if err != nil {
		return fmt.Errorf("failed to refresh bosh access token: %w", err)
	}
	return nil
}

// connect uses the URL from the parsed Bosh environment of a config, sets up the http client for use with either TLS or plain HTTP
// and uses this client to establish a connection to the BOSH Director and its UAA.
func (e *Environment) connect() error {
	err := e.setup()

	if err != nil {
		return err
	}

	err = e.fetchUAAURL()
	if err != nil {
		return err
	}

	return nil
}

// setup configures the BOSH http client for a given environment.
func (e *Environment) setup() error {
	var err error
	e.DirectorURL, err = url.Parse(urlWithScheme(e.URL))
	if err != nil {
		return fmt.Errorf("error parsing environment url (%v): %w", e.URL, err)
	}

	// Workaround for URL.JoinPath, which is buggy: https://github.com/golang/go/issues/58605
	if e.DirectorURL.Path == "" {
		e.DirectorURL.Path = "/"
	}

	// If no port was provided, use BOSH default port
	if e.DirectorURL.Port() == "" {
		e.DirectorURL.Host = fmt.Sprintf("%s:%d", e.DirectorURL.Host, BoshDefaultPort)
	}

	if e.DirectorURL.Scheme != "https" {
		logger.Warn("using unencrypted connection to bosh-director", zap.String("bosh-director-url", e.DirectorURL.String()))
		e.client = http.DefaultClient
	} else {
		logger.Info("using TLS-encrypted connection to bosh-director", zap.String("bosh-director-url", e.DirectorURL.String()))
		transport := http.DefaultTransport.(*http.Transport).Clone()

		if e.CaCert != "" {
			boshCA := x509.NewCertPool()
			ok := boshCA.AppendCertsFromPEM([]byte(e.CaCert))
			if !ok {
				return fmt.Errorf("could not add BOSH Director CA from bosh-config, adding to the cert pool failed")
			}
			transport.TLSClientConfig.RootCAs = boshCA
		}

		e.client = &http.Client{
			Transport: transport,
		}
	}
	return nil
}

// fetchUAAURL connects to the bosh-director API to fetch the bosh-uaa API URL.
func (e *Environment) fetchUAAURL() error {
	res, err := e.client.Do(&http.Request{
		Method: http.MethodGet,
		URL:    e.DirectorURL.JoinPath("/info"),
		Header: http.Header{
			"Accept": {"application/json"},
		},
	})
	if err != nil {
		return fmt.Errorf("could not get response from bosh-director: %w", err)
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d from bosh-director", res.StatusCode)
	}

	var info pcap.BoshInfo
	err = json.NewDecoder(res.Body).Decode(&info)
	if err != nil {
		return err
	}

	if info.UserAuthentication.Type != BoshAuthTypeUAA {
		return fmt.Errorf("unsupported authentication type '%s'", info.UserAuthentication.Type)
	}

	uaaURL, err := url.Parse(info.UserAuthentication.Options.URL)
	if err != nil {
		return err
	}
	e.UaaURL = uaaURL

	// Workaround for URL.JoinPath, which is buggy: https://github.com/golang/go/issues/58605
	if e.UaaURL.Path == "" {
		e.UaaURL.Path = "/"
	}

	return nil
}

// refreshTokens connects to the bosh-uaa API to fetch updated bosh access- & refresh-token.
func (e *Environment) refreshTokens() error {
	if e.RefreshToken == "" {
		return fmt.Errorf("no refresh token found in bosh config. please login first")
	}
	req := http.Request{
		Method: http.MethodPost,
		URL:    e.UaaURL.JoinPath("/oauth/token"),
		Header: http.Header{
			"Accept":        {"application/json"},
			"Content-Type":  {"application/x-www-form-urlencoded"},
			"Authorization": {fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte("bosh_cli:")))},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {e.RefreshToken},
		}.Encode()))),
	}
	res, err := e.client.Do(&req)
	if err != nil {
		return err
	}

	defer func() { _ = res.Body.Close() }()

	var newTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	err = json.NewDecoder(res.Body).Decode(&newTokens)
	if err != nil {
		return err
	}

	e.RefreshToken = newTokens.RefreshToken
	e.AccessTokenType = newTokens.TokenType
	e.AccessToken = newTokens.AccessToken

	return nil
}
