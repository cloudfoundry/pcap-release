package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"regexp"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/bosh"

	"github.com/jessevdk/go-flags"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

var (
	logger         *zap.Logger
	atomicLogLevel zap.AtomicLevel
)

type options struct {
	File               string   `short:"o" long:"file" description:"The output file. Written in binary pcap format." required:"true"`
	PcapAPIURL         string   `short:"u" long:"pcap-api-url" description:"The URL of the PCAP API, e.g. pcap.cf.$LANDSCAPE_DOMAIN" env:"PCAP_API" required:"true"`
	Filter             string   `short:"f" long:"filter" description:"Allows to provide a filter expression in pcap filter format." required:"false"`
	Interface          string   `short:"i" long:"interface" description:"Specifies the network interface to listen on." default:"eth0" required:"false"`
	Type               string   `short:"t" long:"type" description:"Specifies the type of process to capture for the app." default:"web" required:"false"`
	BoshConfigFilename string   `short:"c" long:"bosh-config" description:"Path to the BOSH config file, used for the UAA Token" default:"${HOME}/.bosh/config" required:"false"`
	BoshEnvironment    string   `short:"e" long:"bosh-environment" description:"The BOSH environment to use for retrieving the BOSH UAA token from the BOSH config file" default:"bosh" required:"false"`
	Deployment         string   `short:"d" long:"deployment" description:"The name of the deployment in which you would like to capture." required:"true"`
	InstanceGroups     []string `short:"g" long:"instance-group" description:"The name of an instance group in the deployment in which you would like to capture. Can be defined multiple times." required:"true"`
	InstanceIds        []string `positional-arg-name:"ids" description:"The instance IDs of the deployment to capture." required:"false"`
	Verbose            []bool   `short:"v" long:"verbose" description:"Show verbose debug information"`
}

// TODO: still too long but how can we split it into multiple methods?
func main() {
	var (
		err  error
		opts options
	)
	setupLogging()

	defer func() {
		if err != nil {
			logger.Panic("execution failed", zap.Error(err))
		}
	}()

	// Parse command-line arguments
	_, err = flags.ParseArgs(&opts, os.Args[1:])
	if err != nil {
		err = fmt.Errorf("could not parse the provided arguments %w", err)
		return
	}

	setLogLevel(opts.Verbose) // we cannot log to Debug before this point

	logger.Debug("pcap-bosh-cli initialized", zap.Int64("compatibilityLevel", pcap.CompatibilityLevel))

	// update bosh tokens/config
	apiURL, err := parseAPIURL(urlWithScheme(opts.PcapAPIURL))
	if err != nil {
		return
	}
	boshConfig, err := getBoshConfigFromFile(opts.BoshConfigFilename)
	if err != nil {
		return
	}
	environment, err := getEnvironment(opts.BoshEnvironment, boshConfig)
	if err != nil {
		return
	}
	err = environment.UpdateTokens()
	if err != nil {
		return
	}
	err = writeBoshConfig(boshConfig, opts.BoshConfigFilename)
	if err != nil {
		return
	}

	logger.Debug("bosh-config and tokens successfully updated")

	// set up pcap-client/pcap-api connection
	client, err := pcap.NewClient(opts.File)
	if err != nil {
		err = fmt.Errorf("could not set up pcap-client %w", err)
		return
	}
	err = client.ConnectToAPI(apiURL)
	if err != nil {
		err = fmt.Errorf("could not connect to pcap-api %w", err)
		return
	}

	logger.Debug("pcap-client successfully initialized and connected to pcap-api")

	// set up capture request
	ctx := context.Background()
	ctx, cancel := pcap.WithCancelCause(ctx)
	setupContextCancel(cancel)
	endpointRequest := createEndpointRequest(environment.AccessToken, opts.Deployment, opts.InstanceGroups)
	captureOptions := createCaptureOptions(opts.Interface, opts.Filter, 65_000) // TODO: get snaplen from config or parameters

	// perform capture request
	err = client.HandleRequest(endpointRequest, captureOptions, ctx, cancel)
	if err != nil {
		err = fmt.Errorf("encountered error during request handling: %w", err)
		return
	}

	// handle results of capture request
	err = pcap.Cause(ctx)
	if err != nil {
		if status.Code(err) == codes.OK {
			logger.Info("capture finished successfully")
			return
		}
		err = fmt.Errorf("finished with error %w", err)
		return
	}
}

// sets up the zap.Logger. Currently outputs to stderr in Console format.
func setupLogging() {
	atomicLogLevel = zap.NewAtomicLevelAt(zap.WarnLevel)
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	outputPaths := []string{"stderr"} //TODO: make configurable?
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

// setLogLevel sets the log level of the zap.Logger created in setupLogging via atomicLogLevel
// It accepts []bool as parameter as this is the output of the opts.Verbose flag:
// -v sets the level to zapcore.InfoLevel, -vv (and more v's) sets zapcore.DebugLevel.
func setLogLevel(verbose []bool) {
	var logLevel zapcore.Level
	switch len(verbose) {
	case 0:
		logLevel = zapcore.WarnLevel
	case 1:
		logLevel = zapcore.InfoLevel
	default: // if more than one -v is given as argument
		logLevel = zapcore.DebugLevel
	}

	atomicLogLevel.SetLevel(logLevel)

	logger.Debug("set log-level", zap.String("log-level", logLevel.String()))
}

// getBoshConfigFromFile fetches the content of the specified bosh-config file under path configFilename
// and returns a bosh.Config struct.
func getBoshConfigFromFile(configFilename string) (*bosh.Config, error) {
	var err error
	configFilename = os.ExpandEnv(configFilename)
	configReader, err := os.Open(configFilename)
	if err != nil {
		return nil, fmt.Errorf("could not open bosh-config %w", err)
	}
	config := &bosh.Config{}
	err = yaml.NewDecoder(configReader).Decode(config)
	if err != nil {
		return nil, fmt.Errorf("could not parse the provided bosh-config %w", err)
	}
	logger.Debug("read bosh-config", zap.Any("bosh-config", config))
	return config, nil
}

// urlWithScheme prepends a string with https:// if no scheme is specified.
//
// returns url with scheme prefix.
func urlWithScheme(url string) string {
	re := regexp.MustCompile(`^([\w+.-_]+://)`)
	if !re.MatchString(url) {
		return "https://" + url
	}
	logger.Debug("pcap-api URL contains http/https scheme")
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

// getEnvironment searches the provided bosh.Config (config) for the environmentAlias.
//
// Returns a matching environment if one exists.
func getEnvironment(environmentAlias string, config *bosh.Config) (*bosh.Environment, error) {
	for _, environment := range config.Environments {
		if environment.Alias == environmentAlias {
			logger.Debug("found matching bosh-environment", zap.String("environment-alias", environment.Alias))
			return &environment, nil
		}
	}
	return nil, fmt.Errorf("could not find bosh-environment %s in config", environmentAlias)
}

// setupContextCancel starts a goroutine to capture the SIGINT signal that's sent if the user sends CTRL+C.
//
// It then stops the capture using the pcap.CancelCauseFunc cancel.
func setupContextCancel(cancel pcap.CancelCauseFunc) {
	logger.Debug("registering signal handler for SIGINT")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		logger.Debug("waiting for SIGINT to be sent")
		<-sigChan

		logger.Debug("received SIGINT, stopping capture")
		// cancelCause := pcap.errorf() // TODO: make public so we can use the status to accept this as a successful exit
		cancelCause := fmt.Errorf("client stop, received SIGINT")
		cancel(cancelCause)
	}()
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

// writeBoshConfig writes the bosh.Config (config) to the config-file under configFileName.
func writeBoshConfig(config *bosh.Config, configFileName string) error {
	configWriter, err := os.Create(configFileName)
	if err != nil {
		return fmt.Errorf("failed to create bosh-config file %w", err)
	}

	err = yaml.NewEncoder(configWriter).Encode(config)
	if err != nil {
		return fmt.Errorf("failed to update bosh-config file %w", err)
	}
	logger.Info("wrote updated bosh config/tokens to file", zap.String("config-file", configFileName))
	return nil
}
