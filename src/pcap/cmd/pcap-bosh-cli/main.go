package main

import (
	"context"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/bosh"
	"github.com/jessevdk/go-flags"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
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

	// Parse command-line arguments
	_, err = flags.ParseArgs(&opts, os.Args[1:])
	if err != nil {
		logger.Fatal("could not parse the provided arguments", zap.Error(err))
	}

	setLogLevel(opts.Verbose) // we cannot log to Debug before this point

	// update bosh tokens/config
	apiURL := parseAPIURL(opts.PcapAPIURL)
	boshConfig := getBoshConfigFromFile(opts.BoshConfigFilename)
	environment := getEnvironment(opts.BoshEnvironment, boshConfig)
	err = environment.UpdateTokens()
	if err != nil {
		logger.Fatal("could not refresh bosh tokens", zap.Error(err))
	}
	writeBoshConfig(boshConfig, opts.BoshConfigFilename)

	//initialization done
	logger.Debug("pcap-bosh-cli initialized", zap.Int64("compatibilityLevel", pcap.CompatibilityLevel))

	//set up pcap-client/pcap-api connection
	client, err := pcap.NewClient(opts.File, logger)
	if err != nil {
		logger.Fatal("could not set up pcap-client", zap.Error(err))
	}
	err = client.ConnectToAPI(apiURL)
	if err != nil {
		logger.Fatal("could not connect to pcap-api", zap.Error(err))
	}

	//set up capture request
	ctx := context.Background()
	ctx, cancel := pcap.WithCancelCause(ctx)
	setupContextCancel(cancel)
	endpointRequest := createEndpointRequest(environment.AccessToken, opts.Deployment, opts.InstanceGroups)
	captureOptions := createCaptureOptions(opts.Interface, opts.Filter, 65_000) // TODO: get snaplen from config or parameters

	//perform capture request
	err = client.HandleRequest(endpointRequest, captureOptions, ctx, cancel)
	if err != nil {
		logger.Fatal("encountered error during request handling: %s", zap.Error(err))
	}

	//handle results of capture request
	err = pcap.Cause(ctx)
	if err != nil {
		if status.Code(err) == codes.OK {
			logger.Info("capture finished successfully")
			return
		}
		logger.Fatal("finished with error", zap.Error(err))
	}
}

func setupLogging() {
	atomicLogLevel = zap.NewAtomicLevelAt(zap.WarnLevel)
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	zapConfig := zap.Config{
		Level:             atomicLogLevel,
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          "console",
		EncoderConfig:     encoderConfig,
		OutputPaths:       []string{"stderr"}, //TODO: make configurable?
		ErrorOutputPaths:  []string{"stderr"},
	}
	logger = zap.Must(zapConfig.Build())
	zap.ReplaceGlobals(logger)
	logger.Debug("successfully set up logger")
}

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

func getBoshConfigFromFile(configFilename string) *bosh.Config {
	var err error
	configFilename = os.ExpandEnv(configFilename)
	configReader, err := os.Open(configFilename)
	if err != nil {
		logger.Fatal("could not open bosh-config", zap.Any("bosh-config", configFilename), zap.Error(err))
	}
	config := &bosh.Config{}
	err = yaml.NewDecoder(configReader).Decode(config)
	if err != nil {
		logger.Fatal("could not parse the provided bosh-config", zap.Error(err), zap.String("bosh-config-path", configFilename))
	}
	logger.Debug("read bosh-config", zap.Any("bosh-config", config))
	return config
}

func parseAPIURL(urlString string) *url.URL {
	// check if urlString contains a scheme
	re := regexp.MustCompile(`^(\w+://)`) //
	if re.MatchString(urlString) {
		if strings.HasPrefix(urlString, "http") { // http & https are the only supported protocols
			logger.Debug("pcap-api URL contains http/https scheme")
			url, err := url.Parse(urlString)
			if err != nil {
				logger.Fatal("could not parse pcap-api URL", zap.String("pcap-api URl", urlString), zap.Error(err))
			}
			return url
		}
		logger.Fatal("unsupported pcap-api URL scheme", zap.String("pcap-api URl", urlString))
	}
	logger.Info("pcap-api URL does not contain scheme. Defaulting to HTTPS.", zap.String("pcap-api URl", urlString))
	return &url.URL{Scheme: "https", Host: urlString}
}

func getEnvironment(environmentAlias string, config *bosh.Config) *bosh.Environment {
	for _, environment := range config.Environments {
		if environment.Alias == environmentAlias {
			logger.Debug("found matching bosh-environment", zap.String("environment-alias", environment.Alias))
			return &environment
		}
	}
	logger.Fatal("could not find bosh-environment in config", zap.String("environment-alias", environmentAlias))
	return &bosh.Environment{}
}

func setupContextCancel(cancel pcap.CancelCauseFunc) {
	logger.Debug("registering signal handler for SIGINT")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		logger.Debug("waiting for SIGINT to be sent")
		<-sigChan

		logger.Debug("received SIGINT, stopping progress")
		//cancelCause := pcap.errorf() // TODO: make public so we can use the status to accept this as a successful exit
		cancelCause := fmt.Errorf("client stop")
		cancel(cancelCause)
	}()
}

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

func createCaptureOptions(device string, filter string, snaplen uint32) *pcap.CaptureOptions {
	captureOptions := &pcap.CaptureOptions{
		Device:  device,
		Filter:  filter,
		SnapLen: snaplen,
	}
	logger.Debug("created capture-options", zap.Any("capture-options", captureOptions))
	return captureOptions
}

func writeBoshConfig(config *bosh.Config, configFileName string) {
	configWriter, err := os.Create(configFileName)
	if err != nil {
		logger.Fatal("failed to create bosh-config file", zap.Error(err))
	}

	err = yaml.NewEncoder(configWriter).Encode(config)
	if err != nil {
		logger.Fatal("failed to update bosh-config file", zap.Error(err))
	}
	logger.Info("wrote updated bosh config/tokens to file", zap.String("config-file", configFileName))
}
