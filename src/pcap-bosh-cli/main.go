package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
	"os"
)

type environment struct {
	AccessToken     string `yaml:"access_token"`
	AccessTokenType string `yaml:"access_token_type"`
	Alias           string `yaml:"alias"`
	CaCert          string `yaml:"ca_cert"`
	RefreshToken    string `yaml:"refresh_token"`
	Url             string `yaml:"url"`
}

type boshConfig struct {
	Environments []environment `json:"environments"`
}

func main() {

	var opts struct {
		File            string   `short:"o" long:"file" description:"The output file. Written in binary pcap format." required:"true"`
		PcapApiUrl      string   `short:"u" long:"pcap-api-url" description:"The URL of the PCAP API, e.g. pcap.cf.$LANDSCAPE_DOMAIN" env:"PCAP_API" required:"true"`
		Filter          string   `short:"f" long:"filter" description:"Allows to provide a filter expression in pcap filter format." required:"false"`
		Device          string   `short:"i" long:"device" description:"Specifies the network device to listen on." default:"eth0" required:"false"`
		Type            string   `short:"t" long:"type" description:"Specifies the type of process to capture for the app." default:"web" required:"false"`
		BoshConfig      string   `short:"c" long:"bosh-config" description:"Path to the BOSH config file, used for the UAA Token" default:"${HOME}/.bosh/config" required:"false"`
		BoshEnvironment string   `short:"e" long:"bosh-environment" description:"The BOSH environment to use for retrieving the BOSH UAA token from the BOSH config file" default:"bosh" required:"false"`
		BoshToken       string   `short:"T" long:"token" description:"BOSH UAA Token to use for authentication (instead of BOSH config file)" env:"BOSH_TOKEN" default:"" required:"false"`
		Deployment      string   `short:"d" long:"deployment" description:"The name of the deployment in which you would like to capture." required:"true"`
		InstanceGroups  []string `short:"g" long:"instance-group" description:"The name of an instance group in the deployment in which you would like to capture. Can be defined multiple times." required:"true"`
		InstanceIds     []string `positional-arg-name:"ids" description:"The instance IDs of the deployment to capture." required:"false"`
	}

	_, err := flags.ParseArgs(&opts, os.Args[1:])

	if err != nil {
		panic(err)
	}

	if opts.BoshToken == "" {
		boshConfigPath := os.ExpandEnv(opts.BoshConfig)
		yamlFile, err := os.ReadFile(boshConfigPath)

		if err != nil {
			log.Printf("error while reading yaml file: %v ", err)

			return
		}

		bc := boshConfig{}

		err = yaml.Unmarshal(yamlFile, &bc)
		if err != nil {
			log.Printf("error while parsing yaml file %s: %v ", boshConfigPath, err)
			return
		}

		for _, e := range bc.Environments {
			if e.Alias == opts.BoshEnvironment {
				opts.BoshToken = e.AccessToken
			}
		}
	}

	print(opts.BoshToken)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// FIXME: add BOSH director CA
				InsecureSkipVerify: true,
			},
		},
	}

	res, err := client.Get(opts.PcapApiUrl)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	// log into bosh.

	//loggedIn, err := cliConnection.IsLoggedIn()
	//
	//if !loggedIn || err != nil {
	//	fmt.Println("Please log in first.")
	//	return
	//}

	//ccAPI, err := cliConnection.ApiEndpoint()
	//
	//if err != nil {
	//	fmt.Printf("Could not get CF API endpoint: %s\n", err)
	//	return
	//}
	//
	//pcapAPI := strings.Replace(ccAPI, "api.", "pcap.", 1)
	//
	//// DEBUG
	//pcapAPIEnv, present := os.LookupEnv("PCAP_API")
	//if present {
	//	pcapAPI = pcapAPIEnv
	//}
	//// DEBUG END
	//
	//appName := opts.Positional.AppName
	//app, err := cliConnection.GetApp(appName)
	//
	//if err != nil {
	//	fmt.Printf("Could not get app id for app %s: %s\n", appName, err)
	//	return
	//}
	//
	//var indices []string
	//
	//if opts.Instance == "all" {
	//	// special case: all instances
	//	for index := 0; index < app.InstanceCount; index++ {
	//		indices = append(indices, fmt.Sprintf("%d", index))
	//	}
	//} else {
	//	indices = strings.Split(opts.Instance, ",")
	//}
	//
	//tp := http.DefaultTransport.(*http.Transport).Clone()
	//tp.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // TODO remove before putting into production
	//httpClient := &http.Client{Transport: tp}
	//
	//urlStr := fmt.Sprintf("%s/capture?appid=%s&type=%s&device=%s&filter=%s", pcapAPI, app.Guid, opts.Type, opts.Device, opts.Filter)
	//for _, index := range indices {
	//	urlStr = fmt.Sprintf("%s&index=%s", urlStr, index)
	//}
	//
	//reqURL, err := url.Parse(urlStr)
	//
	//if err != nil {
	//	fmt.Printf("Could not parse URL: %s\n", err)
	//	return
	//}
	//
	//authToken, err := cliConnection.AccessToken()
	//
	//if err != nil {
	//	fmt.Printf("Could not get access token: %s\n", err)
	//	return
	//}
	//
	//req := &http.Request{
	//	Method: "GET",
	//	URL:    reqURL,
	//	Header: map[string][]string{
	//		"Authorization": {authToken},
	//	},
	//}
	//fmt.Printf("Capturing traffic of app %s %s into file %s ...\n", appName, indices, opts.File)
	//resp, err := httpClient.Do(req)
	//
	//if err != nil {
	//	fmt.Printf("Could not receive pcap stream: %s\n", err)
	//	return
	//}
	//defer resp.Body.Close()
	//
	//if resp.StatusCode != 200 {
	//	fmt.Printf("Unexpected status code from pcap api server: %d\n", resp.StatusCode)
	//	msg, _ := io.ReadAll(resp.Body)
	//	fmt.Printf("Details: %s\n", msg)
	//	return
	//}
	//
	//file, err := os.Create(opts.File)
	//defer file.Close()
	//
	//if err != nil {
	//	fmt.Printf("Could not open %s for writing: %s\n", opts.File, err)
	//	return
	//}
	//totalBytes := uint64(0)
	//updateProgress := func(nBytes int) {
	//	totalBytes += uint64(nBytes)
	//	fmt.Printf("\033[2K\rRead %d bytes from stream (%s total)", nBytes, bytefmt.ByteSize(totalBytes))
	//}
	//updateProgress(0)
	//for {
	//	buffer := make([]byte, 4096)
	//	n, err := resp.Body.Read(buffer)
	//	updateProgress(n)
	//	if n > 0 {
	//		file.Write(buffer[:n])
	//	}
	//	if err != nil {
	//		handleIOError(err)
	//		return
	//	}
	//}
}

func handleIOError(err error) {
	if errors.Is(err, io.EOF) {
		fmt.Println("Done.")
	} else {
		fmt.Printf("Error during capture: %s\n", err)
	}
}
