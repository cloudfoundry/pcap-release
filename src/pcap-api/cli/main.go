package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"code.cloudfoundry.org/bytefmt"
	"code.cloudfoundry.org/cli/plugin"
	"github.com/jessevdk/go-flags"
)

type PcapServerCLI struct {
}

func main() {
	plugin.Start(new(PcapServerCLI))
}

func (cli *PcapServerCLI) Run(cliConnection plugin.CliConnection, args []string) {
	// Initialize flags
	type positional struct {
		AppName string `positional-arg-name:"app" description:"The app to capture." required:"true"`
	}

	var opts struct {
		File       string     `short:"o" long:"file" description:"The output file. Written in binary pcap format." required:"true"`
		Filter     string     `short:"f" long:"filter" description:"Allows to provide a filter expression in pcap filter format." required:"false"`
		Device     string     `short:"d" long:"device" description:"Specifies the network device to listen on." default:"eth0" required:"false"`
		Instance   string     `short:"i" long:"instance" description:"Specifies the instances of the app to capture."  default:"all" required:"false"`
		Type       string     `short:"t" long:"type" description:"Specifies the type of process to capture for the app." default:"web" required:"false"`
		Positional positional `positional-args:"true" required:"true"`
	}

	_, err := flags.ParseArgs(&opts, args[1:])

	if err != nil {
		return
	}

	loggedIn, err := cliConnection.IsLoggedIn()

	if !loggedIn || err != nil {
		fmt.Println("Please log in first.")
		return
	}

	ccAPI, err := cliConnection.ApiEndpoint()

	if err != nil {
		fmt.Printf("Could not get CF API endpoint: %s\n", err)
		return
	}

	pcapAPI := strings.Replace(ccAPI, "api.", "pcap.", 1)

	// DEBUG
	pcapAPIEnv, present := os.LookupEnv("PCAP_API")
	if present {
		pcapAPI = pcapAPIEnv
	}
	// DEBUG END

	appName := opts.Positional.AppName
	app, err := cliConnection.GetApp(appName)

	if err != nil {
		fmt.Printf("Could not get app id for app %s: %s\n", appName, err)
		return
	}

	var indices []string

	if opts.Instance == "all" {
		// special case: all instances
		for index := 0; index < app.InstanceCount; index++ {
			indices = append(indices, fmt.Sprintf("%d", index))
		}
	} else {
		indices = strings.Split(opts.Instance, ",")
	}

	tp := http.DefaultTransport.(*http.Transport).Clone()
	tp.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // TODO remove before putting into production
	httpClient := &http.Client{Transport: tp}

	urlStr := fmt.Sprintf("%s/capture?appid=%s&type=%s&device=%s&filter=%s", pcapAPI, app.Guid, opts.Type, opts.Device, opts.Filter)
	for _, index := range indices {
		urlStr = fmt.Sprintf("%s&index=%s", urlStr, index)
	}

	reqURL, err := url.Parse(urlStr)

	if err != nil {
		fmt.Printf("Could not parse URL: %s\n", err)
		return
	}

	authToken, err := cliConnection.AccessToken()

	if err != nil {
		fmt.Printf("Could not get access token: %s\n", err)
		return
	}

	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: map[string][]string{
			"Authorization": {authToken},
		},
	}
	fmt.Printf("Capturing traffic of app %s %s into file %s ...\n", appName, indices, opts.File)
	resp, err := httpClient.Do(req)

	if err != nil {
		fmt.Printf("Could not receive pcap stream: %s\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Unexpected status code from pcap api server: %d\n", resp.StatusCode)
		msg, _ := io.ReadAll(resp.Body)
		fmt.Printf("Details: %s\n", msg)
		return
	}

	file, err := os.Create(opts.File)
	defer file.Close()

	if err != nil {
		fmt.Printf("Could not open %s for writing: %s\n", opts.File, err)
		return
	}
	totalBytes := uint64(0)
	updateProgress := func(nBytes int) {
		totalBytes += uint64(nBytes)
		fmt.Printf("\033[2K\rRead %d bytes from stream (%s total)", nBytes, bytefmt.ByteSize(totalBytes))
	}
	updateProgress(0)
	for {
		buffer := make([]byte, 4096)
		n, err := resp.Body.Read(buffer)
		updateProgress(n)
		if n > 0 {
			file.Write(buffer[:n])
		}
		if err != nil {
			handleIOError(err)
			return
		}
	}
}

func handleIOError(err error) {
	if errors.Is(err, io.EOF) {
		fmt.Println("Done.")
	} else {
		fmt.Printf("Error during capture: %s\n", err)
	}
}

func (cli *PcapServerCLI) GetMetadata() plugin.PluginMetadata {
	return plugin.PluginMetadata{
		Name: "PcapServerCLI",
		Version: plugin.VersionType{
			Major: 0,
			Minor: 1,
			Build: 0,
		},
		Commands: []plugin.Command{
			{
				Name:     "pcap",
				Alias:    "tcpdump",
				HelpText: "Pcap captures network traffic of your apps. To obtain more information use --help",
				UsageDetails: plugin.Usage{
					Usage: "pcap - stream pcap data from your app to disk\n   cf pcap <app> --file <file.pcap> [--filter <expression>] [--instance <index>[,index]...] [--type <type>] [--device <device>]",
					Options: map[string]string{
						"file":     "The output file. Written in binary pcap format.",
						"filter":   "Allows to provide a filter expression in pcap filter format. See https://linux.die.net/man/7/pcap-filter",
						"instance": "Specifies the instances of the app to capture. Possible values: n | 0,1,..n | all Default: all",
						"type":     "Specifies the type of process to capture for the app. Default: web",
						"device":   "Specifies the network device to listen on. Default: eth0",
					},
				},
			},
		},
	}
}
