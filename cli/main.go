package main

import (
	"code.cloudfoundry.org/bytefmt"
	"code.cloudfoundry.org/cli/plugin"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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
		Index      string     `short:"i" long:"index" description:"Specifies the instance index of the app to capture."  default:"0" required:"false"`
		Type       string     `short:"t" long:"type" description:"Specifies the type of process to capture for the app." default:"web" required:"false"`
		Positional positional `positional-args:"true" required:"true"`
	}

	args, err := flags.ParseArgs(&opts, args[1:])

	if err != nil {
		return
	}

	loggedIn, err := cliConnection.IsLoggedIn()

	if !loggedIn || err != nil {
		fmt.Println("Please log in first.")
		return
	}

	ccApi, err := cliConnection.ApiEndpoint()

	if err != nil {
		fmt.Printf("Could not get CF API endpoint: %s\n", err)
		return
	}

	pcapAPI := strings.Replace(ccApi, "api.", "pcap.", 1)

	//DEBUG
	pcapAPIEnv, present := os.LookupEnv("PCAP_API")
	if present {
		pcapAPI = pcapAPIEnv
	}
	//DEBUG END

	appName := opts.Positional.AppName
	app, err := cliConnection.GetApp(appName)

	if err != nil {
		fmt.Printf("Could not get app id for app %s: %s\n", appName, err)
		return
	}

	tp := http.DefaultTransport.(*http.Transport).Clone()
	tp.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //TODO remove before putting into production
	httpClient := &http.Client{Transport: tp}

	reqUrl, err := url.Parse(fmt.Sprintf("%s/capture?appid=%s&index=%s&type=%s&device=%s&filter=%s", pcapAPI, app.Guid, opts.Index, opts.Type, opts.Device, opts.Filter))

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
		URL:    reqUrl,
		Header: map[string][]string{
			"Authorization": {authToken},
		},
	}
	fmt.Printf("Capturing traffic of app %s (%s) into file %s ...\n", appName, opts.Index, opts.File)
	r, err := httpClient.Do(req)

	if err != nil {
		fmt.Printf("Could not receive pcap stream: %s\n", err)
		return
	}
	defer r.Body.Close()

	if r.StatusCode != 200 {
		fmt.Printf("Unexpected status code from pcap api server: %d\n", r.StatusCode)
		msg, _ := io.ReadAll(r.Body)
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
		n, err := r.Body.Read(buffer)
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
					Usage: "pcap - stream pcap data from your app to disk\n   cf pcap <app> --file <file.pcap> [--filter <expression>] [--index <index>] [--type <type>] [--device <device>]",
					Options: map[string]string{
						"file":   "The output file. Written in binary pcap format.",
						"filter": "Allows to provide a filter expression in pcap filter format. See https://linux.die.net/man/7/pcap-filter",
						"index":  "Specifies the instance index of the app to capture. Default: 0",
						"type":   "Specifies the type of process to capture for the app. Default: web",
						"device": "Specifies the network device to listen on. Default: eth0",
					},
				},
			},
		},
	}
}
