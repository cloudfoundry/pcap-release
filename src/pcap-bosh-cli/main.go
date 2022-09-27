package main

import (
	"errors"
	"fmt"
	flags "github.com/jessevdk/go-flags"
	"io"
	"os"
)

type environment struct {
	AccessToken     string `json:"access_token"`
	AccessTokenType string `json:"access_token_type"`
	Alias           string `json:"alias"`
	CaCert          string `json:"ca_cert"`
	RefreshToken    string `json:"refresh_token"`
	Url             string `json:"url"`
}

type boshConfig struct {
	Environments []environment `json:"environments"`
}

func main() {

	// Initialize flags
	type positional struct {
		Deployment  string   `positional-arg-name:"deployment" description:"The name of the deployment in which you would like to capture." required:"true"`
		InstanceIds []string `positional-arg-name:"ids" description:"The instance IDs of the deployment to capture." default:"all" required:"false"`
	}

	var opts struct {
		File       string     `short:"o" long:"file" description:"The output file. Written in binary pcap format." required:"true"`
		Filter     string     `short:"f" long:"filter" description:"Allows to provide a filter expression in pcap filter format." required:"false"`
		Device     string     `short:"d" long:"device" description:"Specifies the network device to listen on." default:"eth0" required:"false"`
		Type       string     `short:"t" long:"type" description:"Specifies the type of process to capture for the app." default:"web" required:"false"`
		Positional positional `positional-args:"true" required:"true"`
	}

	_, err := flags.ParseArgs(&opts, os.Args[1:])

	if err != nil {
		return
	}

	fmt.Printf("%+v", opts)

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
