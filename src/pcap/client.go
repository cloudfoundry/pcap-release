package pcap

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
)

type Client struct {
	endpointRequest *EndpointRequest
	packetOut       io.Writer
	messageOut      io.Writer
	signalChannel   chan os.Signal
	query           *BoshQuery
}

func NewClient(request *EndpointRequest, outputFile string) *Client {
	client := &Client{
		endpointRequest: request,
		messageOut:      os.Stderr,
		signalChannel:   make(chan os.Signal, 1),
	}

	if len(outputFile) == 0 {
		client.packetOut = os.Stdout
	} else {
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			client.packetOut, err = os.Create(outputFile)
			if err != nil {
				fmt.Println(err)
			}
		} else {
			log.Errorf("output file %s already exists", outputFile)
		}
	}

	return client
}

func (client *Client) handleRequest() {

	for {
		log.Infof("running high and dry")

	}

	<-client.signalChannel

	log.Infof("Received Stop Signal from Client, aborting")
}

//var parameters url.Values = map[string][]string{
//	"deployment":  {opts.Deployment},
//	"device":      {opts.Interface},
//	"filter":      {opts.Filter},
//	"instance_id": opts.InstanceIds,
//	"group":       opts.InstanceGroups,
//}
//
//req := &http.Request{
//	Method: "GET",
//	URL: &url.URL{
//		Scheme:   "https",
//		Host:     opts.PcapAPIURL,
//		Path:     "/capture/bosh",
//		RawQuery: parameters.Encode(),
//	},
//	Header: map[string][]string{
//		"Authorization": {fmt.Sprintf("Bearer %s", token.access)}, // TODO: bosh requires an upper-case version of `bearer` even though it is case insensitive, but there is a access token type which is lower-case...
//	},
//}
//
//instanceIds := "all"
//if len(opts.InstanceIds) > 0 {
//	instanceIds = strings.Join(opts.InstanceIds, ", ")
//}
//
//fmt.Printf("Capturing traffic of deployment: %s groups: %v instances: %v into file %s ...\n", opts.Deployment, opts.InstanceGroups, instanceIds, opts.File)
//res, err := client.Do(req)
//if err != nil {
//	fmt.Printf("Could not receive pcap stream: %s\n", err)
//	return
//}
//fmt.Println("foo")
//
//defer silentClose(res.Body)
//
//if res.StatusCode != http.StatusOK {
//	var msg []byte
//	msg, err = io.ReadAll(res.Body)
//	if err != nil {
//		panic(err.Error())
//	}
//
//	err = fmt.Errorf("unexpected statusResponse code api: %d (%s)", res.StatusCode, string(msg))
//	return
//}
//
//file, err := os.Create(opts.File)
//if err != nil {
//	return
//}
//
//defer silentClose(file)
//
//copyWg := &sync.WaitGroup{}
//copyWg.Add(1)
//go func(writer io.Writer, reader io.Reader) {
//	written, err := io.CopyBuffer(writer, reader, make([]byte, 1048576)) // 1 Mebibyte
//	if err != nil {
//		log.Errorf("copy operation stopped: %s", err.Error())
//	}
//	log.Infof("captured %s", bytefmt.ByteSize(uint64(written)))
//	copyWg.Done()
//}(file, res.Body)
//
//stopProgress := make(chan bool)
//go progress(file, stopProgress)
//
//log.Debug("registering signal handler for SIGINT")
//sigChan := make(chan os.Signal, 1)
//signal.Notify(sigChan, os.Interrupt)
//
//log.Debug("waiting for SIGINT to be sent")
//<-sigChan
//
//log.Debug("received SIGINT, stopping progress")
//stopProgress <- true
//
//log.Debug("stopping capture by closing response body")
//err = res.Body.Close()
//
//log.Debug("waiting for copy operation to stop")
//copyWg.Wait()
//
//log.Debug("syncing file to disk")
//err = file.Sync()
//if err != nil {
//	return
//}
//
//log.Debug("closing file")
//err = file.Close()
//if err != nil {
//	return
//},,
