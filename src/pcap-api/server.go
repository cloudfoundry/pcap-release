package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
)

type Api struct {
	httpServer *http.Server
	config     *Config
	ccBaseURL  string
	uaaBaseURL string
}

type cfAPIResponse struct {
	Links struct {
		CCv2 struct {
			Href string `json:"href"`
		} `json:"cloud_controller_v2"` //nolint:tagliatelle
		CCv3 struct {
			Href string `json:"href"`
		} `json:"cloud_controller_v3"`
		UAA struct {
			Href string `json:"href"`
		} `json:"uaa"`
	} `json:"links"`
}

type cfAppResponse struct {
	GUID string `json:"guid"`
	Name string `json:"name"`
}

type cfAppStatsResponse struct {
	Resources []struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
		Host  string `json:"host"`
	} `json:"resources"`
}

func (a *Api) handleHealth(response http.ResponseWriter, _ *http.Request) {
	response.WriteHeader(http.StatusOK)
}

func (a *Api) handleCapture(response http.ResponseWriter, request *http.Request) {

	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	appId := request.URL.Query().Get("appid")
	appIndicesStr := request.URL.Query()["index"]
	appType := request.URL.Query().Get("type")
	device := request.URL.Query().Get("device")
	filter := request.URL.Query().Get("filter")
	authToken := request.Header.Get("Authorization")

	if appId == "" {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("appid missing"))

		return
	}

	var appIndices []int

	if len(appIndicesStr) == 0 {
		appIndices = append(appIndices, 0) // default value
	} else {
		for _, appIndexStr := range appIndicesStr {
			appIndex, err := strconv.Atoi(appIndexStr)
			if err != nil {
				response.WriteHeader(http.StatusBadRequest)
				response.Write([]byte("could not parse index parameter"))
				return
			}
			appIndices = append(appIndices, appIndex)
		}
	}

	if appType == "" {
		appType = "web" // default value
	}

	if device == "" {
		device = "eth0" // default value
	}

	if authToken == "" {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("authentication required"))

		return
	}

	// Check if app can be seen by token
	appVisible, err := a.isAppVisibleByToken(appId, authToken)
	if err != nil {
		log.Errorf("could not check if app %s can be seen by token %s (%s)", appId, authToken, err)
		response.WriteHeader(http.StatusInternalServerError)

		return
	}
	if appVisible == false {
		log.Infof("app %s cannot be seen by token %s", appId, authToken)
		response.WriteHeader(http.StatusForbidden)

		return
	}

	handleIOError := func(err error) {
		if errors.Is(err, io.EOF) {
			log.Debug("Done capturing.")
		} else {
			log.Errorf("Error during capture: %s", err)
		}
	}

	type packetMessage struct {
		packet gopacket.Packet
		done   bool
	}
	packets := make(chan packetMessage, 1000)

	for _, index := range appIndices {
		go func(appIndex int, packets chan packetMessage) {
			defer func() {
				packets <- packetMessage{
					packet: nil,
					done:   true,
				}
			}()
			// App is visible? Great! Let's find out where it lives
			appLocation, err := a.getAppLocation(appId, appIndex, appType, authToken)
			if err != nil {
				log.Errorf("could not get location of app %s index %d of type %s (%s)", appId, appIndex, appType, err)
				return
			}
			// We found the app's location? Nice! Let's contact the pcap-agent on that VM (index only needed for testing)
			agentURL := fmt.Sprintf("https://%s:%s/capture?appid=%s&index=%d&device=%s&filter=%s", appLocation, a.config.AgentPort, appId, appIndex, device, filter)
			pcapStream, err := a.getPcapStream(agentURL)
			if err != nil {
				log.Errorf("could not get pcap stream from URL %s (%s)", agentURL, err)
				// FIXME(max): we see 'http: superfluous response.WriteHeader call' if errors occur in this loop because there is only one response but each routine can fail on it's own.
				//             there is more than one occurrence.
				response.WriteHeader(http.StatusBadGateway)
				return
			}
			defer pcapStream.Close()

			// Stream the pcap back to the client
			pcapReader, err := pcapgo.NewReader(pcapStream)
			if err != nil {
				log.Errorf("could not create pcap reader from pcap stream %s (%s)", pcapStream, err)
				response.WriteHeader(http.StatusBadGateway)
				return
			}
			for {
				data, capInfo, err := pcapReader.ReadPacketData()
				if err != nil {
					handleIOError(err)
					return
				}
				log.Debugf("Read packet: Time %s Length %d Captured %d", capInfo.Timestamp, capInfo.Length, capInfo.CaptureLength)
				packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
				packet.Metadata().CaptureInfo = capInfo
				packets <- packetMessage{
					packet: packet,
					done:   false,
				}
			}
		}(index, packets)
	}

	// Collect all packets from multiple input streams and merge them into one output stream
	w := pcapgo.NewWriter(response)
	err = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	if err != nil {
		log.Error(err)
		return
	}

	bytesTotal := 24 // pcap header is 24 bytes
	done := 0
	for msg := range packets {
		if msg.packet != nil {
			err = w.WritePacket(msg.packet.Metadata().CaptureInfo, msg.packet.Data())
			if err != nil {
				handleIOError(err)
				return
			}
			bytesTotal += msg.packet.Metadata().Length
			if f, ok := response.(http.Flusher); ok {
				f.Flush()
			}
		}
		if msg.done {
			done++
			if done == len(appIndices) {
				log.Infof("Done capturing. Wrote %d bytes from %s to %s", bytesTotal, request.URL, request.RemoteAddr)
				return
			}
		}
	}
}

func (a *Api) getPcapStream(pcapAgentURL string) (io.ReadCloser, error) {
	// TODO possibly move this into a pcapServerClient type
	log.Debugf("Getting pcap stream from %s", pcapAgentURL)
	cert, err := tls.LoadX509KeyPair(a.config.ClientCert, a.config.ClientCertKey)
	if err != nil {
		return nil, err
	}

	caCert, err := ioutil.ReadFile(a.config.AgentCa)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{cert},
				ServerName:         a.config.AgentCommonName,
				InsecureSkipVerify: a.config.AgentTlsSkipVerify, //nolint:gosec
			},
		},
	}

	res, err := client.Get(pcapAgentURL)

	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return res.Body, fmt.Errorf("expected status code %d but got status code %d", http.StatusOK, res.StatusCode)
	}

	return res.Body, nil
}

func (a *Api) getAppLocation(appId string, appIndex int, appType string, authToken string) (string, error) {
	// FIXME refactor with isAppVisibleByToken into common cf client that uses authToken
	log.Debugf("Trying to get location of app %s with index %d of type %s", appId, appIndex, appType)
	httpClient := http.DefaultClient
	appURL, err := url.Parse(fmt.Sprintf("%s/apps/%s/processes/%s/stats", a.ccBaseURL, appId, appType))

	if err != nil {
		return "", err
	}
	req := &http.Request{
		Method: "GET",
		URL:    appURL,
		Header: map[string][]string{
			"Authorization": {authToken},
		},
	}

	res, err := httpClient.Do(req)

	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("expected status code %d but got status code %d", http.StatusOK, res.StatusCode)
	}

	var appStatsResponse *cfAppStatsResponse
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(data, &appStatsResponse)
	if err != nil {
		return "", err
	}

	if len(appStatsResponse.Resources) < appIndex+1 {
		return "", fmt.Errorf("expected at least %d elements in stats array for app %s with index %d of type %s but got %d",
			appIndex+1, appId, appIndex, appType, len(appStatsResponse.Resources))
	}

	for _, process := range appStatsResponse.Resources {
		if process.Index == appIndex {
			if process.Type == appType {
				return process.Host, nil
			}
		}
	}

	return "", fmt.Errorf("could not find process with index %d of type %s for app %s", appIndex, appType, appId)
}

func (a *Api) isAppVisibleByToken(appId string, authToken string) (bool, error) {
	log.Debugf("Checking at %s if app %s can be seen by token %s", a.ccBaseURL, appId, authToken)
	httpClient := http.DefaultClient
	appURL, err := url.Parse(fmt.Sprintf("%s/apps/%s", a.ccBaseURL, appId))

	if err != nil {
		return false, err
	}
	req := &http.Request{
		Method: "GET",
		URL:    appURL,
		Header: map[string][]string{
			"Authorization": {authToken},
		},
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("expected status code %d but got status code %d", http.StatusOK, res.StatusCode)
	}

	var appResponse *cfAppResponse
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return false, err
	}
	err = json.Unmarshal(data, &appResponse)
	if err != nil {
		return false, err
	}

	if appResponse.GUID != appId {
		return false, fmt.Errorf("expected app id %s but got app id %s (%s)", appId, appResponse.GUID, appResponse.Name)
	}

	return true, nil
}

func (a *Api) setup() {
	log.Info("Discovering CF API endpoints...")
	response, err := http.Get(a.config.CfAPI)

	if err != nil {
		log.Fatalf("Could not fetch CF API from %s (%s)", a.config.CfAPI, err)
	}

	var apiResponse *cfAPIResponse
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Could not read CF API response: %s", err)
	}
	err = json.Unmarshal(data, &apiResponse)
	if err != nil {
		log.Fatalf("Could not parse CF API response: %s", err)
	}

	a.ccBaseURL = apiResponse.Links.CCv3.Href
	a.uaaBaseURL = apiResponse.Links.UAA.Href
	log.Info("Done.")
}

func (a *Api) Run() {
	log.Info("Pcap-API starting...")
	a.setup()

	mux := http.NewServeMux()

	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/capture", a.handleCapture)
	log.Info("Starting CLI file Api at root " + a.config.CLIDownloadRoot)
	mux.Handle("/cli/", http.StripPrefix("/cli/", http.FileServer(http.Dir(a.config.CLIDownloadRoot))))

	a.httpServer = &http.Server{
		Addr:    a.config.Listen,
		Handler: mux,
	}

	log.Infof("Listening on %s ...", a.config.Listen)
	if a.config.EnableServerTLS {
		log.Info(a.httpServer.ListenAndServeTLS(a.config.Cert, a.config.Key))
	} else {
		log.Info(a.httpServer.ListenAndServe())
	}
}

func (a *Api) Stop() {
	log.Info("Pcap-API stopping...")
	_ = a.httpServer.Close()
}

func NewApi(c *Config) (*Api, error) {
	if c == nil {
		return nil, fmt.Errorf("config required")
	}

	return &Api{
		config: c,
	}, nil
}
