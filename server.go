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

	log "github.com/sirupsen/logrus"
)

type server struct {
	config     *Config
	ccBaseURL  string
	uaaBaseURL string
}

type cfApiResponse struct {
	Links struct {
		CCv2 struct {
			Href string `json:"href"`
		} `json:"cloud_controller_v2"`
		CCv3 struct {
			Href string `json:"href"`
		} `json:"cloud_controller_v3"`
		UAA struct {
			Href string `json:"href"`
		} `json:"uaa"`
	} `json:"links"`
}

type cfAppResponse struct {
	Guid string `json:"guid"`
	Name string `json:"name"`
}

type cfAppStatsResponse struct {
	Resources []struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
		Host  string `json:"host"`
	} `json:"resources"`
}

func (s *server) handleCapture(response http.ResponseWriter, request *http.Request) {

	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	appId := request.URL.Query().Get("appid")
	appIndexStr := request.URL.Query().Get("index")
	appType := request.URL.Query().Get("type")
	filter := request.URL.Query().Get("filter")
	authToken := request.Header.Get("Authorization")

	if appId == "" {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("appid missing"))
		return
	}

	appIndex, err := strconv.Atoi(appIndexStr)
	if err != nil {
		appIndex = 0 // default value
	}

	if appType == "" {
		appType = "web" // default value
	}

	if authToken == "" {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("authentication required"))
		return
	}

	// Check if app can be seen by token
	appVisible, err := s.isAppVisibleByToken(appId, authToken)
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

	// App is visible? Great! Let's find out where it lives
	appLocation, err := s.getAppLocation(appId, appIndex, appType, authToken)
	if err != nil {
		log.Errorf("could not get location of app %s index %d of type %s (%s)", appId, appIndex, appType, err)
		response.WriteHeader(http.StatusNotFound) //TODO depending on error type this could also be a 5xx status
		return
	}

	// We found the app's location? Nice! Let's contact the pcap-server on that VM
	pcapServerUrl := fmt.Sprintf("https://%s:%s/capture?appid=%s&filter=%s", appLocation, s.config.PcapServerPort, appId, filter)
	pcapStream, err := s.getPcapStream(pcapServerUrl)
	if err != nil {
		log.Errorf("could not stream pcap from URL %s (%s)", pcapServerUrl, err)
		response.WriteHeader(http.StatusBadGateway)
		return
	}
	defer pcapStream.Close()

	handleIOError := func(err error) {
		if errors.Is(err, io.EOF) {
			log.Debug("Done capturing.")
		} else {
			log.Errorf("Error during capture: %s", err)
		}
	}

	// Stream the pcap back to the client
	for {
		buffer := make([]byte, 4096)
		n, errRead := pcapStream.Read(buffer)
		if n > 0 {
			log.Debugf("Read %d bytes from input stream", n)
			m, errWrite := response.Write(buffer[:n])
			if m > 0 {
				log.Debugf("Wrote %d bytes to output stream", m)
				if f, ok := response.(http.Flusher); ok {
					f.Flush()
				}
			}
			if errWrite != nil {
				handleIOError(errWrite)
				return
			}
		}
		if errRead != nil {
			handleIOError(errRead)
			return
		}
	}
}

func (s *server) getPcapStream(pcapServerUrl string) (io.ReadCloser, error) {
	//TODO possibly move this into a pcapServerClient type
	log.Debugf("Getting pcap stream from %s", pcapServerUrl)
	cert, err := tls.LoadX509KeyPair(s.config.PcapServerClientCert, s.config.PcapServerClientKey)
	if err != nil {
		return nil, err
	}

	caCert, err := ioutil.ReadFile(s.config.PcapServerCaCert)
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
				ServerName:         s.config.PcapServerName,
				InsecureSkipVerify: s.config.ClientSkipVerify,
			},
		},
	}

	r, err := client.Get(pcapServerUrl)

	if err != nil {
		return nil, err
	}

	return r.Body, nil
}

func (s *server) getAppLocation(appId string, appIndex int, appType string, authToken string) (string, error) {
	//FIXME refactor with isAppVisibleByToken into common cf client that uses authToken
	log.Debugf("Trying to get location of app %s with index %d of type %s", appId, appIndex, appType)
	httpClient := http.DefaultClient
	appUrl, err := url.Parse(fmt.Sprintf("%s/apps/%s/processes/%s/stats", s.ccBaseURL, appId, appType))

	if err != nil {
		return "", err
	}
	req := &http.Request{
		Method: "GET",
		URL:    appUrl,
		Header: map[string][]string{
			"Authorization": {authToken},
		},
	}

	r, err := httpClient.Do(req)

	if err != nil {
		return "", err
	}

	var appStatsResponse *cfAppStatsResponse
	data, err := ioutil.ReadAll(r.Body)
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

func (s *server) isAppVisibleByToken(appId string, authToken string) (bool, error) {
	log.Debugf("Checking at %s if app %s can be seen by token %s", s.ccBaseURL, appId, authToken)
	httpClient := http.DefaultClient
	appUrl, err := url.Parse(fmt.Sprintf("%s/apps/%s", s.ccBaseURL, appId))

	if err != nil {
		return false, err
	}
	req := &http.Request{
		Method: "GET",
		URL:    appUrl,
		Header: map[string][]string{
			"Authorization": {authToken},
		},
	}

	r, err := httpClient.Do(req)

	if err != nil {
		return false, err
	}

	var appResponse *cfAppResponse
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return false, err
	}
	err = json.Unmarshal(data, &appResponse)
	if err != nil {
		return false, err
	}

	if appResponse.Guid != appId {
		return false, fmt.Errorf("expected app id %s but got app id %s (%s)", appId, appResponse.Guid, appResponse.Name)
	}
	return true, nil
}

func (s *server) setup() {
	log.Info("Discovering CF API endpoints...")
	r, err := http.Get(s.config.CfApi)

	if err != nil {
		log.Fatalf("Could not fetch CF API from %s (%s)", s.config.CfApi, err)
	}

	var apiResponse *cfApiResponse
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Could not read CF API response: %s", err)
	}
	err = json.Unmarshal(data, &apiResponse)
	if err != nil {
		log.Fatalf("Could not parse CF API response: %s", err)
	}

	s.ccBaseURL = apiResponse.Links.CCv3.Href
	s.uaaBaseURL = apiResponse.Links.UAA.Href
	log.Info("Done.")
}

func (s *server) run() {

	log.Info("PcapServer-API starting...")
	s.setup()

	mux := http.NewServeMux()

	mux.HandleFunc("/capture", s.handleCapture)

	server := &http.Server{
		Addr:    s.config.Listen,
		Handler: mux,
	}

	log.Infof("Listening on %s ...", s.config.Listen)
	if s.config.EnableServerTLS {
		log.Fatal(server.ListenAndServeTLS(s.config.Cert, s.config.Key))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}
