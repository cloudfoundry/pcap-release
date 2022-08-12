package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"runtime"

	"github.com/containerd/go-runc"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
)

type Agent struct {
	httpServer *http.Server
	config     *Config
}

func (a *Agent) handleCaptureCF(response http.ResponseWriter, request *http.Request) {
	log.Debugf("Accepted connection from %s", request.RemoteAddr)

	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	appId := request.URL.Query().Get("appid")
	filter := request.URL.Query().Get("filter")
	device := request.URL.Query().Get("device")
	snaplen := uint32(65535)

	if appId == "" {
		response.WriteHeader(http.StatusBadRequest)
		// TODO: add some nice error message
		return
	}

	if device == "" {
		device = "eth0"
	}

	log.Debugf("Appid = %s", appId)
	log.Debugf("Filter = %s", filter)
	log.Debugf("Device = %s", device)

	// CF-SPECIFIC PARTS BEGIN
	type ContainerConfig struct {
		Handle   string `json:"handle"`
		Ip       string `json:"ip"`
		Metadata struct {
			AppId             string `json:"app_id"`
			SpaceId           string `json:"space_id,omitempty"`
			OrgId             string `json:"org_id,omitempty"`
			Ports             string `json:"ports,omitempty"`
			ContainerWorkload string `json:"container_workload,omitempty"`
			PolicyGroupId     string `json:"policy_group_id,omitempty"`
		} `json:"metadata"`
	}
	type ContainerKeys struct {
		Keys map[string]*ContainerConfig
	}

	// Load container store
	var store ContainerKeys
	storeFile := a.config.ContainerStore
	storeData, err := ioutil.ReadFile(storeFile)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	}

	err = json.Unmarshal(storeData, &store.Keys)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	}

	// Get runc container id from instance id
	var containerId string
	for key, value := range store.Keys {
		if value.Metadata.AppId == appId {
			containerId = key
		}
	}

	if containerId == "" {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("Could not find container for instance id " + appId))
		log.Errorln(err)
		return
	}

	log.Debugf("Found container id %s for appid %s", containerId, appId)

	// Get pid from runc container state
	ctx := context.Background()
	runcClient := &runc.Runc{
		Command: a.config.RunC,
		Root:    a.config.RunCRoot,
	}

	container, err := runcClient.State(ctx, containerId)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	}

	pid := container.Pid

	log.Debugf("Found pid %d for container id %s", pid, containerId)

	// CF-SPECIFIC PARTS END

	// Lock the OS Thread, so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	// Get namespace from pid
	newns, _ := netns.GetFromPid(pid)
	defer newns.Close()

	// Activate network namespace
	err = netns.Set(newns)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	}
	// Switch back to the original namespace
	defer netns.Set(origns)

	// Start capturing packets
	log.Debugf("Starting capture of device %s in netns %s of pid %d using filter '%s'", device, newns, pid, filter)
	doCapture(device, filter, snaplen, response)
}

func (a *Agent) handleCaptureBOSH(response http.ResponseWriter, request *http.Request) {
	log.Debugf("Accepted connection from %s", request.RemoteAddr)

	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	filter := request.URL.Query().Get("filter")
	device := request.URL.Query().Get("device")
	snaplen := uint32(65535)

	if device == "" {
		device = "eth0"
	}

	log.Debugf("Filter = %s", filter)
	log.Debugf("Device = %s", device)

	// Start capturing packets
	log.Debugf("Starting capture of device %s using filter '%s'", device, filter)
	doCapture(device, filter, snaplen, response)
}

func doCapture(device string, filter string, snaplen uint32, response http.ResponseWriter) {
	if handle, err := pcap.OpenLive(device, int32(snaplen), true, pcap.BlockForever); err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	} else if err := handle.SetBPFFilter(filter); err != nil { // optional
		response.WriteHeader(http.StatusInternalServerError)
		log.Errorln(err)
		return
	} else {
		w := pcapgo.NewWriter(response)
		err = w.WriteFileHeader(snaplen, layers.LinkTypeEthernet)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			log.Errorln(err)
			return
		}
		flush(response)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			log.Debugf("Packet: %s\n", packet.String())
			err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				if errors.Is(err, io.EOF) {
					log.Debug("Done.")
					return
				}
				response.WriteHeader(http.StatusInternalServerError)
				log.Errorln(err)
				return
			}
			flush(response)
		}
	}
}

func flush(writer io.Writer) {
	if f, ok := writer.(http.Flusher); ok {
		f.Flush()
	}
}

func (a *Agent) Run() {

	mux := http.NewServeMux()

	mux.HandleFunc("/capture", a.handleCaptureCF) // backwards compatibility
	mux.HandleFunc("/capture/cf", a.handleCaptureCF)
	mux.HandleFunc("/capture/bosh", a.handleCaptureBOSH)

	var tlsConfig *tls.Config
	if a.config.EnableServerTLS {
		// Create a CA certificate pool and add cert.pem to it
		caCert, err := ioutil.ReadFile(a.config.CaCert)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// Create the TLS Config with the CA pool and enable Client certificate validation
		tlsConfig = &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
	}

	// Create a Server instance to listen on port 8443 with the TLS config
	a.httpServer = &http.Server{
		Addr:      a.config.Listen,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Infof("Listening on %s ...", a.config.Listen)
	if a.config.EnableServerTLS {
		log.Info(a.httpServer.ListenAndServeTLS(a.config.Cert, a.config.Key))
	} else {
		log.Info(a.httpServer.ListenAndServe())
	}

}

func NewAgent(c *Config) (*Agent, error) {
	if c == nil {
		return nil, fmt.Errorf("config required")
	}

	return &Agent{
		config: c,
	}, nil
}
