package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containerd/go-runc"
	"github.com/domdom82/pcap-server/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
	"io"
	"io/ioutil"
	"net/http"
	"runtime"
)

type Server struct {
	httpServer *http.Server
	config     *config.Config
}

func (s *Server) handleCaptureCF(response http.ResponseWriter, request *http.Request) {
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
		//TODO: add some nice error message
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
	storeFile := s.config.ContainerStore
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
		Command: s.config.RunC,
		Root:    s.config.RunCRoot,
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

func (s *Server) handleCaptureBOSH(response http.ResponseWriter, request *http.Request) {
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

func (s *Server) Run() {

	mux := http.NewServeMux()

	mux.HandleFunc("/capture", s.handleCaptureCF) // backwards compatibility
	mux.HandleFunc("/capture/cf", s.handleCaptureCF)
	mux.HandleFunc("/capture/bosh", s.handleCaptureBOSH)

	var tlsConfig *tls.Config
	if s.config.EnableServerTLS {
		// Create a CA certificate pool and add cert.pem to it
		caCert, err := ioutil.ReadFile(s.config.CaCert)
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
	s.httpServer = &http.Server{
		Addr:      s.config.Listen,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Infof("Listening on %s ...", s.config.Listen)
	if s.config.EnableServerTLS {
		log.Info(s.httpServer.ListenAndServeTLS(s.config.Cert, s.config.Key))
	} else {
		log.Info(s.httpServer.ListenAndServe())
	}

}

func NewServer(c *config.Config) (*Server, error) {
	if c == nil {
		return nil, fmt.Errorf("config required")
	}
	server := &Server{
		config: c,
	}

	return server, nil
}
