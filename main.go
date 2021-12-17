package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containerd/go-runc"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/vishvananda/netns"
	"io/ioutil"
	"net"
	"os"
	"runtime"
)

func main() {

	usage := "usage: pcap-server <instance-id> <device> <filter> <file.pcap>"

	if len(os.Args) < 4 {
		fmt.Println(usage)
		os.Exit(1)
	}

	instanceId := os.Args[1]
	device := os.Args[2]
	filter := os.Args[3]
	outfile := os.Args[4]

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
	storeFile := "/var/vcap/data/container-metadata/store.json"
	storeData, err := ioutil.ReadFile(storeFile)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(storeData, &store.Keys)
	if err != nil {
		panic(err)
	}

	// Get runc container id from instance id
	var containerId string
	for key, value := range store.Keys {
		if value.Metadata.AppId == instanceId {
			containerId = key
		}
	}

	if containerId == "" {
		panic(errors.New("Could not find container for instance id " + instanceId))
	}

	// Get pid from runc container state
	ctx := context.Background()
	runcClient := &runc.Runc{
		Command: "/var/vcap/packages/runc/bin/runc",
		Root:    "/run/containerd/runc/garden",
	}

	container, err := runcClient.State(ctx, containerId)
	if err != nil {
		panic(err)
	}

	pid := container.Pid

	// CF-SPECIFIC PARTS END

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	// Get namespace from pid
	newns, _ := netns.GetFromPid(pid)
	defer newns.Close()

	// Activate network namespace
	netns.Set(newns)

	// Print interfaces in the namespace
	ifaces, _ := net.Interfaces()
	fmt.Printf("Interfaces: %v\n", ifaces)

	// Start capturing packets
	f, err := os.Create(outfile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(1600, layers.LinkTypeEthernet)
	if err != nil {
		panic(err)
	}

	fmt.Println("Listening on " + device + " ...")
	if handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(filter); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Println(packet.String())
			err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				panic(err)
			}
		}
	}

	// Switch back to the original namespace
	netns.Set(origns)
}
