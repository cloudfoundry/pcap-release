# pcap-release
[BOSH](https://bosh.io/) release of the pcap [Cloud Foundry](https://www.cloudfoundry.org/) add-on

## Architecture

* pcap-api is deployed on its own vm.
* pcap-agent is co-located on diego cells.
* pcap-api needs to register its route via route-registrar, part of the cf-routing-release.
* Requests to pcap-api need an authorization header including the oauth token from UAA.
  This token is used to gather information about the app from the cloud-controller.
* The pcap-api makes requests to the pcap-agent on corresponding diego cell.
* The pcap agent starts a tcpdump using libpcap via [the gopacket module](https://github.com/google/gopacket) and streams the results.

<!-- TODO: diagram needs to be updater, only Dominik has most recent version -->
![tcpdump in cf architecture](docs/tcpdump-for-cf.svg "tcpdump in cf architecture")

## Jobs

### pcap-api

* Check if token is valid by requesting app information from CC
* Get diego cell address for app instance from CC
* Connect to pcap agent on diego-cell
* Stream packets back to client

### pcap-agent

* Find container PID for app id
* enter container network namespace
* capture packets and stream back to client

## How to deploy
The release provides two files to integrate with an 
existing [cf-deployment](https://github.com/cloudfoundry/cf-deployment):
* `manifests/ops-files/add-pcap-agent.yml` This provides a shared CA between pcap-agent and pcap-api. It also adds the pcap-agent job to all diego cells.
* `manifests/pcap-agent.yml` This is an example BOSH manifest to deploy the pcap-api

### Step 1 - Add pcap-agent to cf-deployment
```
bosh interpolate -o manifests/ops-files/add-pcap-agent.yml cf-deployment.yml > cf-deployment-pcap.yml
bosh -d cf deploy cf-deployment-pcap.yml
```
This assumes your BOSH deployment name of cf-deployment is called `cf`

### Step 2 - Deploy pcap-api
```
cp manifests/vars-template.yml manifests/vars.yml
vim manifests/vars.yml (adjust as needed)
bosh -d pcap deploy -l manifests/vars.yml manifests/pcap-agent.yml
```
### Step 3 - Install CF CLI plugin
```
wget https://pcap.cf.cfapp.com/cli/pcap-cli-[linux|mac]-amd64 (adjust URL as needed) -O pcap-cli
cf install-plugin pcap-cli
cf pcap ...
```
