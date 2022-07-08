# pcap-server-release
[BOSH](https://bosh.io/) release of the pcap-server [Cloud Foundry](https://www.cloudfoundry.org/) add-on

## Architecture

* pcap-server-api is deployed on its own vm.
* pcap-server is co-located on diego cells.
* pcap-server-api needs to register its route via route-registrar, part of the cf-routing-release.
* Requests to pcap-server-api need an authorization header including the oauth token from UAA.
  This token is used to gather information about the app from the cloud-controller.
* The pcap-api-server makes requests to the pcap-server on corresponding diego cell.

* The pcap server starts a tcpdump using libpcap via [the gopacket module](https://github.com/google/gopacket) and streams the results.

![alt text](docs/tcpdump-for-cf.svg "tcpdump in cf architecture")

## Jobs

### pcap-server-api

* Check if token is valid by requesting app information from CC
* Get diego cell address for app instance from CC
* Connect to pcap server on diego-cell
* Stream packets back to client

### pcap-server

* Find container PID for app id
* enter container network namespace
* capture packets and stream back to client

## How to deploy
The release provides two files to integrate with an 
existing [cf-deployment](https://github.com/cloudfoundry/cf-deployment):
* `manifests/ops-files/add-pcap-server.yml` This provides a shared CA between pcap-server and pcap-server-api. It also adds the pcap-server job to all diego cells.
* `manifests/pcap-server.yml` This is an example BOSH manifest to deploy the pcap-server-api

### Step 1 - Add pcap-server to cf-deployment
```
bosh interpolate -o manifests/ops-files/add-pcap-server.yml cf-deployment.yml > cf-deployment-pcap.yml
bosh -d cf deploy cf-deployment-pcap.yml
```
This assumes your BOSH deployment name of cf-deployment is called `cf`

### Step 2 - Deploy pcap-server-api
```
cp manifests/vars-template.yml manifests/vars.yml
vim manifests/vars.yml (adjust as needed)
bosh -d pcap-server deploy -l manifests/vars.yml manifests/pcap-server.yml
```
### Step 3 - Install CF CLI plugin
```
wget https://pcap.cf.cfapp.com/cli/pcap-server-cli-[linux|mac]-amd64 (adjust URL as needed) -O pcap-cli
cf install-plugin pcap-cli
cf pcap ...
```
