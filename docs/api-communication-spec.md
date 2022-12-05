# PCAP Release API Documentation

This document contains the

- Short overview of what this page describes
    - list of data structures exchanged (describe fields and their purpose, examples for fields, special meanings, such as empty list == all, etc.)
    - list of participants and their purpose ("architecture")

# Overview

- List all participants and exchanged data structures on high level
    - this provides the 10000ft view and allows digging deeper into details

## Interactions

- pcap-cli -> pcap-api
  - status (version information, service alive)
  - capture request for:
    - CF Capture Request
    - BOSH Capture Request
  - send stop request
- pcap-api
  - Status response
  - CF Capture Request
    - pcap-api -> Cloud Controller
      - Validate request, token
      - find endpoints (pcap-agent)
  - BOSH Capture Request
    - pcap-api -> BOSH Director
      - HTTP: Retrieve /info (also works without Auth)
      - HTTP: Retrieve deployment instances
    - pcap-api -> BOSH Director UAA
      - HTTP: Retrieve JWT token key
  - pcap-api -> pcap-agent
    - Status
    - Send Capture Request
    - Send stop request
- pcap-agent -> pcap-api
  - Send status
  - Send Capture Response
    - Message
      - Stop
      - Congestion
      - Error
        - Limit reached (e.g. number of concurrent capture requests exceeded, )
        - Invalid Request (e.g. malformed filter, device not found, etc.)
        - Runtime (any unexpected error occurring on the agent during capture. Contains as much information as possible and forward before terminating)
    - captured pcap data packet(s) - consider batching multiple packets in one Capture Response
- pcap-api -> pcap-cli
    - Status
    - captured pcap data packet
    - Message
        - Stop confirmation
        - Status
          - Agent is gone
          - All agents stopped
          - Congestion
        - Errors
          - Limit reached (e.g. number of concurrent capture requests exceeded, )
          - Unauthorized
          - Invalid Request (e.g. malformed filter, Target not found, device not found, etc.)
        

## Data Structures

The following section defines the data structures, their use and fields' purpose in detail.

### Capture Request

A capture request contains the information needed to target a set of resources, from which to capture network traffic.

- **For CF**, a resource is a single application instance.
  - The capture request can target all instances at once by omitting specific application instance IDs
- **For BOSH**, a resource is a single BOSH VM.
  - The capture request can target individual VMs or all VMs in one or multiple instance groups of a BOSH deployment.

The capture request can contain a start or stop request. The start request can either be for CF or BOSH respectively:

* `start`: one of [CF App Start Capture Request](#cf-app-start-capture-request), [BOSH Start Capture Request](#bosh-start-capture-request)
* `stop`: a [Stop Capture Request](#stop-capture-request)

#### Common Fields for `pcap-agent`

The following attributes are part of all capture requests and define the details required for the `pcap-agent`.

| Parameter      | Type    | Required? | Default | Description                                                                                                                                               |
|----------------|---------|-----------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `device`       | string  | yes       | `eth0`   | The device on the app container from which to capture the traffic                                                                                         |
| `filter`       | string  | no        |         | BPF Filter expression to use with tcpdump command to capture traffic.                                                                                     |
| `snaplen`      | integer | no        | 65535   | Limit the amount of data captured for each packet, see [SnapLen](https://wiki.wireshark.org/SnapLen)                                                      |

#### CF App Start Capture Request

| Parameter | Type | Required? | Default | Description                                                                                                                                                  |
|-----|-----|-----|-----|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  | `Common` | yes | | All [common fields](#common-fields-for-pcap-agent) are included in a CF capture request                                                                      |
| `token`     | `string` | yes | | The UAA token for the user sending the capture request.                                                                                                      |
| `application` | `string` | yes | | The CF name of the target application.                                                                                                                       |
| `type`        | `string` | no | `web`   | An app can have processes of different types, `web` being the default. This allows targeting processes of a specific type for this app.                      |
| `instance_ids` | `[]int` | no | `[]`  | List of instance indexes of the application. An empty list indicates that **all instances** should be captured. Mutually exclusive with `instance_guids`.    |
| `instance_guids` | `[]string` | no | `[]` | List of instance IDs for finer-grained targeting. An empty list indicates that **all instances** should be captured. Mutually exclusive with `instance_ids`. |

#### BOSH Start Capture Request

| Parameter        | Type       | Required? | Default | Description                                                                                                                                                         |
|------------------|------------|-----------|-----|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|                  | `Common`   | yes       | | All [common fields](#common-fields-for-pcap-agent) are included in a CF capture request                                                                                                   |
| `token`          | `string`   | yes       | | The UAA token for the user sending the capture request.                                                                                                             |
| `deployment`     | `string`   | yes       | | The name of the target BOSH deployment.                                                                                                                             |
| `groups`         | `[]string` | yes       |    | A list of instance groups from which to capture. **Must contain at least one instance group**.                                                                      |
| `instance_ids`   | `[]int`    | no        | `[]` | List of instance indexes of the application. An empty list indicates that **all instances** should be captured. Mutually exclusive with `instance_guids`.           |
| `instance_guids` | `[]string` | no        | `[]` | List of instance IDs for finer-grained targeting. An empty list indicates that **all instances** should be captured. Mutually exclusive with `instance_ids`. |

#### Stop Capture Request

The stop capture request just indicates that the capture on the current stream is requested to be stopped gracefully.

### Message

| Parameter      | Type               | Required? | Description                                                                                                                                          |
|----------------|--------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `message_type` | `enum MessageType` | yes       | The type of message sent. This allows for logic based on the message type                                                                            |
| `origin`       | `string`           | yes       | The sender of this message, e.g. `pcap-api-[deployment guid]`, `pcap-agent-[instance_id]`                                                            |
| `message`      | `string`           | no        | The detailed message, human readable, explaining the reason for this message. Optional but recommended, as it could be shown on the CLI to the user. |

#### Enum `MessageType`

| Value                   | Description                                                                                                                                                       |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `INSTANCE_NOT_FOUND`    | One of the requested instances does not exist but there is at least one instance to capture from. MUST be sent as soon as possible.                               |
| `INSTANCE_DISCONNECTED` | One instance failed during capturing but there are still instances left to capture from. The detailed message should contain information about the stopped party. |
| `INSTANCE_STOPPED`      | A single agent has stopped gracefully. The detailed message should contain information about the stopped party.                                                   |
| `START_CAPTURE_FAILED`  | Starting the capture from a specific instance has failed.                                                                                                         |
| `INVALID_REQUEST`       | The request could not be fulfilled, e.g. because the app or BOSH deployment with the requested name do not exist.                                                 |
| `CONGESTED`             | Some participant on the path is congested to the point of discarding data. The detailed message should contain the congested party.                               |
| `CAPTURE_STOPPED`       | Confirmation that the capture has stopped gracefully. All of the targeted agents have stopped.                                                                    |
| `LIMIT_REACHED`         | Some limit has been reached, e.g. number of concurrent requests, time, bytes, etc.; Message details identifies, which limit has been reached.                     |
| `UNAUTHORIZED`          | The token sent by the client is rejected (e.g. invalid, timed out, etc.). Detail for the rejection in the message.                                                |                                                                                                     |
| `INTERNAL_ERROR`        | An error happened while communicating in the PCAP components, independent of the client, e.g. mTLS failure. This indicates unrecoverable internal errors.         |
| `NO_CAPTURE_RUNNING`    | A Stop Capture Request is received but no capture is running.                                                                                                     |

### Status

| Parameter | Type          | Required? | Description                                                                                                                             |
|-----------|---------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `health`  | `enum Health` | yes       | The type of message sent. This allows for logic based on the message type                                                               |
| `version` | `string`      | yes       | Version number of the component. Can be used to ensure communication with compatible versions, and cut-off of unsupported old versions. |
| `status`  | `string`      | yes       | A human readable status message.                                                                                                        |
| `cf`      | `boolean`     | no        | Supports CF requests (only for pcap-api)                                                                                                |                                                                                               | 
| `bosh`    | `boolean`     | no        | Supports BOSH requests (only for pcap-api)                                                                                              |                                                                                               | 

#### Enum `Health`

| Value       | Description                                                                                                                                  |
|-------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `OK`        | Everything is nominal.                                                                                                                       |
| `DRAINING`  | This instance is currently being shut down and is draining its remaining connections.                                                        |
| `UNHEALTHY` | Communication to some of the components is interrupted, e.g. BOSH Director, UAA, Cloud Controller, pcap-api (in the case of the pcap-agent)? |


### PCAP Data

| Parameter | Type        | Description                                                               |
|-----------|-------------|---------------------------------------------------------------------------|
| `data`    | `[]bytes`   | One, potentially multiple, complete packets as captured from the network. |


### Capture Response

Capture Response is a stream that may contain multiple of the following data structures:

* [PCAP Data](#pcap-data)
* [Message](#message)

Messages are used to communicate status and errors.






Common:

- 
CF Case:

- 

Interactions

- subsection for each interaction, listing
    - the participants (request/response)
    - if needed, add a sequence diagram
    - lists the exchanged data

# PCAP API documentation

This page contains the documentation of **pcap-api** deployed as a boshrelease.

**pcap-api** interacts with many components: CLIs, Bosh VMs, CF Apps.

Below will be described all those interactions

# The trivial use case:

pcap-cli requests a capture from a CF app having name "myapp"

pcap-cli sends these data to pcap-api:
pcap-cli ----> pcap-api
```
Data sent:
    Capture Request
    Type: "web"
    device: "eth0"
    filter: "host 1.2.3.4"
    app: "myapp"
    indexes: [] (means all)
```

pcap-api receives the request and asks pcap-agents to capture and stream the captured traffic

- pcap-api ----> pcap-agent
```
Data sent:
    - Capture Request
        Type: "web"
        device: "eth0"
        filter: "host 1.2.3.4"
        appId: "aa-bb-cc-dd"
```

- pcap-api <---- pcap-agent
```
Data Received: 
    Acceptance status
    Stream of packet (data captured from the network)
```

- pcap-cli <---- pcap-api
```
Data Received: 
    - Status of the request: processed or not
```

To stop the request and receive requested pcap data, pcap-cli will send a termination signal
- pcap-cli ----> pcap-api
```
Data sent:
    Terminate Capture Request
```

pcap-api receives the request and asks pcap-agents to stop running captures and stream the resulted pcap data.

- pcap-api ----> pcap-agent
```
Data sent:
    - Terminate Capture Request
```
Agents will stop capture and stream process, then confirm to the api.

- pcap-api <---- pcap-agent
```
Data Received: 
    Acceptance status
```

- pcap-cli <---- pcap-api
```
Data Received: 
    - Capture Request status
    - Captured pcap data (streams bundled into a file)
``` 

### Cli silent disconnection during capture request:
pcap-cli requests a capture from a CF app having name "myapp"

pcap-cli sends these data to pcap-api:
- pcap-cli ----> pcap-api
```
Data sent:
    Capture Request
    Type: web
    device: "eth0"
    filter: "host 1.2.3.4"
    app: "myapp"
    indexes: [] (means all)
```

pcap-api receives the request and asks pcap-agents to capture and stream the captured traffic

- pcap-api ----> pcap-agent

```
Data sent:
    Capture Request
    Type: web
    device: "eth0"
    filter: "host 1.2.3.4"
    appId: "aa-bb-cc-dd"
    indexes: []
```

- pcap-api <---- pcap-agent

```
Data Received: 
    Acceptance status
    Stream of packet (data captured from the network)
```
pcap-api checks periodically if the connection from pcap-cli is alive, if no, sends a cancellation request to the involved agents:

- pcap-api ----> pcap-agent

```
Data sent:
    - Cancel Capture request:
```

pcap-agent will cancel the running capture and stops streaming data to the api

- pcap-api <---- pcap-agent
```
Data Received:  
    confirmation status of cancelled capture request
```

pcap-api will then clean all generated streams saved locally.

### Capture request for non existing app :

pcap-cli send capture request to pcap-api with this data:

```
    Capture Request
    Type: web
    device: "eth0"
    filter: "host 1.2.3.4"
    app: "myapp"
    indexes: [] (means all)
```

pcap-api checks confirms the existence of the app in Cloud Controller and gets its details.
```
    App detail Request
    App_name
```

Cloud Controller replies with an error to pcap-api:
```
    App detail response
    Response Status
    app name: "myapp"
    appId:aa-bb-cc-dd 
    app_type: "web"
    instances:[
        - [host: 5.6.7.8, index: 0, process:"web"]
    ]
```

pcap-api then will notify pcap-cli about the failure and end the connection:
```
Response Status
App doesn't exist
```

### Capture request for non existing app index
In this case, the api will manage the case of targeting a non existing container. For example, we have *myapp* deployed with one instance and in our request we specify to capture index 1.
which corresponds to second instance of *myapp*
pcap-cli will send this data:
```
Capture Request
Type: web
device: "eth0"
filter: "host 1.2.3.4"
app: "myapp"
indexes: [1]
```

pcap-api checks the existence of the app in Cloud Controller and gets its details.
```
App detail request
App_name
```

Cloud Controller replies with an error to pcpa-api:
```
App detail response
Response Status
app name: "myapp"
appId:aa-bb-cc-dd 
app_type: "web"
instances:[
    - [host: 5.6.7.8, index: 0, process:"web"]
]
```

pcap-api then will check if the requested instance is present and notify pcap-cli about the failure and end the connection:
```
Response Status
Target app instance doesn't exist
```

### Application not available during capture
cap-cli sends these data to pcap-api:
pcap-cli ----> pcap-api
```
Data sent:
    Capture Request
    Type: web
    device: "eth0"
    filter: "host 1.2.3.4"
    app: "myapp"
    indexes: [] (means all)
```

pcap-api receives the request and asks pcap-agents to capture and stream the captured traffic
pcap-api ----> pcap-agent
```
Data sent:
    Capture Request
    Type: web
    device: "eth0"
    filter: "host 1.2.3.4"
    appId: "aa-bb-cc-dd"
```

pcap-api <---- pcap-agent
```
Data Received: 
    Send notification app instance not available during capture
    Close connection 
```

pcap-api will notify the cli and terminate the request.
pcap-cli <---- pcap-api
```
Data Received: 
    Stream of packet (data captured from the network)
    Send a termination status => Application issue something went wrong during capture session.
```

### One app instance goes down during capture
cap-cli sends these data to pcap-api:

pcap-cli ----> pcap-api
```
Data sent:
    Capture Request
    Type: web
    device: "eth0"
    filter: "host 1.2.3.4"
    app: "myapp"
    indexes: [] (means all)
```

pcap-api receives the request and asks pcap-agents to capture and stream the captured traffic

pcap-api ----> pcap-agent
```
Data sent:
    - Capture Request
        Type: web
        device: "eth0"
        filter: "host 1.2.3.4"
        appId: "aa-bb-cc-dd"            
```

pcap-api <---- pcap-agent
```

Data Received: 
    Send notification app instance not available during capture
    Close connection 
```

pcap-api will notify the cli about the failed instances
pcap-cli <---- pcap-api
```
Data Received: 
    Informational message : One or more instances of app "myapp" became unreachable during capture process. 
        
```

and continue collecting the stream until receiving a termination request from pcap-cli


### Capture request from a very high traffic multiple instances application:

pcap-cli requests a capture from "myapp" application

pcap-cli sends these data to pcap-api:
- pcap-cli ----> pcap-api
```
Data sent:
    Capture Request
    Type: web
    device: "eth0"
    filter: ""
    app: "myapp"
    indexes: []
```

pcap-api receives the request and asks pcap-agents to capture and stream the captured traffic

- pcap-api ----> pcap-agent

```
Data sent:
    - Capture Request
        Type: web
        device: "eth0"
        filter: ""
        appId: "aa-bb-cc-dd"
```

- pcap-api <---- pcap-agent

```
    Data Received: 
        Acceptance status
        Stream of packet (data captured from the network)
```

if pcap-api get pressure from the agent because to the amount of the streamed data, the traffic became then congested, some packets will be dropped to avoid delaying in capture and to avoid crashing the api.
pcap-api will notify pcap-cli about the overload, the network traffic congestion and the eventual packet loss.

pcap-cli <---- pcap-api
```
Data sent:
    Network congestion: some packet could be dropped.
``` 
### many Capture requests from many very high traffic multiple instances applications:
This case is the same as above, here we put an accent on the fact that we can have many pcap-cli requesting packet from different applications.

In case of network congestion, the messages sent from pcap-api to pcap-clis are the same.

To protect pcap-api, we can introduce a setting **Max number of pcap-cli in parallel** to limit number of cli connections.

To protect also Diego Cells, we can set an equivalent setting on agents **Max pcap requests running per agent**.

## Bosh pcap cli
All the cases listed for CF application are still valid for bosh pcap cli.
The difference is in the data sent by the cli and validation requests from pcap-api to bosh director api.

bosh-pcap-cli will send this data:
 ```
    Capture Request
    Type: BOSH
    device: "eth0"
    filter: "host 1.2.3.4"
    deployment: "haproxy"
    instance_groups: ["ha_proxy_z1", "ha_proxy_z3"]
    instance_ids: []
 ```
Instead of application or application instance, we talk about VMs.
Each bosh deployed VM will host a pcap-agent.
pcap-agent will capture the traffic from the VM and not from the container running the application. This is the difference between the two CLIs.

## Common cases
### Agent not available after starting pcap capture session
We can have this case when the agent stops responding to pcap-api or is not reachable by pcap-api.

pcap-cli <---- pcap-api
```
Data sent:
    Application instance or VM became not available during capture process.
```
If it's only the one agent that fulfills client request, pcap-api will clse the connection, otherwise it continues to collect streamed pcap data until receiving a termination signal from the cli.

### Agent not available when requesting a pcap capture
The agent is not reachable by pcap-api. pcap-api can't
send data to that agent.
pcap-cli <---- pcap-api
```
Data sent:
    Connection close
    Application instance or VM is not available.
```

### pcap-api not available
pcap-cli will close the connection after noticing that the channel with pcap-api is closed.
No data is received in this case.


## summarize all this cases:

### pcap-cli <----> pcap-api

pcap-cli sends to pcap-api
- *Capture Request*

pcap-cli *receives* from pcap-api
- Invalid request
- Auth error (e.g. invalid token)
- Invalid capture request error: unknown deployment or application
- Stream of status messages / pcap captured packets
- Congested Stream / Dropped Messages Notification
- Agent terminated notification (completed, disappeared/disconnected)
- disconnect (no message, stream closed)

### pcap-api <----> pcap-agent

pcap-api sends to pcap-agent
- *Capture Request*

and pcap-api *receives* from pcap-agent
- Stream of status messages / pcap captured packets
- Agent terminated notification (completed, disappeared/disconnected)


