# PCAP Release API Documentation

**Table of Content**
<!-- TOC -->
* [PCAP Release API Documentation](#pcap-release-api-documentation)
  * [CF Case Overview](#cf-case-overview)
    * [Target Identification via Cloud Controller (Option)](#target-identification-via-cloud-controller--option-)
    * [Target Registration via NATS (Option)](#target-registration-via-nats--option-)
  * [BOSH Case Overview](#bosh-case-overview)
  * [Interactions](#interactions)
    * [pcap-cli -> pcap-api](#pcap-cli----pcap-api)
    * [pcap-bosh-cli -> BOSH Director UAA](#pcap-bosh-cli----bosh-director-uaa)
    * [pcap-cf-cli](#pcap-cf-cli)
    * [pcap-api](#pcap-api)
    * [NATS -> pcap-api (option)](#nats----pcap-api--option-)
    * [pcap-agent -> pcap-api](#pcap-agent----pcap-api)
    * [Diego route registrar -> NATS (Option)](#diego-route-registrar----nats--option-)
    * [pcap-api -> pcap-cli](#pcap-api----pcap-cli)
  * [Data Structures](#data-structures)
    * [Capture Request](#capture-request)
      * [Common Fields for `pcap-agent`](#common-fields-for-pcap-agent)
      * [CF App Start Capture Request](#cf-app-start-capture-request)
      * [BOSH Start Capture Request](#bosh-start-capture-request)
      * [Stop Capture Request](#stop-capture-request)
    * [Message](#message)
      * [Enum `MessageType`](#enum-messagetype)
    * [Status](#status)
    * [PCAP Data](#pcap-data)
    * [Capture Response](#capture-response)
  * [Use Cases](#use-cases)
    * [Initialization](#initialization)
    * [Regular Request with Clean Shutdown](#regular-request-with-clean-shutdown)
    * [Authentication and Authorization Failures](#authentication-and-authorization-failures)
    * [Unexpected Disconnects](#unexpected-disconnects)
    * [Invalid Requests](#invalid-requests)
    * [Resource Limits](#resource-limits)
<!-- TOC -->

This document contains the API specification for the PCAP release.

> The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

The pcap-release automates the identification of network capture targets based on metadata from:

- **Cloud Foundry Applications**, where network traffic is captured directly from the application container.  
- **BOSH** Deployment VMs, where network traffic is captured on the VM.

Pcap-release uses gRPC for communication between all components. This document highlights the intended use of fields, scenarios considered by the implementation and detailed explanation of the data structures.

## CF Case Overview

Capturing data from cloud foundry applications REQUIRES the pcap-agent inside the app container. 

The pcap-agent MUST be able to run in HTTP/2 with TLS and plain-text (H2C). The H2C support is needed in the case that the Envoy proxy is used in the app container to provide the TLS termination.

The `pcap-cf-cli` is a plugin to the cf CLI. The default login mechanism, which communicates with the CF UAA, SHALL be used to obtain a token and is outside the scope of the pcap-release.
For the pcap-release, the existing token SHALL be reused.

```mermaid
flowchart LR
    subgraph UAA authentication
        cf[cf UAA]
    end

  style nats fill:#ccf,stroke:#333,stroke-width:2px,color:#fff,stroke-dasharray: 5 5
  style c1e fill:#999,stroke:#333,stroke-width:2px,color:#000,stroke-dasharray: 5 5
  style c2e fill:#999,stroke:#333,stroke-width:2px,color:#000,stroke-dasharray: 5 5
  style c3e fill:#999,stroke:#333,stroke-width:2px,color:#000,stroke-dasharray: 5 5

  subgraph nats-vm
    nats
  end


  gorouter -->|HTTP/1.1, JSON| cf[cf UAA]
  pcap-cf-cli -->|H/2, gRPC| gorouter
  pcap-cf-cli -->|HTTP/1.1, JSON| gorouter
  gorouter -->|H/2, gRPC| pcap-api
    pcap-api ---|NATS| nats
    subgraph pcap deployment
      pcap-api
    end
    
    subgraph diego-cell1
        subgraph cf-app1
            pcap-api -->|H/2, gRPC| c1e[Envoy]
            c1e -->|H2C, gRPC| c1[pcap-agent]
        end
        
      subgraph cf-app2
            pcap-api -->|H/2, gRPC| c2e[Envoy]
        c2e -->|H2C, gRPC| c2[pcap-agent]
      end
      route-registrar1[route-registrar] -.->|NATS| nats
    end
    subgraph diego-cell2
        subgraph cf-app3
            pcap-api -->|H/2, gRPC| c3e[Envoy]
            c3e -->|H2C, gRPC| c3[pcap-agent]
        end
      route-registrar2[route-registrar] -.->|NATS| nats
    end
    subgraph cloud-controller
      pcap-api -->|HTTP/1.1, JSON| cc[Cloud Controller]
    end

```

Figure 1: The Cloud Foundry Application Capturing case

In the CF case, `pcap-agent` runs in the app container. The availability and IP/Port where `pcap-agent` is exposed MUST be accessible to the pcap-api. It CAN be proxied by Envoy.

Identifying the `pcap-agent` in a specific app container can be done:

- by querying the [Cloud Controller](#target-identification-via-cloud-controller--option-)
- by sending [Registration Messages transported via NATS](#target-registration-via-nats--option-)

Both options are described below.

### Target Identification via Cloud Controller (Option)

For the target identification via Cloud Controller, the pcap-api MUST query the cloud controller to identify the target IP and port of the `pcap-agent` in the app container, as exposed by Envoy.

### Target Registration via NATS (Option)

For target registration via NATS, the pcap-agent MUST send a `pcap.register` message indicating:

- the app ID/org ID/space ID
- the IP address of the Diego cell (can be retrieved from the CF app environment)
- the external port of the `pcap-agent`, as provided by Envoy.

When the `pcap-agent` goes offline it MUST send a `pcap.deregister` message.

```mermaid
sequenceDiagram
    pcap-api ->> nats: subscribe: pcap.*
  
    note over diego-cell1: An App becomes healthy
    note over diego-cell2: An App becomes healthy
    loop
        diego-cell1 ->> nats: pcap.register (pcap-agent-[instance1], diego-ip:61404)
        nats ->> pcap-api: pcap.register (pcap-agent-[instance1], diego-ip:61404)
        note right of pcap-api: Store/update agent<br>endpoint: pcap-agent-[instance1], diego-ip:61404
        pcap-api --> pcap-api: 
        diego-cell2 ->> nats: pcap.register (pcap-agent-[instance2], diego-ip:61294)
        nats ->> pcap-api: pcap.register (pcap-agent-[instance2], diego-ip:61294)
        note right of pcap-api: Store/update agent<br>endpoint: pcap-agent-[instance2], diego-ip:61294
        pcap-api --> pcap-api: 
    end
    note over diego-cell1: An app instance1 becomes unhealthy
    note over diego-cell2: An app instance2 unhealthy

    diego-cell1 ->> nats: pcap.deregister (pcap-agent-[instance1], diego-ip:61404)
    nats ->> pcap-api: pcap.deregister (pcap-agent-[instance1], diego-ip:61404)
    note right of pcap-api: Remove agent<br>endpoint: pcap-agent-[instance1], diego-ip:61404
    pcap-api --> pcap-api: 

    diego-cell2 ->> nats: pcap.deregister (pcap-agent-[instance2], diego-ip:61294)
    nats ->> pcap-api: pcap.deregister (pcap-agent-[instance2], diego-ip:61294)
    note right of pcap-api: Remove agent<br>endpoint: pcap-agent-[instance2], diego-ip:61294    
    pcap-api --> pcap-api: 
```

The `pcap-agent` SHOULD send refresh messages in a regular interval, so pcap-api can have an up-to-date view of available pcap-agents. This COULD be used for automated pruning of registered pcap-agents.

## BOSH Case Overview

Capturing data from BOSH deployments requires the pcap-agent on the individual BOSH VMs. The pcap-agent runs on a well-known port and takes care of mTLS verification.

The BOSH director is used to verify and find the requested target VMs' IP addresses. The BOSH UAA is used to verify the token provided by the client.

```mermaid
flowchart LR
    pcap-bosh-cli -->|H/2, gRPC| gorouter
    gorouter -->|H/2, gRPC| pcap-api

    subgraph pcap deployment
        pcap-api
    end
        
    subgraph bosh-deployment-vm1
        pcap-api -->|H/2, gRPC| a1[pcap-agent]
    end
    subgraph bosh-deployment-vm2
        pcap-api -->|H/2, gRPC| a2[pcap-agent]
    end

    subgraph bosh-director-vm
        pcap-api -->|HTTP/1.1, JSON| bosh[BOSH Director]
      pcap-api -->|HTTP/1.1, JSON| bosh-uaa[BOSH UAA]
    end

    pcap-bosh-cli -->|HTTP/1.1, JSON| gorouter
    gorouter -->|HTTP/1.1, JSON| bosh-uaa
```

Figure 2: The BOSH Capturing case

## Interactions

There are two modes of operation, for CF and for BOSH, with two respective CLIs. Those CLIs implement specific communication and parameters for the different use cases, but otherwise contain the same logic to communicate with the pcap-api, which in turn communicates with the pcap-agent.

For the sake of simplification, the term `pcap-api` aims at the logical CLI client contained in both CF and BOSH specific CLIs. The specific names `pcap-cf-cli` and `pcap-bosh-cli` are used to highlight interactions specific to that CLI client.

### pcap-cli -> pcap-api

- request status (version information, service alive)
- Send stop request

### pcap-bosh-cli -> BOSH Director UAA

- Refresh access token via Refresh token
- BOSH Capture Request

### pcap-cf-cli

- Communication with UAA, via plugin host CF CLI
- CF Capture Request

### pcap-api

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
    - HTTP: Retrieve JWT token key (used for RSA signature verification)
- pcap-api -> pcap-agent
  - Status
  - Send Capture Request
  - Send stop request

### NATS -> pcap-api (option)

- Send registration and deregistration messages, according to subscription

### pcap-agent -> pcap-api

- Send status
- Send Capture Response
  - Message
    - Stop
    - Congestion
    - Error
      - Limit reached (e.g. number of concurrent capture requests exceeded, )
      - Invalid Request (e.g. malformed filter, device not found, etc.)
      - Runtime (any unexpected error occurring on the agent during capture. Contains as much information as possible and forward before terminating)
  - captured pcap data packets

### Diego route registrar -> NATS (Option)

- Send registration and deregistration messages

### pcap-api -> pcap-cli

- Status
- captured pcap data packets
- Message
  - Stop confirmation
  - Capture status
    - Agent is gone
    - All agents stopped
    - Congestion
  - Errors
    - Limit reached (e.g. number of concurrent capture requests exceeded on the pcap-api or pcap-agent)
    - Unauthorized
    - Invalid Request (e.g. malformed filter, Target not found, device not found)

## Data Structures

The following section defines the data structures, their use and fields' purpose in detail.

### Capture Request

A capture request contains the information needed to target a set of resources, from which to capture network traffic.

- **For CF**, a resource is a single application instance.
  - The capture request can target all instances at once by omitting specific application instance IDs
- **For BOSH**, a resource is a single BOSH VM.
  - The capture request can target individual VMs or all VMs in one or multiple instance groups of a BOSH deployment.

The capture request can contain a start or stop request. The start request can either be for CF or BOSH respectively:

- `start`: one of [CF App Start Capture Request](#cf-app-start-capture-request), [BOSH Start Capture Request](#bosh-start-capture-request)
- `stop`: a [Stop Capture Request](#stop-capture-request)

#### Common Fields for `pcap-agent`

The following attributes are part of all capture requests and define the details required for the `pcap-agent`.

| Parameter | Type    | Required? | Default | Description                                                                                          |
|-----------|---------|-----------|---------|------------------------------------------------------------------------------------------------------|
| `device`  | string  | yes       | `eth0`  | The device on the app container from which to capture the traffic                                    |
| `filter`  | string  | no        |         | BPF Filter expression to use with tcpdump command to capture traffic.                                |
| `snaplen` | integer | no        | 65535   | Limit the amount of data captured for each packet, see [SnapLen](https://wiki.wireshark.org/SnapLen) |

#### CF App Start Capture Request

| Parameter        | Type       | Required? | Default | Description                                                                                                                                                  |
|------------------|------------|-----------|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
|                  | `Common`   | yes       |         | All [common fields](#common-fields-for-pcap-agent) are included in a CF capture request                                                                      |
| `token`          | `string`   | yes       |         | The CF UAA token for the user sending the capture request.                                                                                                   |
| `application_id` | `string`   | yes       |         | The ID of the target application.                                                                                                                            |
| `type`           | `string`   | no        | `web`   | An app can have processes of different types, `web` being the default. This allows targeting processes of a specific type for this app.                      |
| `instance_ids`   | `[]int`    | no        | `[]`    | List of instance indexes of the application. An empty list indicates that **all instances** should be captured. Mutually exclusive with `instance_guids`.    |
| `instance_guids` | `[]string` | no        | `[]`    | List of instance IDs for finer-grained targeting. An empty list indicates that **all instances** should be captured. Mutually exclusive with `instance_ids`. |

Example request, serialized as JSON:

```json
{
  "capture": {
    "device": "eth0",
    "filter": "host 1.2.3.4 and port 443",
    "snaplen": 96
  },
  "token": "(UAA token)",
  "application_id": "d55b98ba-f645-4219-8b49-2b4654a1716C",
  "type": "web",
  "instance_ids": [1, 4, 7]
}
```

#### BOSH Start Capture Request

| Parameter        | Type       | Required? | Default | Description                                                                                                                                                  |
|------------------|------------|-----------|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
|                  | `Common`   | yes       |         | All [common fields](#common-fields-for-pcap-agent) are included in a CF capture request                                                                      |
| `token`          | `string`   | yes       |         | The BOSH UAA token for the user sending the capture request.                                                                                                 |
| `deployment`     | `string`   | yes       |         | The name of the target BOSH deployment.                                                                                                                      |
| `groups`         | `[]string` | yes       |         | A list of instance groups from which to capture. **Must contain at least one instance group**.                                                               |
| `instance_guids` | `[]string` | no        | `[]`    | List of instance IDs for finer-grained targeting. An empty list indicates that **all instances** should be captured. Mutually exclusive with `instance_ids`. |

Example request, serialized as JSON:

```json
{
  "capture": {
    "device": "eth0",
    "filter": "host 1.2.3.4 and port 443",
    "snaplen": 96
  },
  "token": "(BOSH UAA token)",
  "deployment": "cf",
  "groups": ["router", "diego-cell"],
  "instance_guids": [
    "d55baeba-f645-4219-8b49-2b4654a17165",
    "12345678-f645-4219-8b49-d41cb3e04f99"
  ]
}
```

#### Stop Capture Request

The stop capture request just indicates that the capture on the current stream is requested to be stopped gracefully.

### Message

| Parameter      | Type               | Required? | Description                                                                                                                                          |
|----------------|--------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `message_type` | `enum MessageType` | yes       | The type of message sent. This allows for logic based on the message type                                                                            |
| `origin`       | `string`           | yes       | The sender of this message, e.g. `pcap-api-[group/guid]`, `pcap-agent-[instance_id]`                                                                 |
| `message`      | `string`           | no        | The detailed message, human readable, explaining the reason for this message. Optional but recommended, as it could be shown on the CLI to the user. |

Examples for origin:
```
# bosh, originating from the pcap-api:
pcap-api-router/d55baeba-f645-4219-8b49-2b4654a17165

# bosh, originating from the pcap-agent
pcap-agent-router/d55baeba-f645-4219-8b49-2b4654a17165


# cf, orginating from the pcap-api
pcap-api-f9281cda-1234-bbcd-ef12-1337cafe0048

# cf, originating from the pcap-agent
pcap-agent-f9281cda-1234-bbcd-ef12-1337cafe0048
```

Example message:

```json
{
  "message_type": "Message_CAPTURE_STOPPED",
  "origin": "pcap-api-router/d55baeba-f645-4219-8b49-2b4654a17165",
  "message": "Capturing stopped on agent pcap-agent-router/d55baeba-f645-4219-8b49-2b4654a17165"
}
```

This message indicates that pcap-api received a capture stopped indication (i.e. `OK` status) from the pcap-agent on `router/d55baeba-f645-4219-8b49-2b4654a17165` and passes it on to a CLI.

#### Enum `MessageType`

The table below shows the `MessageType` enum and the meanings of the various values.

When a Native Termination Status is listed, the `pcap-agent` is expected to send this state when closing the connection using the native transport mechanism means. In the case of gRPC, this would be the gRPC Termination State.

Information received from pcap-agent as native termination status code MUST be converted to a `Message` with appropriate `MessageType`, and passed on to the pcap-cli.

| Value                   | Native Termination Status | Origin                   | Description                                                                                                                                                                                                                                                                                                   |
|-------------------------|---------------------------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `INSTANCE_UNAVAILABLE`  | `UNAVAILABLE`             | `pcap-api`               | One of the requested instances does not exist but there is at least one instance to capture from. MUST be sent as soon as possible.<br/>OR: One instance failed during capturing but there are still instances left to capture from. The detailed message should contain information about the stopped party. |
| `START_CAPTURE_FAILED`  | `FAILED_PRECONDITION`     | `pcap-api`               | Starting the capture request has failed because the request could not be fulfilled (e.g. no matching instances, pcap feature not enabled, no capture running)                                                                                                                                                 |
| `INVALID_REQUEST`       | `INVALID_ARGUMENT`        | `pcap-api`, `pcap-agent` | The request could not be fulfilled, e.g. because the app or BOSH deployment with the requested name do not exist.                                                                                                                                                                                             |
| `CONGESTED`             |                           | `pcap-api`, `pcap-agent` | Some participant on the path is congested to the point of discarding data. The detailed message should contain the congested party.                                                                                                                                                                           |
| `CAPTURE_STOPPED`       | `OK`                      | `pcap-api`, `pcap-agent` | A single agent or the overall capture has stopped gracefully. The detailed message should contain information about the stopped party.                                                                                                                                                                        |
| `LIMIT_REACHED`         | `RESOURCE_EXHAUSTED`      | `pcap-api`, `pcap-agent` | Some limit has been reached, e.g. number of concurrent requests, time, bytes, etc.; Message details identifies, which limit has been reached.                                                                                                                                                                 |
|                         | `UNAUTHENTICATED`         | `pcap-api`               | The token sent by the client is rejected (e.g. invalid, timed out, etc.). Detail for the rejection in the message.                                                                                                                                                                                            |                                                                                                     |
| `CONNECTION_ERROR`      |                           | `pcap-api`               | An error happened while attempting communication with PCAP components, independent of the client.                                                                                                                                                                                                             |
|                         | `ABORTED`                 | `pcap-api`               | The capture initially started but while capturing all agents failed and no data is left to forward.                                                                                                                                                                                                           |

If the cause of the error is not clear (e.g. because it could be multiple things) and processing can not continue `UNKNOWN` should be used as the native termination status.

### Status

The status is provided by `pcap-agent` and `pcap-api`. It SHALL be used by the connecting party to ensure that communication happens with the appropriate endpoint and that two parties are compatible. The calling party has to ensure that the compatibility level of the called party is equal or larger and refuse request if it isn't.

Compatibility level is particularly important to stop communication with outdated (and potentially vulnerable) `pcap-agent`s.

| Parameter            | Type      | Required? | Description                                                                                                                                             |
|----------------------|-----------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `healthy`            | `boolean` | yes       | The health state of the agent in question                                                                                                               |
| `compatibilityLevel` | `integer` | yes       | The compatibility level. Once there is a change (like a security issue) that requires both parties to be updated this value MUST be incremented by one. |
| `message`            | `string`  | yes       | A human readable status message.                                                                                                                        |
| `cf`                 | `boolean` | no        | Supports CF requests (only for pcap-api)                                                                                                                |                                                                                               
| `bosh`               | `boolean` | no        | Supports BOSH requests (only for pcap-api)                                                                                                              |                                                                                                

Examples:
```json
{
  "healthy": true,
  "compatibilityLevel": 1,
  "message": "Up with CF and BOSH endpoints",
  "cf": true,
  "bosh": true
}
```

Example for an agent status
```json
{
  "healthy": true,
  "compatibilityLevel": 1,
  "message": "Up, on BOSH instance router/d55baeba-f645-4219-8b49-2b4654a17165" 
}
```

### PCAP Data

| Parameter | Type        | Description                                                               |
|-----------|-------------|---------------------------------------------------------------------------|
| `data`    | `[][]bytes` | One, potentially multiple, complete packets as captured from the network. |

### Capture Response

Capture Response is a stream that may contain multiple of the following data structures:

- [PCAP Data](#pcap-data)
- [Message](#message)

Messages are used to communicate status and errors, and SHALL be forwarded to the requesting client for information. The client MAY present status information to the user.

## Use Cases

The following use cases were considered and should cover the 'happy path' as well as error conditions:

- Regular request with clean shutdown
- Authentication issue(s)
- Agent disconnects unexpectedly
- Request is invalid and cannot be started
  - Identified by the pcap-api
  - Identified by the pcap-agents
  - Some agents cannot comply with the request and don't start
  - Resource Limit
- Congestion
  - on pcap-agent
  - on pcap-api

### Initialization

For **BOSH**, on startup of pcap-api, the BOSH director needs to be contacted in order to:

- make sure the URL is reachable and the endpoint is a BOSH director
- retrieve the URL for the BOSH UAA

```mermaid
sequenceDiagram
    pcap-api ->> bosh-director: /info
    bosh-director ->> pcap-api: BOSH Director Info w/ UAA URL
```

For **CF**, on startup of pcap-api, the Cloud Controller needs to be contacted in order to get :

- The UAA Base URL

This will validate the availability of Cloud Controller.

```mermaid
sequenceDiagram
    pcap-api ->> cloud-controller: /
    cloud-controller ->> pcap-api: CF API URLs
```

### Regular Request with Clean Shutdown

The regular case with a graceful shutdown of all components is shown below for BOSH and CF case respectively.

BOSH Case:

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>BOSH (Deployment, Groups, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> bosh-uaa: Token Keys?
    bosh-uaa ->> pcap-api: Token Keys
    note over pcap-api, bosh-uaa: Token and scope verification    
    pcap-api ->> bosh-director: Instances (Deployment)?
    bosh-director ->> pcap-api: Instances (Deployment)
    par
        pcap-api ->> pcap-agent1: Capture pcap(eth0, "host 1.2.3.4", 65k)
        pcap-api ->> pcap-agent2: Capture pcap(eth0, "host 1.2.3.4", 65k)
        loop
            pcap-agent1 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
            pcap-agent2 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
        end
    end
    pcap-cli ->> pcap-api: Stop
    par
        pcap-api ->> pcap-agent1: Stop
        pcap-api ->> pcap-agent2: Stop
        pcap-agent2 ->> pcap-api: OK (pcap-agent2 stopped)
        pcap-agent1 ->> pcap-api: OK (pcap-agent1 stopped)
        pcap-api ->> pcap-cli: Message: CAPTURE_STOPPED (pcap-agent1)
        pcap-api ->> pcap-cli: Message: CAPTURE_STOPPED (pcap-agent2)
    end

    pcap-api ->>- pcap-cli: OK
```

CF Case (with cloud controller and NATS options)

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (AppID, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token valid
    pcap-api ->> cloud-controller: pcap feature enabled for (AppID, Instances)?
    cloud-controller ->> pcap-api: Feature enabled.
    alt Target agent identification via Cloud Controller
        pcap-api ->> cloud-controller: Instances (AppID, Instances)?
        cloud-controller ->> pcap-api: Instances (AppID, Instances)
    else Target agent registry via NATS
        note right of pcap-api: Look up targets in agent registry
        pcap-api ->> pcap-api: 
    end
    par
        pcap-api ->> pcap-agent1: Capture pcap(eth0, "host 1.2.3.4", 65k)
        pcap-api ->> pcap-agent2: Capture pcap(eth0, "host 1.2.3.4", 65k)
        loop
            pcap-agent1 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
            pcap-agent2 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
        end
    end
    pcap-cli ->> pcap-api: Stop
    note over pcap-cli, pcap-api: Client requests a graceful stop
    par
        pcap-api ->> pcap-agent1: Stop
        pcap-api ->> pcap-agent2: Stop
        pcap-agent2 ->> pcap-api: OK (pcap-agent2 stopped)
        pcap-agent1 ->> pcap-api: OK (pcap-agent1 stopped)
        pcap-api ->> pcap-cli: Message: CAPTURE_STOPPED (pcap-agent1)
        pcap-api ->> pcap-cli: Message: CAPTURE_STOPPED (pcap-agent2)
    end

    pcap-api ->>- pcap-cli: OK

```

### Authentication and Authorization Failures

On authentication failures, the message `UNAUTHENTICATED` is sent back. The message detail explains the reason for rejection, e.g. signature check failed, token expired, etc.

In the case that the authentication is valid but does not have enough permissions, `PERMISSION_DENIED` is sent instead.

The following sequence, with CF as example, shows the flows. The same applies to the BOSH scenario.

```mermaid
sequenceDiagram
    note over pcap-cli, cf-uaa: Token invalid
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (App, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token invalid

    pcap-api ->>- pcap-cli: UNAUTHENTICATED (Reason, e.g. token expired)

    note over pcap-cli, cf-uaa: Not enough permissions
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (App, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token valid
    pcap-api ->> cloud-controller: pcap feature enabled for (AppID, Instances)?
    cloud-controller ->> pcap-api: Feature enabled.
    pcap-api ->> pcap-api: check permissions

    pcap-api ->>- pcap-cli: PERMISSION_DENIED (e.g. role not allowed to do pcap dumps)
```

### Unexpected Disconnects

A clean shutdown of components and notification is necessary when either one of the components disconnect unexpectedly.

When a pcap-agent terminates while capturing, e.g. due to crash or because its connection is lost, pcap-api will notify the pcap-cli that this particular agent is now disconnected.

**NOTE:** This behaviour needs to work correctly, even when no `FIN` is sent from the client, e.g. the node disappears and the request times out.

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (AppID, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token valid
    pcap-api ->> cloud-controller: pcap feature enabled for (AppID, Instances)?
    cloud-controller ->> pcap-api: Feature enabled.
  
    pcap-api ->> cloud-controller: Instances (AppID, Instances)?
    cloud-controller ->> pcap-api: Instances (AppID, Instances)
    par
        pcap-api ->> pcap-agent1: Capture pcap(eth0, "host 1.2.3.4", 65k)
        pcap-api ->> pcap-agent2: Capture pcap(eth0, "host 1.2.3.4", 65k)
        loop
            pcap-agent1 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
            pcap-agent2 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
        end
    end
    pcap-agent1 --X pcap-api: Connection terminated
    pcap-api ->> pcap-cli: Message: INSTANCE_DISCONNECTED (pcap-agent1)
    note over pcap-cli, pcap-api: Client requests a graceful stop
    pcap-cli ->> pcap-api: Stop
    par
        pcap-api ->> pcap-agent2: Stop
        pcap-agent2 ->> pcap-api: OK (pcap-agent2)
        pcap-api ->> pcap-cli: Message: CAPTURE_STOPPED (pcap-agent2)
    end

    pcap-api ->>- pcap-cli: OK
    
```

In the case that the pcap-cli disconnects without stopping the capture, the pcap-api will stop all capture requests on pcap-agents for this client.

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (AppID, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token valid
    pcap-api ->> cloud-controller: pcap feature enabled for (AppID, Instances)?
    cloud-controller ->> pcap-api: Feature enabled.
    alt Target agent identification via Cloud Controller
        pcap-api ->> cloud-controller: Instances (AppID, Instances)?
        cloud-controller ->> pcap-api: Instances (AppID, Instances)
    else Target agent registry via NATS
        note right of pcap-api: Look up targets in agent registry
        pcap-api ->> pcap-api: 
    end
    par
        pcap-api ->> pcap-agent1: Capture pcap(eth0, "host 1.2.3.4", 65k)
        pcap-api ->> pcap-agent2: Capture pcap(eth0, "host 1.2.3.4", 65k)
        loop
            pcap-agent1 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
            pcap-agent2 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
        end
    end
    pcap-cli --X pcap-api: Connection terminated
    note over pcap-api: Terminate all agents for this client
    par
        pcap-api ->> pcap-agent1: Stop
        pcap-api ->> pcap-agent2: Stop
        pcap-agent1 ->> pcap-api: OK (pcap-agent1)
        pcap-agent2 ->> pcap-api: OK (pcap-agent2)
    end
```

In the case that a long-running request is terminated by gorouter due to context deadline, the request will be terminated and the CLI informed by gorouter. The pcap-agent needs to clean up in this case.

```mermaid
sequenceDiagram
    pcap-cli ->>+ gorouter: Token, Capture Request {<br/>CF (AppID, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    gorouter ->>+ pcap-api: Token, Capture Request {<br/>CF (AppID, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token valid
    pcap-api ->> cloud-controller: pcap feature enabled for (AppID, Instances)?
    cloud-controller ->> pcap-api: Feature enabled.
    alt Target agent identification via Cloud Controller
        pcap-api ->> cloud-controller: Instances (AppID, Instances)?
        cloud-controller ->> pcap-api: Instances (AppID, Instances)
    else Target agent registry via NATS
        note right of pcap-api: Look up targets in agent registry
        pcap-api ->> pcap-api: 
    end
    par
        pcap-api ->> pcap-agent1: Capture pcap(eth0, "host 1.2.3.4", 65k)
        pcap-api ->> pcap-agent2: Capture pcap(eth0, "host 1.2.3.4", 65k)
        loop
            pcap-agent1 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
            pcap-agent2 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
        end
    end
    note over pcap-cli, gorouter: The request was longer than<br/>the gorouter request deadline
    gorouter --X pcap-cli: Context deadline exceeded
    gorouter --X pcap-api: Context deadline exceeded
    par
        pcap-api ->> pcap-agent1: Stop
        pcap-api ->> pcap-agent2: Stop
        pcap-agent1 ->> pcap-api: OK (pcap-agent1)
        pcap-agent2 ->> pcap-api: OK (pcap-agent2)
    end
```

### Invalid Requests

Requests can be invalid for many reasons.

The following diagram presents the following invalid request reasons for BOSH captures:

- Invalid deployment name
- Invalid instance group
- No instances matching the request

```mermaid
sequenceDiagram
    note over pcap-cli, pcap-api: Scenario: Unknown Deployment
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>BOSH (Deployment, Groups, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> bosh-uaa: Token Keys?
    bosh-uaa ->> pcap-api: Token Keys
    note over pcap-api, bosh-uaa: Token and scope verification    
    pcap-api ->> bosh-director: Instances (Deployment)?
    bosh-director ->> pcap-api: Unknown deployment: Deployment
    pcap-api ->> pcap-cli: INVALID_ARGUMENT (Unknown deployment: Deployment)
    pcap-api -->- pcap-cli: Close

    note over pcap-cli, pcap-api: Scenario: Invalid Instance Group(s) or Instance IDs
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>BOSH (Deployment, Groups, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> bosh-uaa: Token Keys?
    bosh-uaa ->> pcap-api: Token Keys
    note over pcap-api, bosh-uaa: Token and scope verification    
    pcap-api ->> bosh-director: Instances (Deployment)?
    bosh-director ->> pcap-api: Instances (Deployment)
    note over pcap-api: List does not contain matching<br/>instance groups(s) or instance IDs
    pcap-api ->>- pcap-cli: INVALID_ARGUMENT (Requested instances not found)
```

Availability issues:

- No pcap-agents available in BOSH case (e.g. not deployed for the given deployment, not reachable)
- `PCAP permission` for the space, under which the application is hosted, is not enabled in the CF case

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>BOSH (Deployment, Groups, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> bosh-uaa: Token Keys?
    bosh-uaa ->> pcap-api: Token Keys
    note over pcap-api, bosh-uaa: Token and scope verification    
    pcap-api ->> bosh-director: Instances (Deployment)?
    bosh-director ->> pcap-api: Instances (Deployment)
    note over pcap-api: Find and check pcap-agent targets
    note over pcap-api: None found or unable to connect.
    
    pcap-api ->>- pcap-cli: FAILED_PRECONDITION (No instances found to capture ...)
```

The PCAP feature CAN be enabled for a space. If it is not enabled, the capture will fail.

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (AppID, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token valid
    pcap-api ->> cloud-controller: pcap feature enabled for (AppID, Instances)?
    cloud-controller ->> pcap-api: Feature NOT enabled.
    note over pcap-api: PCAP not enabled on the space.
    
    pcap-api ->>- pcap-cli: FAILED_PRECONDITION (PCAP feature not enabled on space XYZ ...)
```

Issues discovered by pcap-agent:

- Invalid Snap Length
- Invalid / not available device
- Invalid syntax of filter
  - Open Question: pre-check on the pcap-cli/pcap-agent?

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (AppID, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 120k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token valid
    pcap-api ->> cloud-controller: pcap feature enabled for (AppID, Instances)?
    cloud-controller ->> pcap-api: Feature enabled.
    alt Target agent identification via Cloud Controller
        pcap-api ->> cloud-controller: Instances (AppID, Instances)?
        cloud-controller ->> pcap-api: Instances (AppID, Instances)
    else Target agent registry via NATS
        note right of pcap-api: Look up targets in agent registry
        pcap-api ->> pcap-api: 
    end
    par
        pcap-api ->>+ pcap-agent1: Capture pcap(eth0, "host 1.2.3.4", 120k)
        pcap-agent1 ->>- pcap-api: INVALID_ARGUMENT (pcap-agent1, SnapLen > max)
        pcap-api ->> pcap-cli: Message: INVALID_REQUEST (pcap-agent1, SnapLen > max)
    
        note over pcap-agent2: pcap-agent2 only has 'en0' interface
        pcap-api ->>+ pcap-agent2: Capture pcap(eth0, "host 1.2.3.4", 120k)
        pcap-agent2 ->>- pcap-api: INVALID_ARGUMENT (pcap-agent2, device eth0 not available)
        pcap-api ->> pcap-cli: Message: INVALID_REQUEST (pcap-agent2, device eth0 not available)
    end
    
    pcap-api ->>- pcap-cli: FAILED_PRECONDITION (No agents available)
```

The 'invalid filter' use case needs to be handled by the pcap-agent (i.e. sending back the appropriate message and terminating this request), but should ideally be avoided in the pcap-cli or latest pcap-api already by checking the BPF filter syntax before sending it on to the pcap-agent.

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (AppID, Instances)<br/>pcap ("eth0", "hosts 1.2.3.4", 120k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token valid
    pcap-api ->> cloud-controller: pcap feature enabled for (AppID, Instances)?
    cloud-controller ->> pcap-api: Feature enabled.
    alt Target agent identification via Cloud Controller
        pcap-api ->> cloud-controller: Instances (AppID, Instances)?
        cloud-controller ->> pcap-api: Instances (AppID, Instances)
    else Target agent registry via NATS
        note right of pcap-api: Look up targets in agent registry
        pcap-api ->> pcap-api: 
    end
    par
        pcap-api ->>+ pcap-agent1: Capture pcap(eth0, "hosts 1.2.3.4", 120k)
        pcap-agent1 ->>- pcap-api: INVALID_ARGUMENT (pcap-agent1, Unknown keyword 'hosts')
        pcap-api ->> pcap-cli: Message: INVALID_REQUEST (pcap-agent1, Unknown keyword 'hosts')
    
        note over pcap-agent2: pcap-agent2 only has 'en0' interface
        pcap-api ->>+ pcap-agent2: Capture pcap(eth0, "hosts 1.2.3.4", 120k)
        pcap-agent2 ->>- pcap-api: INVALID_ARGUMENT (pcap-agent2, Unknown keyword 'hosts')
        pcap-api ->> pcap-cli: Message INVALID_REQUEST (pcap-agent2, Unknown keyword 'hosts')
    end
    
    pcap-api ->>- pcap-cli: FAILED_PRECONDITION (No agents available)
```

Connections to mTLS can fail due to misconfiguration or expired certificates.

The fact that an mTLS connection failed should be forwarded to the CLI.

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (AppID, [1])<br/>pcap ("eth0", "host 1.2.3.4", 120k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token valid
    pcap-api ->> cloud-controller: pcap feature enabled for (AppID, Instances)?
    cloud-controller ->> pcap-api: Feature enabled.
    alt Target agent identification via Cloud Controller
        pcap-api ->> cloud-controller: Instances (AppID, [1])?
        cloud-controller ->> pcap-api: Instances (AppID, [1])
    else Target agent registry via NATS
        note right of pcap-api: Look up targets in agent registry
        pcap-api ->> pcap-api: 
    end
    par
        pcap-api -->+ pcap-agent1: Capture pcap(eth0, "host 1.2.3.4", 120k) [invalid mTLS Cert]
        pcap-agent1 ->> pcap-api: UNAVAILABLE (pcap-agent1, expected [1], got [other-guid])
    end

    pcap-api ->> pcap-cli: Message: MTLS_ERROR (pcap-agent1, expected [1], got [other-guid])
    
    pcap-api ->>- pcap-cli: FAILED_PRECONDITION (No agents available)
```

### Resource Limits

The amount of concurrently running captures (for each pcap-api instance and each pcap-agent instance) in order to avoid excessive use, overload, etc.

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (AppID, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> cf-uaa: Verify (Token)
    cf-uaa ->> pcap-api: Token valid
    pcap-api ->> cloud-controller: pcap feature enabled for (AppID, Instances)?
    cloud-controller ->> pcap-api: Feature enabled.
    alt Target agent identification via Cloud Controller
        pcap-api ->> cloud-controller: Instances (AppID, Instances)?
        cloud-controller ->> pcap-api: Instances (AppID, Instances)
    else Target agent registry via NATS
        note right of pcap-api: Look up targets in agent registry
        pcap-api ->> pcap-api: 
    end
    par
        note over pcap-agent1: pcap-agent1 already has<br/>ongoing captures
        pcap-api ->> pcap-agent1: Capture pcap(eth0, "host 1.2.3.4", 65k)
        pcap-api ->> pcap-agent2: Capture pcap(eth0, "host 1.2.3.4", 65k)
        loop
            pcap-agent2 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
        end
    end
    pcap-agent1 ->> pcap-api: RESOURCE_EXHAUSTED (pcap-agent1, Concurrent captures exceed limit)
    pcap-api ->> pcap-cli: Message: LIMIT_REACHED (pcap-agent1, Concurrent captures exceed limit)
    note over pcap-cli, pcap-api: Client requests a graceful stop
    pcap-cli ->> pcap-api: Stop
    par
        pcap-api ->> pcap-agent2: Stop
        pcap-agent2 ->> pcap-api: OK (pcap-agent2)
        pcap-api ->> pcap-cli: Message: CAPTURE_STOPPED (pcap-agent2)
    end

    pcap-api ->>- pcap-cli: OK
    
```

The limit for a particular client IP could also be reached with too many ongoing concurrent capture requests. To avoid synchronisation issues, the limit is enforced by each pcap-api instance, not globally.

```mermaid
sequenceDiagram
    note over pcap-cli, pcap-api: The source IP address already has captures running
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>CF (AppID, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> pcap-cli: Message: LIMIT_REACHED (pcap-api, Concurrent captures exceed limit)
    pcap-api -->- pcap-cli: Close
```

The pcap-agents have limited buffers for captured network traffic. When they cannot send their data to pcap-api fast enough, the buffer may fill up. To continue operation, pcap-agent will discard network packets until the buffer can fit further messages.

Consider that the `CONGESTED` message also takes up space in the buffer.

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>BOSH (Deployment, Groups, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> bosh-uaa: Token Keys?
    bosh-uaa ->> pcap-api: Token Keys
    note over pcap-api, bosh-uaa: Token and scope verification    
    pcap-api ->> bosh-director: Instances (Deployment)?
    bosh-director ->> pcap-api: Instances (Deployment)
    par
        pcap-api ->> pcap-agent1: Capture pcap(eth0, "host 1.2.3.4", 65k)
        pcap-api ->> pcap-agent2: Capture pcap(eth0, "host 1.2.3.4", 65k)
        loop
            note over pcap-agent1: pcap-agent1 is capturing more traffic<br/>than can be sent to pcap-api
            pcap-agent1 ->> pcap-api: pcap data
            pcap-agent1 ->> pcap-api: Message: CONGESTED (pcap-agent1, dropped 41 packets)
            pcap-api ->> pcap-cli: pcap data
            pcap-api ->> pcap-cli: Message: CONGESTED (pcap-agent1, dropped 41 packets)
            pcap-agent2 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
        end
    end
    note over pcap-cli, pcap-api: Client requests a graceful stop
    pcap-cli ->> pcap-api: Stop
    par
        pcap-api ->> pcap-agent1: Stop
        pcap-api ->> pcap-agent2: Stop
        pcap-agent2 ->> pcap-api: OK (pcap-agent2)
        pcap-agent1 ->> pcap-api: OK (pcap-agent1)
        pcap-api ->> pcap-cli: Message: CAPTURE_STOPPED (pcap-agent1)
        pcap-api ->> pcap-cli: Message: CAPTURE_STOPPED (pcap-agent2)
    end

    pcap-api ->> pcap-cli: OK
    pcap-api -->- pcap-cli: Close
```

When the pcap-api's buffers towards the client fill up, the pcap-api emits `CONGESTED` messages itself and drops packets to keep the request within limits. This usually happens when the connection to the client is slower than the data rate of the captured network traffic.

```mermaid
sequenceDiagram
    pcap-cli ->>+ pcap-api: Token, Capture Request {<br/>BOSH (Deployment, Groups, Instances)<br/>pcap ("eth0", "host 1.2.3.4", 65k) }
    pcap-api ->> bosh-uaa: Token Keys?
    bosh-uaa ->> pcap-api: Token Keys
    note over pcap-api, bosh-uaa: Token and scope verification    
    pcap-api ->> bosh-director: Instances (Deployment)?
    bosh-director ->> pcap-api: Instances (Deployment)
    par
        pcap-api ->> pcap-agent1: Capture pcap(eth0, "host 1.2.3.4", 65k)
        pcap-api ->> pcap-agent2: Capture pcap(eth0, "host 1.2.3.4", 65k)
        loop
            pcap-agent1 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
            pcap-agent2 ->> pcap-api: pcap data
            pcap-api ->> pcap-cli: pcap data
            note over pcap-api: pcap-api needs to forward more traffic<br/>than can be sent to pcap-cli 
            pcap-api ->> pcap-cli: Message: CONGESTED (pcap-api, dropped 24 packets)
        end
    end
            
    pcap-cli ->> pcap-api: Stop
    par
        pcap-api ->> pcap-agent1: Stop
        pcap-api ->> pcap-agent2: Stop
    pcap-agent2 ->> pcap-api: OK (pcap-agent2)
    pcap-agent1 ->> pcap-api: OK (pcap-agent1)
    pcap-api ->> pcap-cli: Message: CAPTURE_STOPPED (pcap-agent1)
    pcap-api ->> pcap-cli: Message: CAPTURE_STOPPED (pcap-agent2)
    end

    pcap-api ->>- pcap-cli: OK
```

FIXME: Add draining use case description
