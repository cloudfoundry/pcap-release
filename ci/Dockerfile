# Dockerfile for image cf-routing.common.repositories.cloud.sap/pcap-release-testflight
FROM bosh/docker-cpi:main

ARG GINKGO_VERSION=latest
ARG GOLANGCILINT_VERSION=latest
# Set bosh env at login
RUN echo "source /tmp/local-bosh/director/env" >> /root/.bashrc

# Install apt libs
RUN apt-get update && apt-get install -y libpcap-dev python3-pip && rm -rf /var/lib/apt/lists/*

# Install semantic-release and node lts
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && \
    apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*
RUN npm install -g semantic-release && \
    npm install -g @semantic-release/exec

# Install Python libraries needed for scripts
COPY scripts/requirements.txt /requirements.txt
RUN /usr/bin/python3 -m pip install -r /requirements.txt

ENV GOPATH=/go PATH=${PATH}:/go/bin

RUN go install "github.com/onsi/ginkgo/v2/ginkgo@${GINKGO_VERSION}" \
 && go install "github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCILINT_VERSION}" \
 && go install "github.com/geofffranks/spruce/cmd/spruce@latest"
