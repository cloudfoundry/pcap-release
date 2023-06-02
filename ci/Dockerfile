# Dockerfile for image cf-routing.common.repositories.cloud.sap/pcap-release-testflight:dev
FROM bosh/docker-cpi:main

ARG GINKGO_VERSION=latest
ARG GOLANGCILINT_VERSION=latest
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_current.x | sudo -E bash - && \
    apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*

# Set bosh env at login
RUN echo "source /tmp/local-bosh/director/env" >> /root/.bashrc

RUN npm install -g semantic-release && \
    npm install -g @semantic-release/exec

# Install go dependencies
ENV GOBIN=/usr/local/bin
RUN go install "github.com/onsi/ginkgo/v2/ginkgo@${GINKGO_VERSION}" \
 && go install "github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCILINT_VERSION}" \
 && go install "github.com/geofffranks/spruce/cmd/spruce@latest"
