#!/bin/bash

set -ex

RELEASE_GIT_TAG="$1"
mkdir -p "${CONCOURSE_ROOT}/${RELEASE_ROOT}/artifacts"

cp /tmp/pcap-"${RELEASE_GIT_TAG}".tgz "${CONCOURSE_ROOT}/${RELEASE_ROOT}/artifacts/"
