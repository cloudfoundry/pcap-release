#!/bin/bash

set -ex

RELEASE_GIT_TAG="${1:?Release Git Tag is mandatory}"
mkdir -p "${CONCOURSE_ROOT}/${RELEASE_ROOT}/artifacts"

cp /tmp/pcap-"${RELEASE_GIT_TAG}".tgz "${CONCOURSE_ROOT}/${RELEASE_ROOT}/artifacts/"
