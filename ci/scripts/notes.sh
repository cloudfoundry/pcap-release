#!/bin/bash

set -e

RELEASE_GIT_TAG="$1"
VERSION="$2"

RELEASE_TGZ="/tmp/pcap-${RELEASE_GIT_TAG}.tgz"
SHA1=$(sha1sum "${RELEASE_TGZ}" | head -n1 | awk '{print $1}')
export SHA1
SHA256=$(sha256sum "${RELEASE_TGZ}" | head -n1 | awk '{print $1}')
export SHA256

cat >> "${CONCOURSE_ROOT}/${RELEASE_ROOT}/notes.md" <<EOF
### Deployment
\`\`\`yaml
releases:
- name: "${RELEASE_NAME}"
  version: "${VERSION}"
  url: "https://github.com/${GITHUB_OWNER}/${RELEASE_NAME}/releases/download/v${VERSION}/pcap-${RELEASE_GIT_TAG}.tgz"
  sha1: "${SHA1}"

# for deployments with sha256, use the following line instead:
# sha1: "sha256:${SHA256}"
\`\`\`
EOF

cat "${CONCOURSE_ROOT}/${RELEASE_ROOT}/notes.md"
