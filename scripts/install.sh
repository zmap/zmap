#!/usr/bin/env bash
# Install the ZMap APT repository and configure it as a priority source.
#
# Usage (as root or with sudo):
#   curl -fsSL https://storage.googleapis.com/zmap-apt-repo/install.sh | bash
#
# Or to point at a custom repo URL (e.g. staging):
#   curl -fsSL .../install.sh | bash -s -- https://storage.googleapis.com/zmap-apt-repo-staging
set -euo pipefail

REPO_URL="${1:-https://storage.googleapis.com/zmap-apt-repo}"
# 600 beats the distro default (500), ensuring our package wins without forcing
# removal of unrelated packages (which priority > 1000 would do).
PRIORITY="${2:-600}"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

if [ ! -f /etc/os-release ]; then
    echo "Error: /etc/os-release not found — cannot detect OS codename" >&2
    exit 1
fi
. /etc/os-release
CODENAME="${VERSION_CODENAME:-}"
if [ -z "$CODENAME" ]; then
    echo "Error: VERSION_CODENAME not set in /etc/os-release" >&2
    exit 1
fi

ARCH=$(dpkg --print-architecture)
REPO_HOST=$(echo "$REPO_URL" | sed 's|https\?://||; s|/.*||')

echo "Detected: ${PRETTY_NAME:-$ID $VERSION_ID}, codename=${CODENAME}, arch=${ARCH}"
echo "Repo: ${REPO_URL}"

$SUDO mkdir -p /usr/share/keyrings
curl -fsSL "${REPO_URL}/gpg.key" \
    | $SUDO gpg --dearmor -o /usr/share/keyrings/zmap-archive-keyring.gpg

echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/zmap-archive-keyring.gpg] ${REPO_URL} ${CODENAME} main" \
    | $SUDO tee /etc/apt/sources.list.d/zmap.list > /dev/null

$SUDO tee /etc/apt/preferences.d/zmap > /dev/null <<EOF
Package: zmap
Pin: origin ${REPO_HOST}
Pin-Priority: ${PRIORITY}
EOF

$SUDO apt-get update -qq
echo "ZMap repository configured. Run: ${SUDO} apt-get install -y zmap"
