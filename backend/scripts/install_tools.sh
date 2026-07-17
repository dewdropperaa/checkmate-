#!/bin/bash
# Install ProjectDiscovery security tools for local development
# Requires Go 1.21+ to be installed

set -e

TOOLS_DIR="${TOOLS_BINARY_DIR:-/opt/tools}"

echo "Installing ProjectDiscovery tools to ${TOOLS_DIR}..."

# Create tools directory if it doesn't exist
mkdir -p "${TOOLS_DIR}"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go 1.21+ first."
    echo "Visit: https://go.dev/doc/install"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "Go version: ${GO_VERSION}"

# Install tools
echo "Installing subfinder..."
GOBIN="${TOOLS_DIR}" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "Installing httpx..."
GOBIN="${TOOLS_DIR}" go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "Installing katana..."
GOBIN="${TOOLS_DIR}" go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo "Installing nuclei..."
GOBIN="${TOOLS_DIR}" go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Verify installations
echo ""
echo "Verifying installations..."
"${TOOLS_DIR}/subfinder" -version
"${TOOLS_DIR}/httpx" -version
"${TOOLS_DIR}/katana" -version
"${TOOLS_DIR}/nuclei" -version

echo ""
echo "Updating nuclei templates..."
"${TOOLS_DIR}/nuclei" -update-templates || true

echo ""
echo "Tools installed successfully to ${TOOLS_DIR}"
echo ""
echo "Also install (not covered by this script):"
echo "  npm install -g retire"
echo "  Start OWASP ZAP daemon on ZAP_API_URL (e.g. docker compose up zap)"
echo ""
echo "Add to your environment:"
echo "  export TOOLS_BINARY_DIR=${TOOLS_DIR}"
echo "  export PATH=\"\${TOOLS_BINARY_DIR}:\${PATH}\""
