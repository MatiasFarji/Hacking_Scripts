#!/bin/sh
#
# mitmproxy Chain Script for Bug Bounty
#
# Chains mitmproxy with Burp Suite to capture traffic in HAR format.
# Traffic flow: Burp Browser -> Burp (8080) -> mitmproxy (8081) -> Internet
#
# Setup:
#   1. Configure Burp upstream proxy: 127.0.0.1:8081
#   2. Run this script
#   3. Use Burp's embedded browser normally
#
# Usage:
#   ./chain_mitmproxy.sh [target_name]
#   ./chain_mitmproxy.sh              # reads from target.txt in script directory
#

set -e

# Get script directory (works with symlinks too)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Configuration
TARGET_FILE="$SCRIPT_DIR/target.txt"
PROXY_PORT=8081

# Colors for output (if terminal supports it)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    printf "${GREEN}[+]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[!]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[-]${NC} %s\n" "$1" >&2
}

# Get target name
if [ -n "$1" ]; then
    TARGET="$1"
elif [ -f "$TARGET_FILE" ]; then
    TARGET=$(cat "$TARGET_FILE" | tr -d '[:space:]')
else
    error "No target specified and $TARGET_FILE not found"
    echo "Usage: $0 [target_name]"
    exit 1
fi

# Validate target
if [ -z "$TARGET" ]; then
    error "Target name is empty"
    exit 1
fi

# Set paths (target directory is inside script directory)
TARGET_DIR="$SCRIPT_DIR/$TARGET"
FLOW_FILE="$TARGET_DIR/traffic.flow"
HAR_FILE="$TARGET_DIR/traffic.har"

# Create target directory if it doesn't exist
mkdir -p "$TARGET_DIR"

# Display session info
echo "========================================"
info "Target:     $TARGET"
info "Target dir: $TARGET_DIR"
info "Flow file:  $FLOW_FILE"
info "HAR file:   $HAR_FILE"
info "Proxy port: $PROXY_PORT"
echo "========================================"

# Check for existing session
if [ -f "$FLOW_FILE" ]; then
    warn "Existing session found - appending to flow file"
else
    info "Starting new capture session"
fi

# Check if mitmproxy is installed
if ! command -v mitmproxy >/dev/null 2>&1; then
    error "mitmproxy is not installed"
    echo "Install with: pip install mitmproxy"
    exit 1
fi

# Run mitmproxy (append mode with +)
info "Starting mitmproxy on port $PROXY_PORT..."
info "Press 'q' to quit and export HAR"
echo ""

mitmproxy -p "$PROXY_PORT" -w "+$FLOW_FILE"

# Export to HAR on exit
echo ""
info "Exporting flows to HAR format..."

if mitmdump -nr "$FLOW_FILE" --set hardump="$HAR_FILE" 2>/dev/null; then
    info "HAR saved: $HAR_FILE"
    
    # Show stats
    if command -v jq >/dev/null 2>&1; then
        ENTRIES=$(jq '.log.entries | length' "$HAR_FILE" 2>/dev/null || echo "?")
        info "Total requests captured: $ENTRIES"
    fi
else
    warn "HAR export failed"
    warn "Flows preserved in: $FLOW_FILE"
    echo ""
    echo "To manually export later, run:"
    echo "  mitmdump -nr \"$FLOW_FILE\" --set hardump=\"$HAR_FILE\""
fi

echo ""
info "Session complete"