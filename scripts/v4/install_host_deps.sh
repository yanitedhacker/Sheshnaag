#!/usr/bin/env bash
# Install Sheshnaag V4 host dependencies.
#
# Primary target: Ubuntu 22.04 / Debian 12 with KVM acceleration.
# Secondary target: macOS dev boxes (subset only — no kernel-mode tooling).
#
# Idempotent. Re-running on a configured host is a no-op for packages
# already present.
set -euo pipefail

OS="$(uname -s)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

log() { printf '[install_host_deps] %s\n' "$*"; }

install_linux() {
  if ! command -v sudo >/dev/null 2>&1; then
    log "sudo is required on Linux hosts"
    exit 2
  fi

  log "Updating apt index"
  sudo apt-get update -qq

  PACKAGES=(
    nftables
    dnsmasq
    inetsim
    libvirt-daemon-system
    qemu-kvm
    qemu-utils
    virtinst
    bridge-utils
    zeek
    tcpdump
    tshark
    python3-volatility3
    redis-tools
    curl
  )

  log "Installing: ${PACKAGES[*]}"
  sudo apt-get install -y --no-install-recommends "${PACKAGES[@]}"

  if ! command -v limactl >/dev/null 2>&1; then
    log "Skipping limactl install (not in default apt repo); install manually if needed."
  fi

  if ! command -v tetragon >/dev/null 2>&1; then
    log "Tetragon not detected — install via the Cilium project if eBPF runtime hardening is desired."
  fi

  log "Verifying virtualisation is available"
  if grep -qE 'vmx|svm' /proc/cpuinfo; then
    log "  hardware virtualisation: present"
  else
    log "  hardware virtualisation: NOT detected — beta detonation will fall back to software emulation"
  fi
}

install_macos() {
  if ! command -v brew >/dev/null 2>&1; then
    log "Homebrew is required on macOS dev boxes (https://brew.sh)"
    exit 2
  fi
  log "Installing macOS dev subset via brew"
  brew install dnsmasq tcpdump zeek redis curl
  log "macOS does not support kernel-mode collectors (Tetragon, Volatility-on-Linux);"
  log "real detonation must run on a Linux host. The dev subset is sufficient for"
  log "static analysis paths and unit tests."
}

case "${OS}" in
  Linux)
    install_linux
    ;;
  Darwin)
    install_macos
    ;;
  *)
    log "Unsupported OS: ${OS}"
    exit 2
    ;;
esac

log "Done. Verify the lab dependency status via: curl -s http://localhost:8000/api/v4/ops/health | jq .lab_deps"
