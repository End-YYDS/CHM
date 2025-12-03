#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# CHM Component Installer
# - Downloads the latest release of a selected CHM component
# - Installs the binary into /usr/local/bin
# - Creates and configures the CHM group and configuration directory
###############################################################################

APP_KEY="${1:-}"

if [[ -z "${APP_KEY}" ]]; then
    echo "Usage: $0 {dhcp|api|ca|agent|mdns|cd|host|ldap}"
    exit 1
fi

APP_KEY="$(echo "${APP_KEY}" | tr 'A-Z' 'a-z')"

# --------------------------------------------------------------------------- #
# Logging helpers
# --------------------------------------------------------------------------- #
YELLOW="\033[33m"
RED="\033[31m"
GREEN="\033[32m"
RESET="\033[0m"

log_info()    { printf '[INFO] %s\n' "$*"; }
log_warn()    { printf "${YELLOW}[WARN]${RESET} %s\n" "$*"; }
log_error()   { printf "${RED}[ERROR]${RESET} %s\n" "$*" >&2; }
log_success() { printf "${GREEN}[ OK ]${RESET} %s\n" "$*"; }

# --------------------------------------------------------------------------- #
# Component mapping: user input -> release asset/binary name
# --------------------------------------------------------------------------- #
declare -A APP_MAP=(
    [dhcp]="CHM_dhcpd"
    [api]="CHM_APId"
    [ca]="CHMmCA"
    [agent]="CHM_agentd"
    [mdns]="CHMmDNS"
    [cd]="CHMcd"
    [host]="CHM_hostd"
    [ldap]="CHM_ldapd"
)

APP_NAME="${APP_MAP[${APP_KEY}]:-}"

if [[ -z "${APP_NAME}" ]]; then
    log_error "Unknown component name: ${APP_KEY}"
    echo "Valid options: dhcp, api, ca, agent, mdns, cd, host, ldap"
    exit 1
fi

log_info "Selected component: ${APP_KEY}  (binary name: ${APP_NAME})"

# --------------------------------------------------------------------------- #
# Fetch latest release tag from GitHub
# --------------------------------------------------------------------------- #
log_info "Retrieving latest release information from GitHub..."

LATEST_TAG="$(curl -fsSL https://api.github.com/repos/End-YYDS/CHM/releases/latest \
    | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"

if [[ -z "${LATEST_TAG}" ]]; then
    log_error "Failed to determine the latest release tag."
    exit 1
fi

log_info "Latest release tag: ${LATEST_TAG}"

ASSET_NAME="${APP_NAME}-x86_64-unknown-linux-gnu"
DOWNLOAD_URL="https://github.com/End-YYDS/CHM/releases/download/${LATEST_TAG}/${ASSET_NAME}"

log_info "Downloading asset: ${ASSET_NAME}"
log_info "From: ${DOWNLOAD_URL}"

curl -fsSL -o "${APP_NAME}" "${DOWNLOAD_URL}" || {
    log_error "Download failed."
    exit 1
}

chmod +x "${APP_NAME}"
log_success "Download completed."

# --------------------------------------------------------------------------- #
# System group and permissions
# --------------------------------------------------------------------------- #
log_info "Ensuring group 'CHM' exists..."
if sudo getent group CHM >/dev/null 2>&1; then
    log_info "Group 'CHM' already exists."
else
    if sudo groupadd CHM; then
        log_success "Group 'CHM' created."
    else
        log_error "Failed to create group 'CHM'."
        exit 1
    fi
fi

log_info "Adding current user '${USER}' to group 'CHM'..."
if sudo usermod -aG CHM "${USER}"; then
    log_success "User '${USER}' added to group 'CHM'."
    log_warn "Group membership will take effect on your next login or new shell."
else
    log_error "Failed to modify group membership for '${USER}'."
    exit 1
fi

# --------------------------------------------------------------------------- #
# Install binary
# --------------------------------------------------------------------------- #
log_info "Installing binary to /usr/local/bin/${APP_NAME} ..."
sudo install -o root -g CHM -m 0755 "${APP_NAME}" "/usr/local/bin/${APP_NAME}"
log_success "Binary installed."

# --------------------------------------------------------------------------- #
# Configuration directory
# --------------------------------------------------------------------------- #
log_info "Ensuring configuration directory /etc/CHM exists..."
sudo install -d -o root -g CHM -m 2775 /etc/CHM
log_success "Configuration directory ready."

# --------------------------------------------------------------------------- #
# CA-specific initialization
# --------------------------------------------------------------------------- #
if [[ "${APP_KEY}" == "ca" ]]; then
    log_info "Component 'ca' selected. Checking Root CA certificate..."

    mkdir -p certs

    if [[ ! -f "certs/rootCA.pem" ]]; then
        log_warn "Root CA certificate not found (certs/rootCA.pem)."
        log_info "Initializing Root CA using CHMmCA..."
        CHMmCA --root-ca
        log_success "Root CA generated."
    else
        log_info "Root CA certificate already exists. Skipping generation."
    fi
fi

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #
log_success "Installation completed successfully."
log_info    "You can now run the component using: ${APP_NAME}"
