#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# CHM Production Installer
#
# Description:
#   Automated deployment script for the CHM ecosystem.
#   - Fetches and installs release binaries.
#   - Initializes system groups and directory structures.
#   - Generates and patches default configurations (based on justfile logic).
#   - Provisions Systemd unit files for background service management.
#
# Usage:
#   sudo ./chm-install.sh [component_name]
###############################################################################

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
# Input Validation & Component Selection
# --------------------------------------------------------------------------- #
APP_KEY="${1:-}"

if [[ -z "${APP_KEY}" ]]; then
    echo "---------------------------------------------------------------"
    echo " CHM Component Selection"
    echo "---------------------------------------------------------------"
    PS3="Select a component to install (1-8): "
    options=("controller" "api" "ca" "dhcp" "dns" "ldap" "agent" "host" )

    select opt in "${options[@]}"; do
        if [[ -n "$opt" ]]; then
            APP_KEY=$opt
            log_info "You selected: $APP_KEY"
            break
        else
            log_warn "Invalid selection. Please try again."
        fi
    done
fi

APP_KEY="$(echo "${APP_KEY}" | tr 'A-Z' 'a-z')"

# --------------------------------------------------------------------------- #
# Component Mapping
# --------------------------------------------------------------------------- #
declare -A APP_MAP=(
    [dhcp]="CHM_dhcpd"
    [api]="CHM_APId"
    [ca]="CHMmCA"
    [agent]="CHM_agentd"
    [dns]="CHMmDNS"
    [cd]="CHMcd"
    [controller]="CHMcd"
    [host]="CHM_hostd"
    [ldap]="CHM_ldapd"
)

APP_NAME="${APP_MAP[${APP_KEY}]:-}"

if [[ -z "${APP_NAME}" ]]; then
    log_error "Unknown component name: ${APP_KEY}"
    exit 1
fi

log_info "Initializing installation procedure for: ${APP_NAME} (${APP_KEY})"

# --------------------------------------------------------------------------- #
# Fetch latest release tag from GitHub
# --------------------------------------------------------------------------- #
log_info "Fetching latest release information from GitHub..."

LATEST_TAG="$(curl -fsSL https://api.github.com/repos/End-YYDS/CHM/releases/latest \
    | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"

if [[ -z "${LATEST_TAG}" ]]; then
    log_error "Failed to retrieve the latest release tag."
    exit 1
fi

log_info "Latest release tag: ${LATEST_TAG}"

ASSET_NAME="${APP_NAME}-x86_64-unknown-linux-gnu"
DOWNLOAD_URL="https://github.com/End-YYDS/CHM/releases/download/${LATEST_TAG}/${ASSET_NAME}"

log_info "Downloading asset: ${ASSET_NAME}"
log_info "From: ${DOWNLOAD_URL}"

if curl -fsSL -o "${APP_NAME}" "${DOWNLOAD_URL}"; then
    chmod +x "${APP_NAME}"
    log_success "Download completed."
else
    log_error "Download failed."
    exit 1
fi

# --------------------------------------------------------------------------- #
# System group and permissions
# --------------------------------------------------------------------------- #
log_info "Provisioning system environment..."

if getent group CHM >/dev/null 2>&1; then
    log_info "Group 'CHM' already exists."
else
    if sudo groupadd CHM; then
        log_success "Group 'CHM' created successfully."
    else
        log_error "Failed to create group 'CHM'."
        exit 1
    fi
fi

if ! groups "${USER}" | grep -q "\bCHM\b"; then
    sudo usermod -aG CHM "${USER}" || true
    log_info "Added user '${USER}' to group 'CHM'."
fi

log_info "Configuring directory hierarchy under /etc/CHM..."

sudo install -d -o root -g CHM -m 2775 /etc/CHM
sudo install -d -o root -g CHM -m 2775 /etc/CHM/db
sudo install -d -o root -g CHM -m 2775 /etc/CHM/certs

log_success "Directory structure provisioned."

# --------------------------------------------------------------------------- #
# Install binary
# --------------------------------------------------------------------------- #
log_info "Installing binary to /usr/local/bin/${APP_NAME}..."
if sudo install -o root -g CHM -m 0755 "${APP_NAME}" "/usr/local/bin/${APP_NAME}"; then
    log_success "Binary installed successfully."
    # Cleanup downloaded file
    rm -f "${APP_NAME}"
else
    log_error "Failed to install binary."
    exit 1
fi

# --------------------------------------------------------------------------- #
# Configuration Bootstrap
# --------------------------------------------------------------------------- #
log_info "Bootstrapping configuration files..."

cd /etc/CHM

# Generate default config
log_info "Executing config generation routine (-i)..."
if ! sudo "${APP_NAME}" -i >/dev/null 2>&1; then
    log_info "Capturing stdout to configuration file..."
    sudo sh -c "${APP_NAME} -i > ${APP_NAME}_config.toml.example" || true
fi

# Standardize Filenames (Remove .example)
CONFIG_FILE="${APP_NAME}_config.toml"
EXAMPLE_FILE=$(find . -maxdepth 1 -name "*config.toml.example" | head -n 1)

if [[ -n "${EXAMPLE_FILE}" ]]; then
    sudo mv "${EXAMPLE_FILE}" "${CONFIG_FILE}"
    log_success "Configuration initialized: /etc/CHM/${CONFIG_FILE}"
elif [[ -f "${CONFIG_FILE}" ]]; then
    log_info "Existing configuration detected. Skipping generation."
else
    log_warn "Automatic configuration generation incomplete. Manual setup may be required."
fi

# Patch Configuration Paths
if [[ -f "${CONFIG_FILE}" ]]; then
    log_info "Applying production path patches..."

    sudo sed -i 's|"rootCA.pem"|"/etc/CHM/certs/rootCA.pem"|g' "${CONFIG_FILE}"
    sudo sed -i -E 's|"([a-zA-Z0-9_]+\.db)"|"/etc/CHM/db/\1"|g' "${CONFIG_FILE}"

    log_success "Configuration paths patched for production environment."
fi

# --------------------------------------------------------------------------- #
# Component-Specific Initialization
# --------------------------------------------------------------------------- #
if [[ "${APP_KEY}" == "ca" ]]; then
    ROOT_CA_PATH="/etc/CHM/certs/rootCA.pem"
    if [[ ! -f "${ROOT_CA_PATH}" ]]; then
        log_info "Initializing Root Certificate Authority..."

        cd /etc/CHM/certs

        if sudo CHMmCA --root-ca; then
            log_success "Root CA generated at: ${ROOT_CA_PATH}"
        else
            log_error "Failed to generate Root CA."
        fi
    else
        log_info "Root CA already exists. Skipping initialization."
    fi
fi

# --------------------------------------------------------------------------- #
# Service Registration (Systemd)
# --------------------------------------------------------------------------- #
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
log_info "Registering Systemd service unit: ${APP_NAME}.service"


SERVICE_USER="root"


cat <<EOF | sudo tee "${SERVICE_FILE}" > /dev/null
[Unit]
Description=CHM Ecosystem Component - ${APP_NAME}
Documentation=https://github.com/End-YYDS/CHM
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=CHM
# Critical: Sets the context for config loading
WorkingDirectory=/etc/CHM
ExecStart=/usr/local/bin/${APP_NAME}
Restart=always
RestartSec=5
# Environment defaults
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

log_success "Service unit created."
log_info "Reloading system daemon..."
sudo systemctl daemon-reload

# --------------------------------------------------------------------------- #
# Post-Installation Summary
# --------------------------------------------------------------------------- #
echo ""
echo "---------------------------------------------------------------"
echo " Installation Complete"
echo "---------------------------------------------------------------"
log_success "Component '${APP_NAME}' has been successfully deployed."
echo ""
log_info "Configuration Directory : /etc/CHM"
log_info "Database Directory      : /etc/CHM/db"
log_info "Certificate Directory   : /etc/CHM/certs"
echo ""
echo "To start the service, run:"
echo "  sudo systemctl start ${APP_NAME}"
echo ""
echo "To enable start-on-boot, run:"
echo "  sudo systemctl enable ${APP_NAME}"
echo "---------------------------------------------------------------"
