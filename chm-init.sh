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
    options=("controller" "api" "ca" "dhcp" "dns" "ldap" "agent" )

    while true; do
        echo "Select a component to install (1-7):"
        for idx in "${!options[@]}"; do
            printf "  %d) %s\n" $((idx + 1)) "${options[$idx]}"
        done
        read -r -p "> " choice
        case "$choice" in
            1|controller) APP_KEY="controller" ;;
            2|api)        APP_KEY="api" ;;
            3|ca)         APP_KEY="ca" ;;
            4|dhcp)       APP_KEY="dhcp" ;;
            5|dns)        APP_KEY="dns" ;;
            6|ldap)       APP_KEY="ldap" ;;
            7|agent)      APP_KEY="agent" ;;
            *) log_warn "Invalid selection. Please try again."; continue ;;
        esac
        log_info "You selected: ${APP_KEY}"
        break
    done
fi

APP_KEY="$(echo "${APP_KEY}" | tr 'A-Z' 'a-z')"
CHM_GROUP="chm"
CHM_USER="chm-user"

# --------------------------------------------------------------------------- #
# Component Mapping
# --------------------------------------------------------------------------- #
declare -A APP_MAP=(
    [dhcp]="CHM_dhcpd"
    [api]="CHM_API"
    [ca]="CHMmCA"
    [agent]="CHM_agentd"
    [dns]="CHMmDNS"
    [cd]="CHMcd"
    [controller]="CHMcd"
    [ldap]="CHM_ldapd"
)

APP_NAME="${APP_MAP[${APP_KEY}]:-}"

if [[ -z "${APP_NAME}" ]]; then
    log_error "Unknown component name: ${APP_KEY}"
    exit 1
fi

SERVICE_USER="root"
SERVICE_GROUP="${CHM_GROUP}"

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

download_asset() {
    local bin_name="$1"
    local asset_name="${bin_name}-x86_64-unknown-linux-gnu"
    local url="https://github.com/End-YYDS/CHM/releases/download/${LATEST_TAG}/${asset_name}"
    log_info "Downloading asset: ${asset_name}"
    log_info "From: ${url}"
    if curl -fsSL -o "${bin_name}" "${url}"; then
        chmod +x "${bin_name}"
        log_success "Download completed: ${bin_name}"
    else
        log_error "Download failed: ${bin_name}"
        exit 1
    fi
}

download_queue=("${APP_NAME}")
if [[ "${APP_KEY}" == "agent" ]]; then
    download_queue+=("CHM_hostd")
fi

for bin in "${download_queue[@]}"; do
    download_asset "${bin}"
done

# --------------------------------------------------------------------------- #
# System group and permissions
# --------------------------------------------------------------------------- #
log_info "Provisioning system environment..."

if getent group "${CHM_GROUP}" >/dev/null 2>&1; then
    log_info "Group '${CHM_GROUP}' already exists."
else
    if sudo groupadd "${CHM_GROUP}"; then
        log_success "Group '${CHM_GROUP}' created successfully."
    else
        log_error "Failed to create group '${CHM_GROUP}'."
        exit 1
    fi
fi

if ! groups "${USER}" | grep -q "\b${CHM_GROUP}\b"; then
    sudo usermod -aG "${CHM_GROUP}" "${USER}" || true
    log_info "Added user '${USER}' to group '${CHM_GROUP}'."
fi

log_info "Configuring directory hierarchy under /etc/CHM..."

sudo install -d -o root -g "${CHM_GROUP}" -m 2775 /etc/CHM
sudo install -d -o root -g "${CHM_GROUP}" -m 2775 /etc/CHM/db
sudo install -d -o root -g "${CHM_GROUP}" -m 2775 /etc/CHM/certs

log_success "Directory structure provisioned."

# --------------------------------------------------------------------------- #
# Install binary
# --------------------------------------------------------------------------- #
for bin in "${download_queue[@]}"; do
    log_info "Installing binary to /usr/local/bin/${bin}..."
    if sudo install -o root -g "${CHM_GROUP}" -m 0755 "${bin}" "/usr/local/bin/${bin}"; then
        log_success "Binary installed successfully: ${bin}"
        rm -f "${bin}"
    else
        log_error "Failed to install binary: ${bin}"
        exit 1
    fi
done

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
CONFIG_FILE="/etc/CHM/config/${APP_NAME}_config.toml"
files=(/etc/CHM/config/*.example)
if ((${#files[@]})); then
  for f in "${files[@]}"; do
    sudo mv -- "$f" "${f%.example}"
  done;
  log_info "Renamed ${#files[@]} file(s)."
else
  log_warn "No *.example files found under /etc/CHM/config to rename."
fi

# Patch Configuration Paths
if [[ -f "${CONFIG_FILE}" ]]; then
    log_info "Applying production path patches..."

    sudo sed -i 's|"rootCA.pem"|"/etc/CHM/certs/rootCA.pem"|g' "${CONFIG_FILE}"
    sudo sed -i -E 's|"([a-zA-Z0-9_]+\.db)"|"/etc/CHM/db/\1"|g' "${CONFIG_FILE}"

    log_success "Configuration paths patched for production environment."
fi

# Update DNS server IP
sudo sed -i "s#^dns_server *= *\"[^\"]*\"#dns_server = \"https://10.0.0.21\"#" "${CONFIG_FILE}"

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
elif [[ "${APP_KEY}" == "dns" ]]; then
    DNS_CONFIG_PATH="/etc/CHM/config/CHMmDNS_config.toml"
    read -s -p "Enter a new password for the DNS service database: " NEW_PASSWORD
    sudo sed -i "s|password = \"\"|password = \"${NEW_PASSWORD}\"|g" "$DNS_CONFIG_PATH"
elif [[ "${APP_KEY}" == "ldap" ]]; then
    LDAP_CONFIG_PATH="/etc/CHM/config/CHM_ldapd_config.toml"
    read -s -p "Enter a new password for the LDAP service database: " NEW_PASSWORD
    sudo sed -i "s|bind_password = \"admin\"|bind_password = \"${NEW_PASSWORD}\"|g" "${LDAP_CONFIG_PATH}"
fi

# --------------------------------------------------------------------------- #
# Service Registration (Systemd)
# --------------------------------------------------------------------------- #
if [[ "${APP_KEY}" == "agent" ]]; then
    HOST_SERVICE_FILE="/etc/systemd/system/CHM_hostd.service"
    log_info "Registering Systemd service unit: CHM_hostd"
    cat <<EOF | sudo tee "${HOST_SERVICE_FILE}" > /dev/null
[Unit]
Description=CHM Ecosystem Component - CHM_hostd
Documentation=https://github.com/End-YYDS/CHM
Requires=CHM_hostd.socket
After=CHM_hostd.socket

[Service]
Type=simple
User=root
Group=${CHM_GROUP}
WorkingDirectory=/etc/CHM
ExecStart=/usr/local/bin/CHM_hostd
Restart=always
RestartSec=5
# Environment=RUST_LOG=info
UMask=002

[Install]
WantedBy=multi-user.target
EOF

    HOST_SOCKET_FILE="/etc/systemd/system/CHM_hostd.socket"
cat <<EOF | sudo tee "${HOST_SOCKET_FILE}" > /dev/null
[Unit]
Description=CHM Host Daemon Socket
After=network.target

[Socket]
ListenStream=/run/chm/CHM_hostd.sock

SocketMode=0660
SocketUser=root
SocketGroup=chm

Accept=no

[Service]
UMask=002

[Install]
WantedBy=sockets.target
EOF

    AGENT_SERVICE_FILE="/etc/systemd/system/CHM_agentd.service"
    log_info "Registering Systemd service unit: CHM_agentd"
    cat <<EOF | sudo tee "${AGENT_SERVICE_FILE}" > /dev/null
[Unit]
Description=CHM Ecosystem Component - CHM_agentd
Documentation=https://github.com/End-YYDS/CHM
Requires=CHM_hostd.socket
After=CHM_hostd.socket
BindsTo=CHM_hostd.service
PartOf=CHM_hostd.service

[Service]
Type=simple
User=root
Group=${CHM_GROUP}
WorkingDirectory=/etc/CHM
ExecStart=/usr/local/bin/CHM_agentd
Restart=on-failure
RestartSec=5
# Environment=RUST_LOG=info
UMask=002

[Install]
WantedBy=multi-user.target
EOF
elif [[ "${APP_KEY}" == "controller" ]]; then
    SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
    log_info "Registering Systemd service unit: ${APP_NAME}.service"


    cat <<EOF | sudo tee "${SERVICE_FILE}" > /dev/null
[Unit]
Description=CHM Ecosystem Component - ${APP_NAME}
Documentation=https://github.com/End-YYDS/CHM
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
# Critical: Sets the context for config loading
WorkingDirectory=/etc/CHM
ExecStart=/usr/local/bin/${APP_NAME} serve
Restart=always
RestartSec=5
# Environment defaults
# Environment=RUST_LOG=info
UMask=002

[Install]
WantedBy=multi-user.target
EOF
else
    SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
    log_info "Registering Systemd service unit: ${APP_NAME}.service"


    cat <<EOF | sudo tee "${SERVICE_FILE}" > /dev/null
[Unit]
Description=CHM Ecosystem Component - ${APP_NAME}
Documentation=https://github.com/End-YYDS/CHM
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
# Critical: Sets the context for config loading
WorkingDirectory=/etc/CHM
ExecStart=/usr/local/bin/${APP_NAME}
Restart=always
RestartSec=5
# Environment defaults
# Environment=RUST_LOG=info
UMask=002

[Install]
WantedBy=multi-user.target
EOF
fi

log_success "Service unit created."
log_info "Reloading system daemon..."
sudo systemctl daemon-reload

# --------------------------------------------------------------------------- #
# Start hostd then agentd, ensure connectivity before permission hardening
# --------------------------------------------------------------------------- #
connection_ok=false
agent_available=false
if [[ "${APP_KEY}" == "agent" ]]; then
    host_service="CHM_hostd"
    agent_service="CHM_agentd"
    # SOCKET_PATH="/tmp/agent_hostd.sock"
    sudo systemctl list-unit-files --type=service --no-legend | grep -q "^${host_service}";
    is_exists=$?

    if [[ "${is_exists}" -eq 0 ]]; then
        log_info "Starting ${host_service} service..."
        if ! sudo systemctl start "${host_service}.service"; then
            log_error "Failed to start ${host_service}"
            exit 1
        fi
    else
        log_error "${host_service}.service not found. Please install host component first."
        exit 1
    fi

    for _ in {1..15}; do
        if sudo systemctl is-active --quiet "${host_service}"; then
            break
        fi
        sleep 1
    done

    #TODO: 改service unit
    # if [[ -f "${CONFIG_FILE}" ]]; then
    #     detected_path=$(sudo awk -F'=' '/^SocketPath[[:space:]]*=/{gsub(/"/,"",$2); gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2; exit}' "${CONFIG_FILE}")
    #     if [[ -n "${detected_path}" ]]; then
    #         SOCKET_PATH="${detected_path}"
    #     fi
    # fi
    # if [[ -S "${SOCKET_PATH}" ]]; then
    #     sudo chown root:"${CHM_GROUP}" "${SOCKET_PATH}" || log_warn "Failed to adjust socket owner: ${SOCKET_PATH}"
    #     sudo chmod 770 "${SOCKET_PATH}" || log_warn "Failed to adjust socket permissions: ${SOCKET_PATH}"
    #     log_info "Socket ${SOCKET_PATH} permissions set to root:${CHM_GROUP} (770)"
    # else
    #     log_warn "Can't find socket ${SOCKET_PATH}, unable to set permissions (HostD may not have created it yet?)"
    # fi

    sudo systemctl list-unit-files --type=service --no-legend | grep -q "^${agent_service}";
    is_exists=$?
    if [[ "${is_exists}" -eq 0 ]]; then
        log_info "Starting ${agent_service} service..."
        if ! sudo systemctl restart "${agent_service}.service"; then
            log_error "Failed to start ${agent_service}"
            exit 1
        fi
    else
        if [[ "${APP_KEY}" == "agent" ]]; then
            log_error "${agent_service} not found. Please install agent component first."
            exit 1
        else
            log_warn "${agent_service} not found; skipping agent start."
        fi
    fi

    sudo systemctl is-active --quiet CHM_hostd.socket
    if [[ $? -ne 0 ]]; then
        log_error "CHM_hostd.socket is not active after hostd start attempt."
        exit 1
    fi
    sudo systemctl is-active --quiet "${agent_service}"
    if [[ $? -ne 0 ]]; then
        log_error "${agent_service} is not active after start attempt."
        exit 1
    fi


        # log_info "Waiting for AgentD to confirm HostD connectivity..."
        # for _ in {1..30}; do
        # if sudo journalctl -u "${agent_service}" -n 50 --no-pager 2>/dev/null | grep -q "HostD health check passed"; then
        #         connection_ok=true
        #         break
        #     fi
        #     sleep 1
        # done
fi

# --------------------------------------------------------------------------- #
# Permission reset & privilege drop (Agent only; runs after sudo-required steps)
# --------------------------------------------------------------------------- #
if [[ "${APP_KEY}" != "host" ]]; then
    if [[ "${APP_KEY}" == "agent" ]]; then
        log_warn "AgentD did not confirm successful connection to HostD; maintaining root execution."
    else
        log_info "Finalizing permissions and non-root execution..."

        if id -u "${CHM_USER}" >/dev/null 2>&1; then
            log_info "User '${CHM_USER}' already exists."
        else
            if sudo useradd --system -r -M -s /usr/sbin/nologin -g "${CHM_GROUP}" "${CHM_USER}"; then
                log_success "User '${CHM_USER}' created with primary group '${CHM_GROUP}'."
            else
                log_error "Failed to create user '${CHM_USER}'."
                exit 1
            fi
        fi

        if [[ "${APP_KEY}" == "agent" ]]; then
            sudo chown root:"${CHM_GROUP}" /etc/CHM /etc/CHM/db /etc/CHM/certs
            sudo chmod 2775 /etc/CHM /etc/CHM/db /etc/CHM/certs

            if [[ -n "${CONFIG_FILE:-}" && -f "${CONFIG_FILE}" ]]; then
                sudo chown root:"${CHM_GROUP}" "${CONFIG_FILE}"
                # sudo chmod 660 "${CONFIG_FILE}"

                if sudo grep -q '^RunAsUser' "${CONFIG_FILE}"; then
                    sudo sed -i -E "s/^RunAsUser\\s*=\\s*\"[^\"]*\"/RunAsUser = \"${CHM_USER}\"/" "${CONFIG_FILE}"
                else
                    echo "RunAsUser = \"${CHM_USER}\"" | sudo tee -a "${CONFIG_FILE}" > /dev/null
                fi

                if sudo grep -q '^RunAsGroup' "${CONFIG_FILE}"; then
                    sudo sed -i -E "s/^RunAsGroup\\s*=\\s*\"[^\"]*\"/RunAsGroup = \"${CHM_GROUP}\"/" "${CONFIG_FILE}"
                else
                    echo "RunAsGroup = \"${CHM_GROUP}\"" | sudo tee -a "${CONFIG_FILE}" > /dev/null
                fi
            fi
        fi

        service_file="/etc/systemd/system/${APP_NAME}.service"
        if [[ -f "${service_file}" ]]; then
            sudo sed -i -E "s/^User=.*/User=${CHM_USER}/" "${service_file}"
            sudo sed -i -E "s/^Group=.*/Group=${CHM_GROUP}/" "${service_file}"
        fi

        sudo systemctl daemon-reload

        if sudo systemctl is-active --quiet "${APP_NAME}"; then
            sudo systemctl restart "${APP_NAME}"
        fi

        log_success "Service '${APP_NAME}' will run as '${CHM_USER}:${CHM_GROUP}' (HostD remains root)."
    fi
fi

# --------------------------------------------------------------------------- #
# Final Edits
# --------------------------------------------------------------------------- #

if [[ "${APP_KEY}" == "dns" ]]; then
  cd $HOME
  curl -O https://raw.githubusercontent.com/End-YYDS/CHM-Dns-Container/main/docker-compose.yml
#   curl -O https://raw.githubusercontent.com/End-YYDS/CHM-Dns-Container/main/.env.default
#   mv .env.default .env
#   sudo sed -i "s#^POSTGRES_PASSWORD *= *\"[^\"]*\"#POSTGRES_PASSWORD = \"${NEW_PASSWORD}\"#" .env
#   docker compose up -d
elif [[ "${APP_KEY}" == "ldap" ]]; then
  cd $HOME
  curl -O https://raw.githubusercontent.com/End-YYDS/CHM-Ldap-Container/main/docker-compose.yml
#   curl -O https://raw.githubusercontent.com/End-YYDS/CHM-Ldap-Container/main/.env.default
#   mv .env.default .env
#   sudo sed -i "s#^LDAP_ORGANISATION *= *\"[^\"]*\"#LDAP_ORGANISATION = \"CHM Inc.\"#" .env
#   sudo sed -i "s#^LDAP_DOMAIN *= *\"[^\"]*\"#LDAP_DOMAIN = \"chm.com\"#" .env
#   sudo sed -i "s#^LDAP_BASE_DN *= *\"[^\"]*\"#LDAP_BASE_DN = \"dc=chm,dc=com\"#" .env
#   sudo sed -i "s#^LDAP_ADMIN_PASSWORD *= *\"[^\"]*\"#LDAP_ADMIN_PASSWORD = \"${NEW_PASSWORD}\"#" .env
#   sudo sed -i "s#^LDAP_CONFIG_PASSWORD *= *\"[^\"]*\"#LDAP_CONFIG_PASSWORD = \"${NEW_PASSWORD}\"#" .env
#   docker compose up -d
fi

if [[ "${APP_KEY}" == "dns" || "${APP_KEY}" == "ldap" ]]; then
    curl -O http://192.168.1.6:8080/.env
    docker compose up -d
fi

if [[ "${APP_KEY}" == "api" ]]; then
    sudo sed -i "s#^Controller *= *\"[^\"]*\"#Controller = \"https://10.0.0.10\"#" ${CONFIG_FILE}
fi

sudo chmod -R 2775 /etc/CHM

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
log_info "Configuration File      : ${CONFIG_FILE}"
echo ""
echo "To start the service, run:"
echo "  sudo systemctl start ${APP_NAME}"
echo "To check OTP, run:"
echo "  sudo journalctl -fu ${APP_NAME}"
echo "---------------------------------------------------------------"
