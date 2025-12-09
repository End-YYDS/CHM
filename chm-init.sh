#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# CHM Production Installer (Refactored)
#
# Description:
#   Automated deployment script for the CHM ecosystem.
#   - Fetches and installs release binaries.
#   - Initializes system groups and directory structures.
#   - Generates and patches default configurations.
#   - Provisions Systemd unit files.
#
# Usage:
#   sudo ./chm-install.sh [component_name]
###############################################################################

# =========================================================================== #
# 0. Global Variables & Logging
# =========================================================================== #

# Colors
YELLOW="\033[33m"
RED="\033[31m"
GREEN="\033[32m"
BLUE="\033[36m"
BOLD="\033[1m"
RESET="\033[0m"

# Global Config
CHM_GROUP="chm"
CHM_USER="chm-user"
INSTALL_DIR="/usr/local/bin"
APP_ROOT="/etc/CHM"

# Logging Functions
log_info()    { printf "${BLUE}[INFO]${RESET} %s\n" "$*"; }
log_warn()    { printf "${YELLOW}[WARN]${RESET} %s\n" "$*"; }
log_error()   { printf "${RED}[ERROR]${RESET} %s\n" "$*" >&2; }
log_success() { printf "${GREEN}[ OK ]${RESET} %s\n" "$*"; }

log_section() {
    echo ""
    printf "${BOLD}==============================================================${RESET}\n"
    printf "${BOLD} %s ${RESET}\n" "$*"
    printf "${BOLD}==============================================================${RESET}\n"
}

# =========================================================================== #
# 1. Component Selection & Validation
# =========================================================================== #

select_component() {
    local input_key="${1:-}"

    if [[ -z "${input_key}" ]]; then
        log_section "Component Selection"
        options=("controller" "api" "ca" "dhcp" "dns" "ldap" "agent" "frontend")

        echo "Select a component to install:"
        for idx in "${!options[@]}"; do
            printf "  ${BOLD}%d)${RESET} %s\n" $((idx + 1)) "${options[$idx]}"
        done

        while true; do
            read -r -p "> " choice
            case "$choice" in
                1|controller) input_key="controller" ;;
                2|api)        input_key="api" ;;
                3|ca)         input_key="ca" ;;
                4|dhcp)       input_key="dhcp" ;;
                5|dns)        input_key="dns" ;;
                6|ldap)       input_key="ldap" ;;
                7|agent)      input_key="agent" ;;
                8|frontend)   input_key="frontend" ;;
                *) log_warn "Invalid selection. Please try again."; continue ;;
            esac
            break
        done
    fi

    # Normalize input
    APP_KEY="$(echo "${input_key}" | tr 'A-Z' 'a-z')"
    log_info "Selected Component: ${APP_KEY}"
}

map_component_name() {
    declare -A APP_MAP=(
        [dhcp]="CHM_dhcpd"
        [api]="CHM_API"
        [ca]="CHMmCA"
        [agent]="CHM_agentd"
        [dns]="CHMmDNS"
        [cd]="CHMcd"
        [controller]="CHMcd"
        [ldap]="CHM_ldapd"
        [frontend]="frontend"
    )

    APP_NAME="${APP_MAP[${APP_KEY}]:-}"

    if [[ -z "${APP_NAME}" ]]; then
        log_error "Unknown component key: ${APP_KEY}"
        exit 1
    fi

    # Defaults
    SERVICE_USER="root"
    SERVICE_GROUP="${CHM_GROUP}"

    log_info "Mapped Binary Name: ${APP_NAME}"
}

# =========================================================================== #
# 2. System Provisioning (Groups & Dirs)
# =========================================================================== #

provision_system() {
    log_section "System Environment Provisioning"

    # 1. Create Group
    if getent group "${CHM_GROUP}" >/dev/null 2>&1; then
        log_info "Group '${CHM_GROUP}' already exists."
    else
        if sudo groupadd "${CHM_GROUP}"; then
            log_success "Group '${CHM_GROUP}' created."
        else
            log_error "Failed to create group '${CHM_GROUP}'."
            exit 1
        fi
    fi

    # 2. Create Directories
    log_info "Creating directory structure under ${APP_ROOT}..."
    sudo install -d -o root -g "${CHM_GROUP}" -m 2775 "${APP_ROOT}"
    sudo install -d -o root -g "${CHM_GROUP}" -m 2775 "${APP_ROOT}/db"
    sudo install -d -o root -g "${CHM_GROUP}" -m 2775 "${APP_ROOT}/certs"
    log_success "Directories created successfully."
}

# =========================================================================== #
# 3. Fetch & Install Binaries
# =========================================================================== #

fetch_and_install() {
    log_section "Downloading Artifacts"

    log_info "Fetching latest release tag from GitHub..."
    LATEST_TAG="$(curl -fsSL https://api.github.com/repos/End-YYDS/CHM/releases/latest \
      | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"

    if [[ -z "${LATEST_TAG}" ]]; then
      log_error "Failed to retrieve the latest release tag."
      exit 1
    fi
    log_info "Detected version: $(printf "${GREEN}%s${RESET}" "${LATEST_TAG}")"

    # Prepare download list
    download_queue=("${APP_NAME}")
    if [[ "${APP_KEY}" == "agent" ]]; then
      log_info "Agent installation detected: Adding CHM_hostd to queue."
      download_queue+=("CHM_hostd")
    fi

    # Download Loop
    for bin in "${download_queue[@]}"; do
      local asset_name="${bin}-x86_64-unknown-linux-musl"
      local url="https://github.com/End-YYDS/CHM/releases/download/${LATEST_TAG}/${asset_name}"

        log_info "Downloading: ${bin} -> ${asset_name}"
        if curl -fsSL -o "${bin}" "${url}"; then
            chmod +x "${bin}"
            log_success "Downloaded: ${bin}"
        else
            log_error "Download failed for ${bin}."
            exit 1
        fi
    done

    # Install Loop
    log_section "Installing Binaries"
    for bin in "${download_queue[@]}"; do
        log_info "Installing ${bin} to ${INSTALL_DIR}..."
        if sudo install -o root -g "${CHM_GROUP}" -m 0755 "${bin}" "${INSTALL_DIR}/${bin}"; then
            log_success "Installed: ${bin}"
            rm -f "${bin}"
        else
            log_error "Installation failed: ${bin}"
            exit 1
        fi
    done
}

# =========================================================================== #
# 4. Configuration Bootstrapping
# =========================================================================== #

bootstrap_config() {
    log_section "Configuration Bootstrap"

    cd "${APP_ROOT}"

    # Generate Config
    local bin_path="${INSTALL_DIR}/${APP_NAME}"

    log_info "Generating default configuration for ${APP_NAME}..."
    sudo "${bin_path}" -i

    # Rename .example files
    CONFIG_FILE="${APP_ROOT}/config/${APP_NAME}_config.toml"
    local files=("${APP_ROOT}"/config/*.example)

    # Check if files exist before iterating
    if [[ -e "${files[0]}" ]]; then
        for f in "${files[@]}"; do
            sudo mv -- "$f" "${f%.example}"
            log_info "Renamed config: $(basename "$f") -> $(basename "${f%.example}")"
        done
    else
        log_warn "No .example files found to rename."
    fi

    # Patch Paths
    if [[ -f "${CONFIG_FILE}" ]]; then
        log_info "Patching configuration paths in ${CONFIG_FILE}..."
        sudo sed -i 's|"rootCA.pem"|"/etc/CHM/certs/rootCA.pem"|g' "${CONFIG_FILE}"
        sudo sed -i -E 's|"([a-zA-Z0-9_]+\.db)"|"/etc/CHM/db/\1"|g' "${CONFIG_FILE}"

        log_info "Setting DNS server IP..."
        sudo sed -i "s#^dns_server *= *\"[^\"]*\"#dns_server = \"https://10.0.0.21\"#" "${CONFIG_FILE}"

        log_success "Configuration patched."
    else
        log_warn "Config file not found at ${CONFIG_FILE}. Skipping patches."
    fi

    sudo chmod 2775 -R ${APP_ROOT}
}

# =========================================================================== #
# 5. Component Specific Initialization
# =========================================================================== #

init_specific_component() {
    log_section "Component Initialization: ${APP_KEY}"

    case "${APP_KEY}" in
        ca)
            local root_ca_path="${APP_ROOT}/certs/rootCA.pem"
            if [[ ! -f "${root_ca_path}" ]]; then
                log_info "Generating Root CA..."
                cd "${APP_ROOT}/certs"
                if sudo CHMmCA --root-ca; then
                    log_success "Root CA generated."
                else
                    log_error "Failed to generate Root CA."
                fi
            else
                log_info "Root CA already exists."
            fi
            ;;
        dns)
            # 1. Ask for Username (Default: chm-user)
            read -r -p "Enter database username [default: chm-user]: " DB_USER || true
            DB_USER="${DB_USER:-chm-user}"

            # 2. Ask for Password (Default: 12345678)
            read -s -p "Enter password for the DNS service database [default: 12345678]: " NEW_PASSWORD || true
            NEW_PASSWORD="${NEW_PASSWORD:-12345678}"

            echo ""
            log_info "Updating DNS config user and password..."
            sudo sed -i "s#^username *= *\"[^\"]*\"#username = \"${DB_USER}\"#" "${CONFIG_FILE}"
            sudo sed -i "s#^password *= *\"[^\"]*\"#password = \"${NEW_PASSWORD}\"#" "${CONFIG_FILE}"
            ;;
        ldap)
            # 1. Ask for Username (Default: admin)
            read -r -p "Enter LDAP bind username [default: admin]: " LDAP_USER || true
            LDAP_USER="${LDAP_USER:-admin}"

            # 2. Ask for Password (Default: 12345678)
            read -s -p "Enter password for the LDAP service database [default: 12345678]: " NEW_PASSWORD || true
            NEW_PASSWORD="${NEW_PASSWORD:-12345678}"

            echo ""
            log_info "Updating LDAP bind password..."
            sudo sed -i "s|bind_password = \"admin\"|bind_password = \"${NEW_PASSWORD}\"|g" "${CONFIG_FILE}"

            if [[ -n "${LDAP_USER:-}" && "${LDAP_USER}" != "admin" ]]; then
                log_info "Non-default LDAP bind user or password detected. Adding -u -p flag."
                sudo CHM_ldapd -u ${LDAP_USER} -p ${NEW_PASSWORD}
            fi
            ;;
        api)
            log_info "Patching API Controller address..."
            sudo sed -i "s#^Controller *= *\"[^\"]*\"#Controller = \"https://10.0.0.10\"#" "${CONFIG_FILE}"
            ;;
    esac
}

# =========================================================================== #
# 6. Service Registration (Systemd)
# =========================================================================== #

create_systemd_service() {
    log_section "Registering Systemd Services"

    if [[ "${APP_KEY}" == "agent" ]]; then
        # --- HOST DAEMON ---
        local host_svc="/etc/systemd/system/CHM_hostd.service"
        local host_sock="/etc/systemd/system/CHM_hostd.socket"
        local agent_svc="/etc/systemd/system/CHM_agentd.service"

        log_info "Creating CHM_hostd.service..."
        cat <<EOF | sudo tee "${host_svc}" > /dev/null
[Unit]
Description=CHM Ecosystem Component - CHM_hostd
Documentation=https://github.com/End-YYDS/CHM
Requires=CHM_hostd.socket
After=CHM_hostd.socket

[Service]
Type=simple
User=root
Group=${CHM_GROUP}
WorkingDirectory=${APP_ROOT}
ExecStart=${INSTALL_DIR}/CHM_hostd
Restart=always
RestartSec=5
UMask=002

[Install]
WantedBy=multi-user.target
EOF

        log_info "Creating CHM_hostd.socket..."
        cat <<EOF | sudo tee "${host_sock}" > /dev/null
[Unit]
Description=CHM Host Daemon Socket
After=network.target

[Socket]
ListenStream=/run/chm/CHM_hostd.sock
SocketMode=0660
SocketUser=root
SocketGroup=${CHM_GROUP}
Accept=no

[Install]
WantedBy=sockets.target
EOF

        # --- AGENT DAEMON ---
        log_info "Creating CHM_agentd.service..."
        cat <<EOF | sudo tee "${agent_svc}" > /dev/null
[Unit]
Description=CHM Ecosystem Component - CHM_agentd
Documentation=https://github.com/End-YYDS/CHM
Requires=CHM_hostd.socket
After=CHM_hostd.service CHM_hostd.socket network-online.target
BindsTo=CHM_hostd.service
PartOf=CHM_hostd.service

[Service]
Type=simple
User=root
Group=${CHM_GROUP}
WorkingDirectory=${APP_ROOT}
ExecStart=${INSTALL_DIR}/CHM_agentd
Restart=on-failure
RestartSec=5
UMask=002

[Install]
WantedBy=multi-user.target
EOF

    else
        # --- STANDARD SERVICES ---
        local svc_file="/etc/systemd/system/${APP_NAME}.service"
        local exec_cmd="${INSTALL_DIR}/${APP_NAME}"

        # Controller needs 'serve' argument
        if [[ "${APP_KEY}" == "controller" ]]; then
            exec_cmd="${exec_cmd} serve"
        fi

        log_info "Creating ${APP_NAME}.service..."
        cat <<EOF | sudo tee "${svc_file}" > /dev/null
[Unit]
Description=CHM Ecosystem Component - ${APP_NAME}
Documentation=https://github.com/End-YYDS/CHM
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${APP_ROOT}
ExecStart=${exec_cmd}
Restart=always
RestartSec=5
UMask=002

[Install]
WantedBy=multi-user.target
EOF
    fi

    log_info "Reloading Systemd daemon..."
    sudo systemctl daemon-reload
    log_success "Service registration complete."
}

# =========================================================================== #
# 7. Service Startup & Verification
# =========================================================================== #

start_services() {
    # Only special handling for Agent right now to check HostD connectivity
    if [[ "${APP_KEY}" == "agent" ]]; then
        log_section "Starting Host & Agent Services"

        local host_service="CHM_hostd"
        local agent_service="CHM_agentd"

        sudo systemctl daemon-reload

        # Check HostD existenc
        if systemctl list-unit-files "${host_service}.service" &>/dev/null; then
            log_info "Starting ${host_service} service..."
            if ! sudo systemctl start "${host_service}.service"; then
                log_error "Failed to start ${host_service}"
                exit 1
            fi
        else
            log_error "${host_service}.service not found."
            exit 1
        fi

        log_info "Waiting for ${host_service} to stabilize..."
        for _ in {1..15}; do
            if sudo systemctl is-active --quiet "${host_service}"; then
                break
            fi
            sleep 1
        done

        # Check AgentD existence
        if systemctl list-unit-files "${agent_service}.service" &>/dev/null; then
            log_info "Starting ${agent_service} service..."
            if ! sudo systemctl restart "${agent_service}.service"; then
                log_error "Failed to start ${agent_service}"
                exit 1
            fi
        else
            log_error "${agent_service}.service not found."
            exit 1
        fi

        # Final Verify
        if ! sudo systemctl is-active --quiet CHM_hostd.socket; then
             log_error "Socket is not active!"
             exit 1
        fi
        if ! sudo systemctl is-active --quiet "${agent_service}"; then
             log_error "Agent service is not active!"
             exit 1
        fi

        log_success "Host and Agent services started successfully."
    fi
}

# =========================================================================== #
# 8. Permission Hardening (Post-Install)
# =========================================================================== #

apply_permissions() {
    # Host component stays root.
    # Others get dropped to chm-user.

    if [[ "${APP_KEY}" != "host" ]]; then
        log_section "Hardening Permissions"
        log_info "Configuring service user '${CHM_USER}'..."

        # 1. Create User
        if id -u "${CHM_USER}" >/dev/null 2>&1; then
            log_info "User '${CHM_USER}' already exists."
        else
            if sudo useradd --system -r -M -s /usr/sbin/nologin -g "${CHM_GROUP}" "${CHM_USER}"; then
                log_success "Created system user '${CHM_USER}'."
            else
                log_error "Failed to create user '${CHM_USER}'."
                exit 1
            fi
        fi

        # 2. Agent Specific Logic
        if [[ "${APP_KEY}" == "agent" ]]; then
            log_info "Applying specific Agent permissions..."

            # Socket File Check
            local socket_path="/run/chm/CHM_hostd.sock"
            if ! [[ -S "${socket_path}" ]]; then
                log_error "Socket file not found at ${socket_path}. Systemd might create it on next access."
                exit 1
            fi

            # Directory Ownership
            sudo chown -R root:"${CHM_GROUP}" "${APP_ROOT}"
            sudo chmod -R 2775 "${APP_ROOT}"

            # Patch Config
            if [[ -n "${CONFIG_FILE:-}" && -f "${CONFIG_FILE}" ]]; then
                sudo chown root:"${CHM_GROUP}" "${CONFIG_FILE}"

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

        # 3. Update Systemd Service
        local service_file="/etc/systemd/system/${APP_NAME}.service"
        if [[ -f "${service_file}" ]]; then
            log_info "Updating systemd service to run as ${CHM_USER}..."
            sudo sed -i -E "s/^User=.*/User=${CHM_USER}/" "${service_file}"
            sudo sed -i -E "s/^Group=.*/Group=${CHM_GROUP}/" "${service_file}"

            sudo systemctl daemon-reload

            if sudo systemctl is-active --quiet "${APP_NAME}"; then
                sudo systemctl restart "${APP_NAME}"
                log_success "Service '${APP_NAME}' restarted as user '${CHM_USER}'."
            fi
        fi
    fi
}

# =========================================================================== #
# 9. Final Docker & Environment Steps
# =========================================================================== #

setup_extras() {
    log_section "Finalizing Setup & Docker Integration"

    if [[ "${APP_KEY}" == "dns" ]]; then
        sudo mkdir -p /root/DNS
        # +sudo
        cd /root/DNS

        log_info "Downloading DNS Docker Compose..."

        sudo curl -O https://raw.githubusercontent.com/End-YYDS/CHM-Dns-Container/main/docker-compose.yml
        sudo curl -O https://raw.githubusercontent.com/End-YYDS/CHM-Dns-Container/main/.env.default
        sudo mv .env.default .env

        sudo sed -i "s#^POSTGRES_USER *= *\"[^\"]*\"#POSTGRES_USER = \"${DB_USER}\"#" .env
        sudo sed -i "s#^POSTGRES_PASSWORD *= *\"[^\"]*\"#POSTGRES_PASSWORD = \"${NEW_PASSWORD}\"#" .env

        sudo docker compose down -v || true
        sudo docker compose up -d
    elif [[ "${APP_KEY}" == "ldap" ]]; then
        sudo mkdir -p /root/LDAP
        sudo cd /root/LDAP

        log_info "Downloading LDAP Docker Compose..."

        sudo curl -O https://raw.githubusercontent.com/End-YYDS/CHM-Ldap-Container/main/docker-compose.yml
        sudo curl -O https://raw.githubusercontent.com/End-YYDS/CHM-Ldap-Container/main/.env.default
        sudo mv .env.default .env

        sudo sed -i "s#^LDAP_ORGANISATION *= *\"[^\"]*\"#LDAP_ORGANISATION = \"CHM Inc.\"#" .env
        sudo sed -i "s#^LDAP_DOMAIN *= *\"[^\"]*\"#LDAP_DOMAIN = \"chm.com\"#" .env
        sudo sed -i "s#^LDAP_BASE_DN *= *\"[^\"]*\"#LDAP_BASE_DN = \"dc=chm,dc=com\"#" .env
        sudo sed -i "s#^LDAP_ADMIN_PASSWORD *= *\"[^\"]*\"#LDAP_ADMIN_PASSWORD = \"${NEW_PASSWORD}\"#" .env
        sudo sed -i "s#^LDAP_CONFIG_PASSWORD *= *\"[^\"]*\"#LDAP_CONFIG_PASSWORD = \"${NEW_PASSWORD}\"#" .env

        # Check Dependencies
        log_info "Checking dependencies..."
        if ! command -v unzip >/dev/null 2>&1; then
            log_info "Installing 'unzip'..."
            sudo apt-get update && sudo apt-get install -y unzip
        fi

        local url="https://raw.githubusercontent.com/End-YYDS/CHM-Ldap-Container/main/bootstrap.zip"
        local asset_name="bootstrap.zip"
        local target_dir="/root/LDAP"
        log_info "Downloading: ${url}"
        if curl -fsSL -o "${asset_name}" "${url}"; then
            log_success "Downloaded: ${asset_name}"

            # Unzip
            if sudo unzip -o -q "${asset_name}" -d "${target_dir}"; then
                log_success "Extracted successfully."
            else
                log_error "Unzip failed."
                exit 1
            fi

            log_success "bootstrap.zip deployed to ${target_dir}."
            rm -f "${asset_name}"
        else
            log_error "Download failed."
            exit 1
        fi

        sudo docker compose down -v || true
        sudo rm -rf data || true
        sudo docker compose up -d --build phpldapadmin
        for i in {1..15}; do
            if sudo docker compose exec -T openldap ldapsearch -Y EXTERNAL -H ldapi:/// -s base -b "" dn >/dev/null 2>&1; then
                log_info "LDAP ready!"
                break
            fi
            log_info "Waiting for LDAP to be ready..."
            sleep 2
        done
        sleep 3

        sudo docker compose exec openldap ldapmodify -Y EXTERNAL -H ldapi:/// -f /container/service/slapd/assets/config/bootstrap/ldif/custom/3.ldif
        sudo docker compose exec openldap ldapmodify -Y EXTERNAL -H ldapi:/// -f /container/service/slapd/assets/config/bootstrap/ldif/custom/4.ldif
    fi

    # if [[ "${APP_KEY}" == "dns" || "${APP_KEY}" == "ldap" ]]; then
    #     log_info "Fetching external environment config from 192.168.1.6..."
    #     curl -O http://192.168.1.6:8080/.env || log_warn "Failed to fetch .env from 192.168.1.6 (Is the dev server up?)"

    #     if command -v docker >/dev/null 2>&1; then
    #         log_info "Starting Docker containers..."
    #         docker compose up -d || log_warn "Docker compose up failed."
    #     else
    #         log_warn "Docker not found, skipping container start."
    #     fi
    # fi

    # Final Permission Sweep
    sudo chmod -R 2775 "${APP_ROOT}"

    # Enable Services
    log_info "Enabling ${APP_NAME} service to start on boot..."

    if [[ "${APP_KEY}" == "agent" ]]; then
      sudo systemctl enable --now CHM_hostd.socket
      sudo systemctl enable --now CHM_hostd.service
      sudo systemctl enable --now CHM_agentd.service
      return
    else
      sudo systemctl enable --now "${APP_NAME}.service"
    fi
}

# =========================================================================== #
# 10. Summary
# =========================================================================== #

print_summary() {
    echo ""
    printf "${GREEN}${BOLD}---------------------------------------------------------------${RESET}\n"
    printf "${GREEN}${BOLD} Installation Complete: ${APP_NAME} ${RESET}\n"
    printf "${GREEN}${BOLD}---------------------------------------------------------------${RESET}\n"
    log_info "Configuration Directory : ${APP_ROOT}"
    log_info "Database Directory      : ${APP_ROOT}/db"
    log_info "Certificate Directory   : ${APP_ROOT}/certs"
    log_info "Configuration File      : ${CONFIG_FILE}"
    echo ""
    if [[ "${APP_KEY}" == "agent" ]]; then
      echo "To start Agent service, run:"
      echo "  sudo systemctl start CHM_hostd.service"
      echo "  sudo systemctl start CHM_agentd.service"
      echo "To stop Agent service, run:"
      echo "  sudo systemctl stop CHM_hostd.socket"
      echo "  sudo systemctl stop CHM_hostd.service"
      echo "To check Agent OTP, run:"
      echo "  sudo journalctl -fu CHM_agentd.service"
    if [[ "${APP_KEY}" == "controller" ]]; then
      echo "To initialize the controller, run:"
      echo "  sudo CHMcd init -H https://<CA_ip> -c <CA_OTP> -d <DNS_OTP>"
      echo "To add other services, run:"
      echo "  sudo CHMcd add -H https://<Service_ip> -p <Service_OTP>"
      echo "To start the service, run:"
      echo "  sudo systemctl start ${APP_NAME}.service"
      echo "To stop the service, run:"
      echo "  sudo systemctl stop ${APP_NAME}.service"
    else
      echo "To start the service, run:"
      echo "  sudo systemctl start ${APP_NAME}.service"
      echo "To stop the service, run:"
      echo "  sudo systemctl stop ${APP_NAME}.service"
      echo "To check OTP, run:"
      echo "  sudo journalctl -fu ${APP_NAME}.service"
    fi
    echo "---------------------------------------------------------------"
}

# =========================================================================== #
# Frontend Initialization
# =========================================================================== #

frontend_init() {
    log_section "Frontend Initialization"

    local base_dir="/var/www/chm-frontend"
    local target_dir="${base_dir}/dist"

    # Check Dependencies
    log_info "Checking dependencies..."
    if ! command -v unzip >/dev/null 2>&1; then
        log_info "Installing 'unzip'..."
        sudo apt-get update && sudo apt-get install -y unzip
    fi

    # Fetch Release Info
    log_info "Fetching latest Frontend release..."
    local latest_tag
    latest_tag="$(curl -fsSL https://api.github.com/repos/End-YYDS/Frontend-Web/releases/latest \
        | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"

    if [[ -z "${latest_tag}" ]]; then
        log_error "Failed to retrieve the latest frontend tag."
        exit 1
    fi
    log_info "Detected version: ${latest_tag}"

    # Download & Extract
    local asset_name="frontend-${latest_tag}.zip"
    local url="https://github.com/End-YYDS/Frontend-Web/releases/download/${latest_tag}/${asset_name}"

    log_info "Downloading: ${url}"
    if curl -fsSL -o "${asset_name}" "${url}"; then
        log_success "Downloaded: ${asset_name}"

        log_info "Deploying to ${target_dir}..."
        sudo rm -rf "${target_dir}"
        sudo mkdir -p "${target_dir}"

        # Unzip
        if sudo unzip -o -q "${asset_name}" -d "${target_dir}"; then
            log_success "Extracted successfully."
        else
            log_error "Unzip failed."
            exit 1
        fi

        log_success "Frontend deployed to ${target_dir}."
        rm -f "${asset_name}"
    else
        log_error "Download failed."
        exit 1
    fi
}

# =========================================================================== #
# Main Execution Flow
# =========================================================================== #

main() {
    # 1. Inputs
    select_component "${1:-}"

    if [[ "${APP_KEY}" == "frontend" ]]; then
        frontend_init
        exit 0
    fi

    map_component_name

    # 2. Prep
    provision_system

    # 3. Artifacts
    fetch_and_install

    # 4. Config
    bootstrap_config
    init_specific_component

    # 5. Service
    create_systemd_service
    start_services

    # 6. Secure
    apply_permissions

    # 7. Extras
    setup_extras

    # 8. Done
    print_summary
}

# Run Main
main "$@"
