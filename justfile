set shell := ["bash", "-cu"]
set dotenv-load := true

SED := `if command -v gsed &> /dev/null; then echo gsed; else echo sed; fi`
CONTAINER := `if command -v podman &> /dev/null; then echo podman; elif command -v docker &> /dev/null; then echo docker; else echo "ERROR: neither podman nor docker found" >&2; exit 1;fi`
CA_DATABASE_URL := env_var('CA_DATABASE_URL')
DNS_DATABASE_URL := env_var('DNS_DATABASE_URL')
LDAP_DATABASE_URL := env_var('LDAP_DATABASE_URL')
DHCP_DATABASE_URL := env_var('DHCP_DATABASE_URL')
CA_FOLDER := "apps/ca"
DNS_FOLDER := "apps/dns"
LDAP_FOLDER := "apps/ldap"
DHCP_FOLDER := "apps/dhcp"
CA_FOLDER_MIGRATE := "apps/ca/migrations"
LDAP_FOLDER_MIGRATE := "apps/ldap/migrations"
DNS_FOLDER_MIGRATE := "apps/dns/migrations"
DHCP_FOLDER_MIGRATE := "apps/dhcp/migrations"
CONFIG_FOLDER := "config"
DATA_FOLDER := "data"
DB_FOLDER := "db"
CERT_FOLDER := "certs"

default:
    @just --list

reset-db db_url src="./migrations":
    @[ -n "{{ db_url }}" ] || { echo "ERROR: db_url is empty"; exit 1; }
    @[ -d "{{ src }}" ]    || { echo "ERROR: source '{{ src }}' not found"; exit 1; }
    @sqlx migrate revert --source "{{ src }}" -D "{{ db_url }}" || true
    @sqlx migrate run    --source "{{ src }}" -D "{{ db_url }}" || true

migrate db_url src="./migrations":
    @[ -n "{{ db_url }}" ] || { echo "ERROR: db_url is empty"; exit 1; }
    @[ -d "{{ src }}" ]    || { echo "ERROR: source '{{ src }}' not found"; exit 1; }
    @[ -n "{{ db_url }}" ] || { echo "ERROR: db_url is empty"; exit 1; }
    @[ -d "{{ src }}" ]    || { echo "ERROR: source '{{ src }}' not found"; exit 1; }
    @sqlx migrate run --source "{{ src }}" -D "{{ db_url }}" || true

create-ca-db:
    @sqlx database create -D "{{ CA_DATABASE_URL }}"

create-ldap-db:
    @sqlx database create -D "{{ LDAP_DATABASE_URL }}"

create-dhcp-db:
    @sqlx database create -D "{{ DHCP_DATABASE_URL }}"

create-ca-root:
    @cargo run -p ca --bin CHMmCA -- --root-ca

reset-ca: (reset-db CA_DATABASE_URL CA_FOLDER_MIGRATE)

reset-dns: (reset-db DNS_DATABASE_URL DNS_FOLDER_MIGRATE)

reset-ldap: (reset-db LDAP_DATABASE_URL LDAP_FOLDER_MIGRATE)

reset-dhcp: (reset-db DHCP_DATABASE_URL DHCP_FOLDER_MIGRATE)

reset-all: reset-ca reset-dns reset-ldap reset-dhcp

migrate-ca: (migrate CA_DATABASE_URL CA_FOLDER_MIGRATE)

migrate-dns: (migrate DNS_DATABASE_URL DNS_FOLDER_MIGRATE)

migrate-ldap: (migrate LDAP_DATABASE_URL LDAP_FOLDER_MIGRATE)

migrate-dhcp: (migrate DHCP_DATABASE_URL DHCP_FOLDER_MIGRATE)

migrate-all: migrate-ca migrate-dns migrate-ldap reset-dhcp

replace old new file:
    @{{ SED }} -i 's/{{ old }}/{{ new }}/g' {{ file }}

rename old new:
    @if [ -f {{ old }} ]; then \
        mv {{ old }} {{ new }}; \
        echo "Renamed {{ old }} -> {{ new }}"; \
    else \
        echo "File {{ old }} not found!"; \
        exit 1; \
    fi

remove-examples:
    @set -euo pipefail; \
    shopt -s nullglob; \
    files=({{ CONFIG_FOLDER }}/*.example); \
    if ((${#files[@]})); then \
      for f in "${files[@]}"; do \
        mv -- "$f" "${f%.example}"; \
      done; \
      echo "Renamed ${#files[@]} file(s)."; \
    else \
      echo "No *.example files found under {{ CONFIG_FOLDER }}"; \
    fi

# 開發環境
run-ca args="":
    @[[ ! -f "{{ DB_FOLDER }}/cert_store.db" ]] && just create-ca-db || true
    @[[ ! -f "{{ CERT_FOLDER }}/rootCA.pem" ]] && just create-ca-root || true
    @DATABASE_URL={{ CA_DATABASE_URL }} RUST_LOG=info,ca=debug,CHMmCA=debug  cargo run -p ca --bin CHMmCA -- {{ args }}

run-dns args="":
    @{{CONTAINER}} start CHM-DNS || true
    @DATABASE_URL={{ DNS_DATABASE_URL }} RUST_LOG=info,dns=debug,CHMmDNS=debug cargo run -p dns --bin CHMmDNS -- {{ args }}

run-controller args="":
    @RUST_LOG=info,controller=debug,CHMcd=debug,chm_dns_resolver=info,chm_cluster_utils=debug cargo run -p controller --bin CHMcd -- {{ args }}

run-api args="":
    @RUST_LOG=info,CHM_API=info,api_server=debug,chm_cluster_utils=debug cargo run -p api_server --bin CHM_API -- {{ args }}

run-agentd args="":
    @RUST_LOG=info,agent=info,CHM_agentd=debug cargo run -p agent --bin CHM_agentd -- {{ args }}

run-hostd args="":
    @RUST_LOG=info,agent=debug,CHM_hostd=debug cargo run -p agent --bin CHM_hostd -- {{ args }}

run-ldap args="":
    @[[ ! -f "{{ DB_FOLDER }}/ids.db" ]] && just create-ldap-db || true
    @DATABASE_URL={{ LDAP_DATABASE_URL }} RUST_LOG=info,ldap=debug,CHM_ldapd=debug cargo run -p ldap --bin CHM_ldapd -- {{ args }}

run-dhcp args="":
    @[[ ! -f "{{ DB_FOLDER }}/dhcp.db" ]] && just create-dhcp-db || true
    @DATABASE_URL={{ DHCP_DATABASE_URL }} RUST_LOG=info,dhcp=debug,CHM_dhcpd=debug cargo run -p dhcp --bin CHM_dhcpd -- {{ args }}

run-api-client args="":
    @RUST_LOG=CHM_API=debug,api_server=debug,chm_cluster_utils=debug cargo run -p api_server --bin client -- {{ args }}

run-init password="":
    @just run-dns '-i'
    @just run-ca '-i'
    @just run-api '-i'
    @just run-ldap '-i'
    @just run-dhcp '-i'
    @just run-controller '-i'
    @just run-agentd '-i'
    @just remove-examples
    @files=({{ CONFIG_FOLDER }}/{CHM_API,CHM_dhcpd,CHM_ldapd,CHMcd,CHMmDNS,CHM_agentd}_config.toml); \
    for i in $(seq 0 $(( ${#files[@]} - 1 )) ); do \
        echo "Processing file: ${files[$i]}"; \
        just replace 'rootCA.pem' "rootCA'$((i+1))'.pem" "${files[$i]}"; \
    done
    @just replace "30s" "1h" "{{ CONFIG_FOLDER }}/CHMmCA_config.toml"
    @just replace "30s" "1h" "{{ CONFIG_FOLDER }}/CHMmDNS_config.toml"
    @just replace 'bind_password = "admin"' 'bind_password = "{{ password }}"' "{{ CONFIG_FOLDER }}/CHM_ldapd_config.toml"
    @just replace "389" "6389" "{{ CONFIG_FOLDER }}/CHM_ldapd_config.toml"
    @just replace 'RunAsUser = "chm"' 'RunAsUser = "$USER"' "{{ CONFIG_FOLDER }}/CHM_agentd_config.toml"

# -------------------------------------------------------------
#  啟動整個 CHM cluster
# -------------------------------------------------------------
start-cluster:
    #!/usr/bin/env bash
    set -euo pipefail

    LOG_DIR="/tmp/chm_logs"
    OTP_DIR="/tmp/chm_otps"
    PID_DIR="/tmp/chm_pids"

    rm -rf "$LOG_DIR" "$OTP_DIR" "$PID_DIR" 2>/dev/null || true
    mkdir -p "$LOG_DIR" "$OTP_DIR" "$PID_DIR"

    declare -a services=("ca" "dns" "ldap" "dhcp" "api")
    declare -a commands=("run-ca" "run-dns" "run-ldap" "run-dhcp" "run-api")

    echo "[*] 啟動 CHM services..."

    start_service() {
        local name="$1"
        local cmd="$2"
        local log="$LOG_DIR/$name.log"
        local otp_path="$OTP_DIR/$name.otp"
        local port_path="$OTP_DIR/$name.port"
        local pid_path="$PID_DIR/$name.pid"

        echo "[*] 啟動 $name ..."
        just "$cmd" >"$log" 2>&1 &
        local pid=$!
        echo "$pid" > "$pid_path"
        echo "[*] $name PID = $pid"

        # watcher
        {
            tail -n0 -F "$log" 2>/dev/null &
            local tail_pid=$!

            while IFS= read -r line < <(tail -n0 -F "$log" 2>/dev/null); do
                if [[ $line =~ Using[[:space:]]OTP:\ ([a-zA-Z0-9]+) ]]; then
                    echo "${BASH_REMATCH[1]}" > "$otp_path"
                    echo "[+] $name OTP: ${BASH_REMATCH[1]}"
                fi

                if [[ $line =~ listening\ on:\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+) ]]; then
                    echo "${BASH_REMATCH[1]}" > "$port_path"
                    echo "[+] $name listening on: ${BASH_REMATCH[1]}"
                fi

                # ★ Exit condition ★
                if [[ -s "$otp_path" && -s "$port_path" ]]; then
                    kill "$tail_pid" 2>/dev/null || true
                    break
                fi
            done
        } &
    }

    need_port() {
        case "$1" in
            ca|dns|ldap|dhcp|api) return 0 ;;
            *)             return 1 ;;
        esac
    }

    for i in "${!services[@]}"; do
        start_service "${services[$i]}" "${commands[$i]}"
    done

    echo "[*] 等待所有服務 OTP / Port..."

    for s in "${services[@]}"; do
        while [[ ! -s "$OTP_DIR/$s.otp" ]]; do sleep 0.1; done
    done

    for s in "${services[@]}"; do
        if need_port "$s"; then
            while [[ ! -s "$OTP_DIR/$s.port" ]]; do sleep 0.1; done
        fi
    done

    # 讀取所有 OTP / Port
    CA_OTP=$(<"$OTP_DIR/ca.otp")
    DNS_OTP=$(<"$OTP_DIR/dns.otp")
    LDAP_OTP=$(<"$OTP_DIR/ldap.otp")
    DHCP_OTP=$(<"$OTP_DIR/dhcp.otp")
    API_OTP=$(<"$OTP_DIR/api.otp")

    LDAP_PORT=$(<"$OTP_DIR/ldap.port")
    DHCP_PORT=$(<"$OTP_DIR/dhcp.port")
    API_PORT=$(<"$OTP_DIR/api.port")
    CA_PORT=$(<"$OTP_DIR/ca.port")
    DNS_PORT=$(<"$OTP_DIR/dns.port")

    echo "---- OTPs ----"
    echo "CA   = $CA_OTP"
    echo "DNS  = $DNS_OTP"
    echo "LDAP = $LDAP_OTP"
    echo "DHCP = $DHCP_OTP"
    echo "API  = $API_OTP"
    echo
    echo "---- Ports ----"
    echo "LDAP = $LDAP_PORT"
    echo "DHCP = $DHCP_PORT"
    echo "API  = $API_PORT"
    echo

    # Controller 初始化
    INIT_CMD="init -H https://$CA_PORT -c $CA_OTP -d $DNS_OTP"
    echo "[*] Controller 初始化：$INIT_CMD"
    just run-controller "$INIT_CMD"

    echo "[*] 加入 API 節點 ..."
    just run-controller "add -H https://$API_PORT -p $API_OTP"

    # Controller add nodes
    echo "[*] 加入 LDAP 節點 ..."
    just run-controller "add -H https://$LDAP_PORT -p $LDAP_OTP"

    echo "[*] 加入 DHCP 節點 ..."
    just run-controller "add -H https://$DHCP_PORT -p $DHCP_OTP"

    echo "[*] 全部節點加入完成"

    # -------------------------------------------------------------
    # 🆕 最後：啟動 controller serve
    # -------------------------------------------------------------
    echo "[*] 啟動 Controller serve ..."
    just run-controller 'serve' > "$LOG_DIR/controller_serve.log" 2>&1 &
    CONTROLLER_SERVE_PID=$!
    echo "$CONTROLLER_SERVE_PID" > "$PID_DIR/controller_serve.pid"
    echo "[+] Controller serve PID = $CONTROLLER_SERVE_PID"
    echo "[✔] CHM cluster 完整啟動完成！"

# -------------------------------------------------------------
# 停止整個 cluster：stop-cluster
# -------------------------------------------------------------
stop-cluster:
    #!/usr/bin/env bash
    set -euo pipefail

    PID_DIR="/tmp/chm_pids"

    if [[ ! -d "$PID_DIR" ]]; then
        echo "[!] 沒找到 PID 目錄，可能 cluster 尚未啟動"
        exit 1
    fi

    echo "[*] 停止 CHM services + controller serve..."

    shopt -s nullglob
    for pid_file in "$PID_DIR"/*.pid; do
        svc=$(basename "$pid_file" .pid)
        pid=$(<"$pid_file")

        if kill -0 "$pid" 2>/dev/null; then
            echo "[*] 停止 $svc (PID $pid)"
            kill "$pid" 2>/dev/null || true
        else
            echo "[-] $svc 已不在執行中"
        fi
    done
    shopt -u nullglob

    echo "[✔] CHM cluster 已完全停止"

cluster-status:
    #!/usr/bin/env bash
    set -euo pipefail

    PID_DIR="/tmp/chm_pids"

    if [[ ! -d "$PID_DIR" ]]; then
        echo "[!] 沒有找到 PID 目錄 ($PID_DIR)，可能 cluster 尚未啟動"
        exit 1
    fi

    shopt -s nullglob
    pid_files=("$PID_DIR"/*.pid)

    if (( ${#pid_files[@]} == 0 )); then
        echo "[!] 沒有任何 PID 記錄檔"
        exit 0
    fi

    printf "%-20s %-10s %s\n" "SERVICE" "STATUS" "PID"
    printf "%-20s %-10s %s\n" "-------" "------" "---"

    for pid_file in "${pid_files[@]}"; do
        svc="$(basename "$pid_file" .pid)"
        pid="$(<"$pid_file")"

        if kill -0 "$pid" 2>/dev/null; then
            status="RUNNING"
        else
            status="DEAD"
        fi

        printf "%-20s %-10s %s\n" "$svc" "$status" "$pid"
    done

    shopt -u nullglob

logs service:
    #!/usr/bin/env bash
    set -euo pipefail

    LOG_DIR="/tmp/chm_logs"
    svc="{{service}}"

    case "$svc" in
        ca|dns|ldap|dhcp|api|controller)
            ;;
        *)
            echo "[!] 未知的 service: $svc"
            echo "    可用：ca dns ldap dhcp api controller_serve"
            exit 1
            ;;
    esac

    log_file="$LOG_DIR/$svc.log"

    if [[ ! -f "$log_file" ]]; then
        echo "[!] 找不到 log 檔案：$log_file"
        exit 1
    fi

    echo "[*] 顯示 $svc 的 log：$log_file"
    echo "[*] (Ctrl-C 結束 tail)"
    tail -n 50 -f "$log_file"

clean-logs:
    @rm -rf /tmp/chm_logs /tmp/chm_otps /tmp/chm_pids 2>/dev/null || true
    @echo "Cleaned /tmp/chm_logs, /tmp/chm_otps, /tmp/chm_pids"

clean-certs:
    @find {{ CERT_FOLDER }} -mindepth 1 -not -name ".gitkeep" -print0 | xargs -0 rm -rf

clean-data:
    @find {{ DATA_FOLDER }} -mindepth 1 -not -name ".gitkeep" -print0 | xargs -0 rm -rf

clean-db:
    @find {{ DB_FOLDER }} -mindepth 1 -not -name ".gitkeep" -print0 | xargs -0 rm -rf

clean-config:
    @find {{ CONFIG_FOLDER }} -mindepth 1 -not -name ".gitkeep" -print0 | xargs -0 rm -rf

clean-all: clean
    @cargo clean

clean: reset-all clean-certs clean-config clean-data clean-db

# Todo: 添加release執行
run-r-ca args="":
    @[[ ! -f "{{ DB_FOLDER }}/cert_store.db" ]] && just create-ca-db || true
    @[[ ! -f "{{ CERT_FOLDER }}/rootCA.pem" ]] && just create-ca-root || true
    @DATABASE_URL={{ CA_DATABASE_URL }} RUST_LOG=ca=info,CHM_CA=info  cargo run -p ca --bin CHM_CA -r -- {{ args }}

run-r-dns args="":
    @{{CONTAINER}} start CHM-DNS || true
    @DATABASE_URL={{ DNS_DATABASE_URL }} RUST_LOG=dns=info,CHM_mDNSd=info cargo run -p dns --bin CHM_mDNSd -r -- {{ args }}

run-r-controller args="":
    @RUST_LOG=trace,controller=info,CHMcd=info,chm_dns_resolver=info cargo run -p controller --bin CHMcd -r -- {{ args }}

run-r-api args="":
    @RUST_LOG=CHM_API=info cargo run -p api_server --bin CHM_API -r -- {{ args }}

run-r-ldap args="":
    @[[ ! -f "{{ DB_FOLDER }}/ids.db" ]] && just create-ldap-db || true
    @DATABASE_URL={{ LDAP_DATABASE_URL }} RUST_LOG=trace,ldap=info,CHM_ldapd=info cargo run -p ldap --bin CHM_ldapd -r -- {{ args }}

run-r-dhcp args="":
    @[[ ! -f "{{ DB_FOLDER }}/dhcp.db" ]] && just create-dhcp-db || true
    @DATABASE_URL={{ DHCP_DATABASE_URL }} RUST_LOG=dhcp=info,CHM_dhcpd=info cargo run -p dhcp --bin CHM_dhcpd -r -- {{ args }}

run-r-agentd args="":
    @RUST_LOG=agent=info,CHM_agentd=info cargo run -p agent --bin CHM_agentd -r -- {{ args }}

run-r-hostd args="":
    @RUST_LOG=agent=info,CHM_hostd=info cargo run -p agent --bin CHM_hostd -r -- {{ args }}

# Todo: 添加release編譯
sqlx-prepare:
    @[[ ! -f "{{ DB_FOLDER }}/cert_store.db" ]] && just create-ca-db || true
    @[[ ! -f "{{ DB_FOLDER }}/ids.db" ]] && just create-ldap-db || true
    @[[ ! -f "{{ DB_FOLDER }}/dhcp.db" ]] && just create-dhcp-db || true
    @just reset-all || true
    @(cd {{ CA_FOLDER }} && cargo sqlx prepare  -D "{{ CA_DATABASE_URL }}")
    @(cd {{ DNS_FOLDER }} && cargo sqlx prepare -D "{{ DNS_DATABASE_URL }}")
    @(cd {{ LDAP_FOLDER }} && cargo sqlx prepare -D "{{ LDAP_DATABASE_URL }}")
    @(cd {{ DHCP_FOLDER }} && cargo sqlx prepare -D "{{ DHCP_DATABASE_URL }}")

sqlx-prepare-only:
    @(cd {{ CA_FOLDER }} && cargo sqlx prepare  -D "{{ CA_DATABASE_URL }}")
    @(cd {{ DNS_FOLDER }} && cargo sqlx prepare -D "{{ DNS_DATABASE_URL }}")
    @(cd {{ LDAP_FOLDER }} && cargo sqlx prepare -D "{{ LDAP_DATABASE_URL }}")
    @(cd {{ DHCP_FOLDER }} && cargo sqlx prepare -D "{{ DHCP_DATABASE_URL }}")

build-release:
    @[[ ! -f "{{ DB_FOLDER }}/cert_store.db" ]] && just create-ca-db || true
    @[[ ! -f "{{ DB_FOLDER }}/ids.db" ]] && just create-ldap-db || true
    @[[ ! -f "{{ DB_FOLDER }}/dhcp.db" ]] && just create-dhcp-db || true
    @SQLX_OFFLINE=true cargo build --workspace --release

build-release-musl:
    @[[ ! -f "{{ DB_FOLDER }}/cert_store.db" ]] && just create-ca-db || true
    @[[ ! -f "{{ DB_FOLDER }}/ids.db" ]] && just create-ldap-db || true
    @[[ ! -f "{{ DB_FOLDER }}/dhcp.db" ]] && just create-dhcp-db || true
    @SQLX_OFFLINE=true cargo build --workspace --release --target x86_64-unknown-linux-musl

release-all:
    @just sqlx-prepare
    @just build-release
