set shell := ["bash", "-cu"]
set dotenv-load := true

SED := "gsed"
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
    @cargo run -p ca --bin CHM_CA -- --create-ca

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
    @DATABASE_URL={{ CA_DATABASE_URL }} RUST_LOG=ca=debug,CHM_CA=debug  cargo run -p ca --bin CHM_CA -- {{ args }}

run-dns args="":
    @podman start CHM-DNS || true
    @DATABASE_URL={{ DNS_DATABASE_URL }} RUST_LOG=dns=debug,CHM_mDNSd=debug cargo run -p dns --bin CHM_mDNSd -- {{ args }}

run-controller args="":
    @RUST_LOG=trace,controller=debug,CHMcd=debug cargo run -p controller --bin CHMcd -- {{ args }}

run-api args="":
    @RUST_LOG=CHM_API=debug,api_server=debug,chm_cluster_utils=debug cargo run -p api_server --bin CHM_API -- {{ args }}

run-agentd args="":
    @RUST_LOG=agent=debug,CHM_agentd=debug cargo run -p agent --bin CHM_agentd -- {{ args }}

run-hostd args="":
    @RUST_LOG=agent=debug,CHM_hostd=debug cargo run -p agent --bin CHM_hostd -- {{ args }}

run-ldap args="":
    @[[ ! -f "{{ DB_FOLDER }}/ids.db" ]] && just create-ldap-db || true
    @DATABASE_URL={{ LDAP_DATABASE_URL }} RUST_LOG=trace,ldap=debug,CHM_ldapd=debug cargo run -p ldap --bin CHM_ldapd -- {{ args }}

run-dhcp args="":
    @[[ ! -f "{{ DB_FOLDER }}/dhcp.db" ]] && just create-dhcp-db || true
    @DATABASE_URL={{ DHCP_DATABASE_URL }} RUST_LOG=dhcp=debug,CHM_dhcpd=debug cargo run -p dhcp --bin CHM_dhcpd -- {{ args }}

run-api-client args="":
    @RUST_LOG=CHM_API=debug,api_server=debug,chm_cluster_utils=debug cargo run -p api_server --bin client -- {{ args }}

run-init password="":
    @just run-dns '-i'
    @just run-ca '-i'
    @just run-api '-i'
    @just run-ldap '-i'
    @just run-dhcp '-i'
    @just run-controller '-i'
    @just remove-examples
    @files=({{ CONFIG_FOLDER }}/{CHM_API,CHM_dhcpd,CHM_ldapd,CHMcd,CHMmDNS}_config.toml); \
    for i in $(seq 0 $(( ${#files[@]} - 1 )) ); do \
        echo "Processing file: ${files[$i]}"; \
        just replace 'rootCA.pem' "rootCA'$((i+1))'.pem" "${files[$i]}"; \
    done
    @just replace "30s" "1h" "{{ CONFIG_FOLDER }}/CHMmCA_config.toml"
    @just replace "30s" "1h" "{{ CONFIG_FOLDER }}/CHMmDNS_config.toml"
    @just replace 'bind_password = "admin"' 'bind_password = "{{ password }}"' "{{ CONFIG_FOLDER }}/CHM_ldapd_config.toml"

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
    @podman start CHM-DNS || true
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

release-all:
    @just sqlx-prepare
    @just build-release
