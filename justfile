set shell := ["bash", "-cu"]
set dotenv-load := true

CA_DATABASE_URL := env_var('CA_DATABASE_URL')
DNS_DATABASE_URL := env_var('DNS_DATABASE_URL')
CA_FOLDER_MIGRATE := "apps/ca/migrations"
CA_FOLDER := "apps/ca"
DNS_FOLDER := "apps/dns"
DNS_FOLDER_MIGRATE := "apps/dns/migrations"
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

create-ca-root:
    @cargo run -p ca --bin CHM_CA -- --create-ca

reset-ca: (reset-db CA_DATABASE_URL CA_FOLDER_MIGRATE)

reset-dns: (reset-db DNS_DATABASE_URL DNS_FOLDER_MIGRATE)

reset-all: reset-ca reset-dns

migrate-ca: (migrate CA_DATABASE_URL CA_FOLDER_MIGRATE)

migrate-dns: (migrate DNS_DATABASE_URL DNS_FOLDER_MIGRATE)

migrate-all: migrate-ca migrate-dns

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

run-api-client args="":
    @RUST_LOG=CHM_API=debug,api_server=debug,chm_cluster_utils=debug cargo run -p api_server --bin client -- {{ args }}

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

# Todo: 添加release編譯
sqlx-prepare:
    @[[ ! -f "{{ DB_FOLDER }}/cert_store.db" ]] && just create-ca-db || true
    @just reset-all
    @(cd {{ CA_FOLDER }} && cargo sqlx prepare  -D "{{ CA_DATABASE_URL }}")
    @(cd {{ DNS_FOLDER }} && cargo sqlx prepare -D "{{ DNS_DATABASE_URL }}")

build-release:
    @[[ ! -f "{{ DB_FOLDER }}/cert_store.db" ]] && just create-ca-db || true
    @SQLX_OFFLINE=true cargo build --workspace --release

release-all:
    @just sqlx-prepare
    @just build-release
