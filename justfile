set shell := ["bash", "-cu"]
set dotenv-load := true

CA_DATABASE_URL := env_var('CA_DATABASE_URL')
DNS_DATABASE_URL := env_var('DNS_DATABASE_URL')
CA_FOLDER_MIGRATE := "apps/ca/migrations"
DNS_FOLDER_MIGRATE := "apps/dns/migrations"
CONFIG_FOLDER := "config"
DATA_FOLDER := "data"
DB_FOLDER := "db"
CERT_FOLDER := "certs"

default:
    @just --list

clean:
    @cargo clean

reset-db db_url src="./migrations":
    @[ -n "{{ db_url }}" ] || { echo "ERROR: db_url is empty"; exit 1; }
    @[ -d "{{ src }}" ]    || { echo "ERROR: source '{{ src }}' not found"; exit 1; }
    @sqlx migrate revert --source "{{ src }}" -D "{{ db_url }}"
    @sqlx migrate run    --source "{{ src }}" -D "{{ db_url }}"

migrate db_url src="./migrations":
    @[ -n "{{ db_url }}" ] || { echo "ERROR: db_url is empty"; exit 1; }
    @[ -d "{{ src }}" ]    || { echo "ERROR: source '{{ src }}' not found"; exit 1; }
    @[ -n "{{ db_url }}" ] || { echo "ERROR: db_url is empty"; exit 1; }
    @[ -d "{{ src }}" ]    || { echo "ERROR: source '{{ src }}' not found"; exit 1; }
    @sqlx migrate run --source "{{ src }}" -D "{{ db_url }}"

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

run-ca args="":
    @[[ ! -f "{{ DB_FOLDER }}/cert_store.db" ]] && just create-ca-db || true
    @[[ ! -f "{{ CERT_FOLDER }}/rootCA.pem" ]] && just create-ca-root || true
    @DATABASE_URL={{ CA_DATABASE_URL }} RUST_LOG=ca=debug,CHM_CA=debug  cargo run -p ca --bin CHM_CA -- {{ args }}

run-dns args="":
    @podman start CHM-DNS || true
    @DATABASE_URL={{ DNS_DATABASE_URL }} RUST_LOG=dns=debug,CHM_mDNSd=debug cargo run -p dns --bin CHM_mDNSd -- {{ args }}

run-controller args="":
    @RUST_LOG=controller=debug,CHMcd=debug cargo run -p controller --bin CHMcd -- {{ args }}

run-api args="":
    @RUST_LOG=api_server=debug,CHM_API=debug cargo run -p api_server --bin CHM_API -- {{ args }}

clean-certs:
    @find {{ CERT_FOLDER }} -mindepth 1 -not -name ".gitkeep" -print0 | xargs -0 rm -rf

clean-data:
    @find {{ DATA_FOLDER }} -mindepth 1 -not -name ".gitkeep" -print0 | xargs -0 rm -rf

clean-db:
    @find {{ DB_FOLDER }} -mindepth 1 -not -name ".gitkeep" -print0 | xargs -0 rm -rf

clean-config:
    @find {{ CONFIG_FOLDER }} -mindepth 1 -not -name ".gitkeep" -print0 | xargs -0 rm -rf

# clean-run-all: clean reset-all run-ca run-dns run-controller
clean-all: reset-all clean-certs clean-config clean-data clean-db

#Todo: 添加release編譯
