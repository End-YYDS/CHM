#!/bin/bash

docker run -d \
  --name CHM-DNS \
  -e POSTGRES_USER=chm \
  -e POSTGRES_PASSWORD=qpM9CdpdbpF4z6C\
  -e POSTGRES_DB=dns \
  -v pgdata:/var/lib/postgresql/data \
  -p 5432:5432 \
  postgres:latest

export DATABASE_URL=postgresql://chm:qpM9CdpdbpF4z6C@127.0.0.1:5432/dns
cargo sqlx migrate run
