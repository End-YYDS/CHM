#!/bin/bash

docker run -d \
  --name CHM-DNS \
  -e POSTGRES_USER=chm \
  -e POSTGRES_PASSWORD=qpM9CdpdbpF4z6C\
  -e POSTGRES_DB=dns \
  -v pgdata:/var/lib/postgresql/data \
  -p 5432:5432 \
  postgres:latest
