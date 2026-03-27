#!/bin/bash
set -e

KEY=$(tr -dc a-z0-9 < /dev/urandom | head -c 32)
echo "ZAP_API_KEY=$KEY" > config/env

# docker compose up --build --force-recreate -d
