#!/bin/bash
set -eu
set -x

REPORTID="6c8a4ca3-b538-43b6-9b02-e9d1d6bb30f5"
FILTER="apply_overrides=0 levels=hml min_qod=70 first=1 sort-reverse=severity"

xmlreq="<get_reports report_id=\"$REPORTID\" ignore_pagination=\"1\" details=\"1\" filter=\"$FILTER\" />"
user="admin"
pass="9f7f748410df"

echo adduser go
echo gvm-cli \
  --timeout -1 \
  --gmp-username "$user" \
  --gmp-password "$pass" \
  socket \
  --xml \'"$xmlreq"\'
echo docker compose cp gvm-tools:/home/go/report.xml .
echo if the cp fails use the container name and "$(docker ps)" directly

docker compose run -ti --entrypoint=/bin/bash gvm-tools

# docker compose run -ti gvmd gvm-cli \
#   --gmp-username "$user" \
#   --gmp-password "$pass" \
#   socket \
#   --xml "$xmlreq"
