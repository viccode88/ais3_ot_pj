#!/bin/sh
set -eu

openplc_url="${OPENPLC_V3_URL:-http://127.0.0.1:18080}"
openplc_user="${OPENPLC_V3_USERNAME:-openplc}"
openplc_password="${OPENPLC_V3_PASSWORD:-openplc}"
cookie_file="$(mktemp "${TMPDIR:-/tmp}/plcfp-openplc-v3.XXXXXX")"
trap 'rm -f "$cookie_file"' EXIT HUP INT TERM

curl --fail --silent --show-error \
  --retry 30 --retry-connrefused --retry-delay 1 --max-time 3 \
  "${openplc_url}/login" >/dev/null

curl --fail --silent --show-error \
  --cookie-jar "$cookie_file" \
  --data-urlencode "username=${openplc_user}" \
  --data-urlencode "password=${openplc_password}" \
  --request POST \
  "${openplc_url}/login" >/dev/null

curl --fail --silent --show-error \
  --cookie "$cookie_file" \
  "${openplc_url}/start_plc" >/dev/null

curl --fail --silent --show-error \
  --cookie "$cookie_file" \
  "${openplc_url}/runtime_logs"
