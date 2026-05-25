#!/usr/bin/env bash
set -euo pipefail

: "${NDND_SOCKET:?set NDND_SOCKET to an ndnd application Unix socket}"
: "${NDN_APP_SIGNING_KEY_FILE:?set NDN_APP_SIGNING_KEY_FILE to an operator-format NDN KEY PEM}"
: "${NDN_APP_SIGNING_CERT_FILE:?set NDN_APP_SIGNING_CERT_FILE to its NDN CERT PEM}"
: "${NDN_APP_TRUST_ANCHOR_DIR:?set NDN_APP_TRUST_ANCHOR_DIR to trusted public roots}"
: "${NDN_APP_CERTIFICATE_CHAIN_DIR:?set NDN_APP_CERTIFICATE_CHAIN_DIR to public leaf and intermediate certs}"

export NDN_CLIENT_TRANSPORT="unix://${NDND_SOCKET}"
name="${NDN_TEST_NAME:-/root-network/subnetwork1/helloworld/valid}"

cargo run --locked --bin producer -- --name "${name}" &
producer_pid="$!"
trap 'kill "${producer_pid}" 2>/dev/null || true' EXIT
sleep 1
cargo run --locked --bin consumer -- --name "${name}"
