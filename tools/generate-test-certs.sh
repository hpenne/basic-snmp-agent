#!/usr/bin/env bash
#
# Generates a self-signed CA and server/client certificates for TLS testing.
# All output goes to tests/fixtures/certs/ relative to the repository root.
#
# The script is idempotent: running it again overwrites any previously
# generated files with fresh ones.
#
# Tested with LibreSSL (macOS) and OpenSSL (Linux).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${REPO_ROOT}/tests/fixtures/certs"

mkdir -p "${CERT_DIR}"

echo "Generating TLS test certificates in ${CERT_DIR}"

# ---------------------------------------------------------------------------
# CA certificate and key
# ---------------------------------------------------------------------------

echo "  [1/3] Generating CA key and self-signed certificate..."

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "${CERT_DIR}/ca.key"
chmod 600 "${CERT_DIR}/ca.key"

# Write CA extensions to a temporary config file so that LibreSSL's openssl
# can apply them via -extfile.  LibreSSL does not support -addext, and its
# "req -new -x509" variant also ignores -extfile, so we use the two-step
# CSR+sign approach (same as the server/client certs below).
# keyUsage = keyCertSign, cRLSign is required for net-snmp to accept this cert
# as a trust anchor; without it net-snmp silently rejects the CA cert when
# loading it into the SSL trust store.
CA_EXT_FILE="${CERT_DIR}/ca.ext"
cat > "${CA_EXT_FILE}" <<EOF
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

openssl req \
    -new \
    -key "${CERT_DIR}/ca.key" \
    -out "${CERT_DIR}/ca.csr" \
    -subj "/CN=Test CA"

openssl x509 \
    -req \
    -days 3650 \
    -in "${CERT_DIR}/ca.csr" \
    -signkey "${CERT_DIR}/ca.key" \
    -extfile "${CA_EXT_FILE}" \
    -out "${CERT_DIR}/ca.crt"

rm -f "${CA_EXT_FILE}" "${CERT_DIR}/ca.csr"

# ---------------------------------------------------------------------------
# Server certificate signed by the CA
#
# A Subject Alternative Name extension is required because modern TLS
# implementations ignore the CN field for hostname verification (RFC 6125).
# ---------------------------------------------------------------------------

echo "  [2/3] Generating server key and CA-signed certificate..."

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "${CERT_DIR}/server.key"
chmod 600 "${CERT_DIR}/server.key"

openssl req \
    -new \
    -key "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.csr" \
    -subj "/CN=test-agent"

# Write the SAN extension to a temporary config file so that LibreSSL's
# openssl (which does not support -addext) can apply it via -extfile.
SERVER_EXT_FILE="${CERT_DIR}/server.ext"
cat > "${SERVER_EXT_FILE}" <<EOF
subjectAltName = DNS:localhost, DNS:test-agent-mib, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

openssl x509 \
    -req \
    -days 3650 \
    -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -extfile "${SERVER_EXT_FILE}" \
    -out "${CERT_DIR}/server.crt"

rm -f "${SERVER_EXT_FILE}" "${CERT_DIR}/server.csr"

# ---------------------------------------------------------------------------
# Client certificate signed by the CA
#
# A Subject Alternative Name extension is added for consistency with the
# server certificate; some TLS stacks validate SANs on client certs too.
# ---------------------------------------------------------------------------

echo "  [3/3] Generating client key and CA-signed certificate..."

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "${CERT_DIR}/client.key"
chmod 600 "${CERT_DIR}/client.key"

openssl req \
    -new \
    -key "${CERT_DIR}/client.key" \
    -out "${CERT_DIR}/client.csr" \
    -subj "/CN=snmp-client"

# Write the SAN extension to a temporary config file so that LibreSSL's
# openssl (which does not support -addext) can apply it via -extfile.
CLIENT_EXT_FILE="${CERT_DIR}/client.ext"
cat > "${CLIENT_EXT_FILE}" <<EOF
subjectAltName = DNS:snmp-client
extendedKeyUsage = clientAuth
EOF

# Use -CAserial (not -CAcreateserial) so that the serial file written by the
# server signing step is reused, avoiding duplicate serial numbers.
openssl x509 \
    -req \
    -days 3650 \
    -in "${CERT_DIR}/client.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAserial "${CERT_DIR}/ca.srl" \
    -extfile "${CLIENT_EXT_FILE}" \
    -out "${CERT_DIR}/client.crt"

rm -f "${CLIENT_EXT_FILE}" "${CERT_DIR}/client.csr" "${CERT_DIR}/ca.srl"

echo "Done. Generated files:"
ls -1 "${CERT_DIR}"
