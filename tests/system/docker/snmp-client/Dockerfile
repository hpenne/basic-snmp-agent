FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends snmp ca-certificates tcpdump && \
    rm -rf /var/lib/apt/lists/*

# net-snmp's TLS cert scanner only looks in the home directory (~/.snmp/tls/).
# Cert + key must share the same base name and live in tls/certs/.
# CA cert goes in tls/ca-certs/ for server certificate validation.
RUN mkdir -p /root/.snmp/tls/certs /root/.snmp/tls/ca-certs
COPY tests/fixtures/certs/client.crt /root/.snmp/tls/certs/client.crt
COPY tests/fixtures/certs/client.key /root/.snmp/tls/certs/client.key
COPY tests/fixtures/certs/ca.crt /root/.snmp/tls/ca-certs/ca.crt

# localCert: SHA-256 fingerprint of the client certificate; net-snmp uses the
#            cert index to resolve the identity into the SSL context.
# peerCert:  SHA-256 fingerprint of the agent's server certificate for pinning.
# Both lookups require a populated cert index.  The RUN step below triggers
# init_snmp() which scans ~/.snmp/tls/ and writes the index files; the
# populated index is then baked into the image layer so it exists before the
# first real snmpget invocation processes the localCert/peerCert directives.
RUN printf 'trustCert d5e80371f8a20f1f4b44989ee0bf69d2ee9276699ee0103224aea7592cf008b8\nlocalCert 628eae58b93c89b20738caef21cd66d2d30a3f8b85e237ad0e0222a89032a825\n' > /etc/snmp/snmp.conf

# Force TLS 1.2 minimum via OpenSSL's system config.
#
# net-snmp's TLS code explicitly constructs its SSL_CTX with a TLS 1.0 minimum
# (client_version = 0x0301 in the ClientHello), overriding OpenSSL 3.0's own
# default of TLS 1.2.  With client_version = 0x0301, OpenSSL omits the
# signature_algorithms extension from the ClientHello; rustls rejects any
# ClientHello that lacks this extension when ECDHE cipher suites are offered
# (RFC 5246 §7.4.1.4.1).
#
# Setting MinProtocol = TLSv1.2 in [system_default_sect] is processed by
# OpenSSL at SSL_CTX_new() time, before net-snmp's setup code runs, and forces
# client_version to 0x0303.  OpenSSL 3.0 always includes signature_algorithms
# in TLS 1.2+ ClientHellos.  This deliberately avoids net-snmp's tlsAlgorithms
# directive, which calls SSL_CTX_set_cipher_list() and causes a pre-ClientHello
# InternalError alert from net-snmp's own tls_setup_handshake().
RUN printf '\n[openssl_init]\nssl_conf = ssl_sect\n\n[ssl_sect]\nsystem_default = system_default_sect\n\n[system_default_sect]\nMinProtocol = TLSv1.2\n' >> /etc/ssl/openssl.cnf

# Trigger cert-index population; the connection fails (no server) but the
# index files in /var/lib/snmp/cert_indexes/ are written and preserved in
# the image layer.
RUN snmpget -v3 -l authPriv -u dummy tlstcp:localhost:1 1.3.6.1.2.1.1.1.0 2>/dev/null; true

