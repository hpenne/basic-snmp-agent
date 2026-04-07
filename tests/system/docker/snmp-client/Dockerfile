FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends snmp ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/snmp/certs
COPY tests/fixtures/certs/client.crt /etc/snmp/certs/client.crt
COPY tests/fixtures/certs/client.key /etc/snmp/certs/client.key
COPY tests/fixtures/certs/ca.crt /etc/snmp/certs/ca.crt

# Install the test CA into the system trust store so OpenSSL (used by
# net-snmp's TLS transport) validates the agent's server certificate.
COPY tests/fixtures/certs/ca.crt /usr/local/share/ca-certificates/test-ca.crt
RUN update-ca-certificates

# localCert/localKey configure the client identity for mutual TLS.
# Server certificate validation uses the system CA trust store above.
RUN printf 'localCert /etc/snmp/certs/client.crt\nlocalKey /etc/snmp/certs/client.key\n' > /etc/snmp/snmp.conf
