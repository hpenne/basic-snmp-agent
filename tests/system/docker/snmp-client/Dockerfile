FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends snmp && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/snmp/certs
COPY tests/fixtures/certs/client.crt /etc/snmp/certs/client.crt
COPY tests/fixtures/certs/client.key /etc/snmp/certs/client.key
COPY tests/fixtures/certs/ca.crt /etc/snmp/certs/ca.crt
RUN printf 'clientCert /etc/snmp/certs/client.crt\nclientKey /etc/snmp/certs/client.key\ntrustCerts /etc/snmp/certs/ca.crt\n' > /etc/snmp/snmp.conf
