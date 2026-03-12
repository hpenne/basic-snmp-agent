FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends snmptrapd snmp python3 && \
    rm -rf /var/lib/apt/lists/*

COPY tests/system/docker/snmptrapd/snmptrapd.conf /etc/snmp/snmptrapd.conf
COPY tests/system/docker/snmptrapd/record-trap.py /usr/local/bin/record-trap.py

RUN chmod +x /usr/local/bin/record-trap.py && mkdir -p /traps

EXPOSE 162/udp

# -f    foreground (do not daemonise)
# -Lo   log to stdout
# -n    do not translate source addresses to hostnames
# -m "" load no MIBs so all OIDs arrive at the trap handler in dotted-decimal
CMD ["snmptrapd", "-f", "-Lo", "-n", "-m", ""]
