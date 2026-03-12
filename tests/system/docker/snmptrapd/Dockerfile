FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends snmptrapd snmp && \
    rm -rf /var/lib/apt/lists/*

COPY snmptrapd.conf /etc/snmp/snmptrapd.conf

EXPOSE 162/udp

# -f    foreground (do not daemonise)
# -Lo   log to stdout
# -n    do not translate source addresses to hostnames
# -m "" load no MIBs so all OIDs print as fully dotted-decimal numerics
CMD ["snmptrapd", "-f", "-Lo", "-n", "-m", ""]
