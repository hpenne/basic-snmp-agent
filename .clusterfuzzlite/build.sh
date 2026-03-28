#!/bin/bash -eu
cd "$SRC"/basic-snmp-agent
cargo fuzz build -O
cp fuzz/target/*/release/snmpv3_request "$OUT"/
