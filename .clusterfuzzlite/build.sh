#!/bin/bash -eu
cd "$SRC"/basic-snmp-agent
cargo fuzz build -O
cp fuzz/target/*/release/snmpv3_request "$OUT"/
cp fuzz/target/*/release/snmpv3_request_auth "$OUT"/
cp fuzz/target/*/release/tcp_framing "$OUT"/
cp fuzz/target/*/release/snmpv3_request_structured "$OUT"/
cp fuzz/target/*/release/snmpv3_request_auth_structured "$OUT"/
cp fuzz/snmpv3.dict "$OUT"/snmpv3_request.dict
cp fuzz/snmpv3.dict "$OUT"/snmpv3_request_auth.dict
