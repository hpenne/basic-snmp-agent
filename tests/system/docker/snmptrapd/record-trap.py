#!/usr/bin/env python3
"""snmptrapd trap handler: records each received trap as a JSON line.

snmptrapd invokes this script for every received trap, passing the trap
data on stdin in the following format:

    HOSTNAME
    IP-ADDRESS
    OID1 VALUE1
    OID2 VALUE2
    ...

With the ``-n`` flag and ``-m ""`` passed to snmptrapd, OIDs arrive in
fully dotted-decimal numeric form (e.g. ``.1.3.6.1.2.1.1.3.0``).

Each record is appended to ``/traps/received.jsonl`` as a single JSON line
so that behave step definitions can read and assert on trap content without
parsing unstructured log output.
"""

import json
import os
import sys

lines = [line.rstrip("\n") for line in sys.stdin.readlines()]

if len(lines) < 2:
    print(
        f"record-trap.py: warning: expected at least 2 lines (hostname + source) "
        f"but received {len(lines)}",
        file=sys.stderr,
    )

hostname = lines[0] if lines else ""
source = lines[1] if len(lines) > 1 else ""

varbinds = []
for line in lines[2:]:
    if not line.strip():
        continue
    parts = line.split(None, 1)
    if len(parts) >= 1:
        varbinds.append(
            {
                "oid": parts[0],
                "value": parts[1] if len(parts) > 1 else "",
            }
        )

record = {"hostname": hostname, "source": source, "varbinds": varbinds}

os.makedirs("/traps", exist_ok=True)
with open("/traps/received.jsonl", "a") as fh:
    fh.write(json.dumps(record) + "\n")
    fh.flush()
