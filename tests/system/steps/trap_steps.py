"""Behave step definitions for SNMP trap system tests.

Design principles
-----------------
- Received traps are retrieved from the structured JSON store written by
  ``record-trap.py`` inside each snmptrapd container.  No log parsing.
- Every received trap is given an explicit name in the ``Then`` step that
  captures it; subsequent ``And`` steps reference that name.  Named state
  stored in ``context.named_traps`` is always keyed by a name that appears
  verbatim in the step text, so there is no hidden implicit state.
- The test-agent binary runs as a Docker container on the same bridge network
  as snmptrapd, allowing hostname-based addressing (``snmptrapd:162``).  This
  works on macOS (where Docker Desktop does not forward UDP to the host) and
  on Linux CI runners alike.
"""

import json
import os
import subprocess
import tempfile
import time

from behave import given, then, use_step_matcher, when

# Use the regex-based step matcher so that quoted parameters are matched with
# ``[^"]+``, preventing one step pattern from matching a longer variant.
use_step_matcher("re")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _dot(oid: str) -> str:
    """Return *oid* with a leading dot, matching snmptrapd's numeric output."""
    return oid if oid.startswith(".") else f".{oid}"


def _run_agent(context, trap_defs: list) -> subprocess.CompletedProcess:
    """Serialise *trap_defs* to a temp JSON file and run the test-agent container."""
    fd, path = tempfile.mkstemp(suffix=".json")
    context.temp_files.append(path)
    with os.fdopen(fd, "w") as fh:
        json.dump(trap_defs, fh)

    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", context.docker_network,
            "-v", f"{path}:/trap.json",
            context.test_agent_image, "/trap.json",
        ],
        capture_output=True,
        text=True,
    )
    context.last_agent_output = result.stdout + result.stderr
    return result


def _read_traps(container: str) -> list[dict]:
    """Return all trap records from *container*'s JSON store, or [] if none."""
    result = subprocess.run(
        ["docker", "exec", container, "cat", "/traps/received.jsonl"],
        capture_output=True,
        text=True,
        check=False,
    )
    traps = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            try:
                traps.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return traps


def _poll_for_trap(
    container: str,
    attempts: int = 10,
    interval: float = 0.5,
    min_count: int = 1,
) -> list[dict]:
    """Poll *container*'s trap store until at least *min_count* traps appear.

    Returns all traps received so far once the threshold is met, or the last
    (possibly empty) snapshot after exhausting all attempts.
    """
    for _ in range(attempts):
        traps = _read_traps(container)
        if len(traps) >= min_count:
            return traps
        time.sleep(interval)
    return _read_traps(container)


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------

@given("snmptrapd is running")
def step_snmptrapd_is_running(context):
    result = subprocess.run(
        ["docker", "ps", "-q", "-f", f"name={context.snmptrapd_container}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.stdout.strip(), (
        f"snmptrapd container '{context.snmptrapd_container}' is not running"
    )


@given(r'a second snmptrapd named "(?P<receiver_name>[^"]+)" is running')
def step_second_snmptrapd_running(context, receiver_name):
    container_name = f"snmptrapd-{receiver_name}-test"
    subprocess.run(
        [
            "docker", "run", "-d", "--rm",
            "--name", container_name,
            "--network", context.docker_network,
            context.snmptrapd_image,
        ],
        check=True,
        capture_output=True,
    )
    context.extra_container_map[receiver_name] = container_name
    context.extra_containers.append(container_name)
    # Allow snmptrapd to bind its UDP socket before the scenario sends a trap.
    time.sleep(1)


# ---------------------------------------------------------------------------
# When steps
# ---------------------------------------------------------------------------

@when(r'the agent sends a trap with OID "(?P<trap_oid>[^"]+)"')
def step_send_trap(context, trap_oid):
    _run_agent(context, [
        {
            "request_id": 1,
            "trap_oid": trap_oid,
            "destinations": ["snmptrapd:162"],
            "varbinds": [],
        }
    ])


@when(r'the agent sends a trap with OID "(?P<trap_oid>[^"]+)" and varbinds')
def step_send_trap_with_varbinds(context, trap_oid):
    varbinds = []
    for row in context.table:
        try:
            value = int(row["value"])
        except ValueError:
            value = row["value"]
        varbinds.append({"oid": row["oid"], "type": row["type"], "data": value})
    _run_agent(context, [
        {
            "request_id": 1,
            "trap_oid": trap_oid,
            "destinations": ["snmptrapd:162"],
            "varbinds": varbinds,
        }
    ])


def _receiver_dest(context, receiver_name: str) -> str:
    """Return the ``host:port`` destination address for a named receiver."""
    if receiver_name == "snmptrapd":
        return "snmptrapd:162"
    return f"{context.extra_container_map[receiver_name]}:162"


@when(r'the agent sends to receivers "(?P<receiver1>[^"]+)" and "(?P<receiver2>[^"]+)" a trap with OID "(?P<trap_oid>[^"]+)"')
def step_send_trap_to_two_receivers(context, receiver1, receiver2, trap_oid):
    dest1 = _receiver_dest(context, receiver1)
    dest2 = _receiver_dest(context, receiver2)
    _run_agent(context, [
        {
            "request_id": 1,
            "trap_oid": trap_oid,
            "destinations": [dest1, dest2],
            "varbinds": [],
        }
    ])


@when(r'the agent sends an oversized trap with OID "(?P<trap_oid>[^"]+)"')
def step_send_oversized_trap(context, trap_oid):
    # 10 × 200-byte OctetString varbinds produce ~2 000+ bytes after BER
    # overhead, comfortably exceeding the 1 500-byte MTU cap.
    varbinds = [
        {"oid": f"1.3.6.1.2.1.1.{i}.0", "type": "OctetString", "data": "A" * 200}
        for i in range(10)
    ]
    _run_agent(context, [
        {
            "request_id": 1,
            "trap_oid": trap_oid,
            "destinations": ["snmptrapd:162"],
            "varbinds": varbinds,
        }
    ])


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------

@then(r'snmptrapd receives a trap named "(?P<name>[^"]+)"')
def step_snmptrapd_receives_trap(context, name):
    traps = _poll_for_trap(context.snmptrapd_container)
    assert traps, "snmptrapd did not receive any trap within the timeout"
    context.named_traps[name] = traps[0]


@then(r'"(?P<receiver_name>[^"]+)" receives a trap named "(?P<name>[^"]+)"')
def step_receiver_receives_trap(context, receiver_name, name):
    container = context.extra_container_map[receiver_name]
    traps = _poll_for_trap(container)
    assert traps, (
        f"Receiver '{receiver_name}' (container '{container}') did not receive "
        "any trap within the timeout"
    )
    context.named_traps[name] = traps[0]


@then(r'trap "(?P<name>[^"]+)" has varbind "(?P<oid>[^"]+)"')
def step_trap_has_varbind(context, name, oid):
    trap = context.named_traps[name]
    dot_oid = _dot(oid)
    matching = [v for v in trap["varbinds"] if v["oid"] == dot_oid]
    assert matching, (
        f"Trap '{name}' has no varbind with OID '{dot_oid}'.\n"
        f"Varbinds present: {trap['varbinds']}"
    )


@then(r'trap "(?P<name>[^"]+)" has varbind "(?P<oid>[^"]+)" with value "(?P<expected_value>[^"]+)"')
def step_trap_has_varbind_with_value(context, name, oid, expected_value):
    trap = context.named_traps[name]
    dot_oid = _dot(oid)
    dot_val = _dot(expected_value) if "." in expected_value else expected_value
    matching = [v for v in trap["varbinds"] if v["oid"] == dot_oid]
    assert matching, (
        f"Trap '{name}' has no varbind with OID '{dot_oid}'.\n"
        f"Varbinds present: {trap['varbinds']}"
    )
    # Substring match: snmptrapd may prefix the value with type information
    # (e.g. "OID: .1.3.6.1..." or "INTEGER: 42"), so we check containment
    # rather than equality.
    assert any(dot_val in v["value"] for v in matching), (
        f"Trap '{name}' varbind '{dot_oid}' does not contain value '{dot_val}'.\n"
        f"Actual values: {[v['value'] for v in matching]}"
    )


@then(r'the agent reports an error containing "(?P<substring>[^"]+)"')
def step_agent_reports_error(context, substring):
    assert substring in context.last_agent_output, (
        f"Expected '{substring}' in agent output.\nOutput:\n{context.last_agent_output}"
    )


@then("snmptrapd receives no traps")
def step_snmptrapd_receives_no_traps(context):
    # Wait briefly to give any errant datagram time to arrive and be recorded.
    time.sleep(1)
    traps = _read_traps(context.snmptrapd_container)
    assert not traps, (
        f"Expected no traps but snmptrapd recorded {len(traps)}:\n"
        + "\n".join(json.dumps(t) for t in traps)
    )
