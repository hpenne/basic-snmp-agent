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

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from typing import Any

from behave import (  # pylint: disable=no-name-in-module,import-error  # behave uses lazy imports
    given,
    then,
    when,
)

from context_protocol import SnmpAgentContext

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _dot(oid: str) -> str:
    """Return *oid* with a leading dot, matching snmptrapd's numeric output."""
    return oid if oid.startswith(".") else f".{oid}"


# Engine ID for the authNoPriv trap test agent ("trap-auth-np" in text format).
_TRAP_AUTH_NP_ENGINE_ID = "80001f8804747261702d617574682d6e70"

# Engine ID for the authPriv trap test agent ("trap-auth-pr" in text format).
_TRAP_AUTH_PRIV_ENGINE_ID = "80001f8804747261702d617574682d7072"

# Engine ID for the noAuthNoPriv trap test agent ("trap-noauth" in text format).
_TRAP_NOAUTH_ENGINE_ID = "80001f8804747261702d6e6f61757468"


def _run_agent_docker(
    context: SnmpAgentContext,
    trap_defs: list[dict[str, Any]],
    env_vars: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Serialise *trap_defs* to a temp JSON file and run the test-agent container."""
    fd, path = tempfile.mkstemp(suffix=".json")
    context.temp_files.append(path)
    with os.fdopen(fd, "w") as fh:
        json.dump(trap_defs, fh)

    env_args = []
    for key, val in (env_vars or {}).items():
        env_args.extend(["-e", f"{key}={val}"])

    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            context.docker_network,
            *env_args,
            "-v",
            f"{path}:/trap.json",
            context.test_agent_image,
            "/trap.json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    context.last_agent_output = result.stdout + result.stderr
    return result


def _parse_varbind_table(context: SnmpAgentContext) -> list[dict[str, str | int]]:
    """Convert a Behave table of (oid, type, value) rows into trap-definition varbinds."""
    varbinds: list[dict[str, str | int]] = []
    for row in context.table:
        try:
            value: str | int = int(row["value"])
        except ValueError:
            value = row["value"]
        varbinds.append({"oid": row["oid"], "type": row["type"], "data": value})
    return varbinds


def _read_traps(container: str) -> list[dict[str, Any]]:
    """Return all trap records from *container*'s JSON store, or [] if none."""
    result = subprocess.run(
        ["docker", "exec", container, "cat", "/traps/received.jsonl"],
        capture_output=True,
        text=True,
        check=False,
    )
    traps: list[dict[str, Any]] = []
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
) -> list[dict[str, Any]]:
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
def step_snmptrapd_is_running(context: SnmpAgentContext) -> None:
    result = subprocess.run(
        ["docker", "ps", "-q", "-f", f"name={context.snmptrapd_container}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert (
        result.stdout.strip()
    ), f"snmptrapd container '{context.snmptrapd_container}' is not running"


@given('a second snmptrapd named "{receiver_name}" is running')
def step_second_snmptrapd_running(
    context: SnmpAgentContext, receiver_name: str
) -> None:
    container_name = f"snmptrapd-{receiver_name}-test"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            container_name,
            "--network",
            context.docker_network,
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


@when('the agent sends a trap with OID "{trap_oid}"')
def step_send_trap(context: SnmpAgentContext, trap_oid: str) -> None:
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": ["snmptrapd:162"],
                "varbinds": [],
            }
        ],
    )


@when('the agent sends a trap with OID "{trap_oid}" and varbinds')
def step_send_trap_with_varbinds(context: SnmpAgentContext, trap_oid: str) -> None:
    varbinds = _parse_varbind_table(context)
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": ["snmptrapd:162"],
                "varbinds": varbinds,
            }
        ],
    )


def _receiver_dest(context: SnmpAgentContext, receiver_name: str) -> str:
    """Return the ``host:port`` destination address for a named receiver."""
    if receiver_name == "snmptrapd":
        return "snmptrapd:162"
    return f"{context.extra_container_map[receiver_name]}:162"


@when(
    'the agent sends to receivers "{receiver1}" and "{receiver2}" a trap with OID "{trap_oid}"'
)
def step_send_trap_to_two_receivers(
    context: SnmpAgentContext, receiver1: str, receiver2: str, trap_oid: str
) -> None:
    dest1 = _receiver_dest(context, receiver1)
    dest2 = _receiver_dest(context, receiver2)
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": [dest1, dest2],
                "varbinds": [],
            }
        ],
    )


@when('the agent sends an oversized trap with OID "{trap_oid}"')
def step_send_oversized_trap(context: SnmpAgentContext, trap_oid: str) -> None:
    # 10 × 200-byte OctetString varbinds produce ~2 000+ bytes after BER
    # overhead, comfortably exceeding the 1 500-byte MTU cap.
    varbinds = [
        {"oid": f"1.3.6.1.2.1.1.{i}.0", "type": "OctetString", "data": "A" * 200}
        for i in range(10)
    ]
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": ["snmptrapd:162"],
                "varbinds": varbinds,
            }
        ],
    )


@when('the agent sends a trap with OID "{trap_oid}" to no destinations')
def step_send_trap_no_destinations(context: SnmpAgentContext, trap_oid: str) -> None:
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": [],
                "varbinds": [],
            }
        ],
    )


@when(
    'the agent at authNoPriv with user "{user}" and password "{password}" sends a trap with OID "{trap_oid}"'
)
def step_send_trap_auth_no_priv(
    context: SnmpAgentContext, user: str, password: str, trap_oid: str
) -> None:
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": ["snmptrapd:162"],
                "varbinds": [],
            }
        ],
        env_vars={
            "USM_ENGINE_ID": _TRAP_AUTH_NP_ENGINE_ID,
            "USM_USER": user,
            "USM_AUTH_PROTO": "SHA-256",
            "USM_AUTH_PASS": password,
            "USM_SECURITY_LEVEL": "authNoPriv",
        },
    )


@when(
    'the agent at authNoPriv with user "{user}" and password "{password}" sends a trap with OID "{trap_oid}" and varbinds'
)
def step_send_trap_auth_no_priv_with_varbinds(
    context: SnmpAgentContext, user: str, password: str, trap_oid: str
) -> None:
    varbinds = _parse_varbind_table(context)
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": ["snmptrapd:162"],
                "varbinds": varbinds,
            }
        ],
        env_vars={
            "USM_ENGINE_ID": _TRAP_AUTH_NP_ENGINE_ID,
            "USM_USER": user,
            "USM_AUTH_PROTO": "SHA-256",
            "USM_AUTH_PASS": password,
            "USM_SECURITY_LEVEL": "authNoPriv",
        },
    )


@when(
    'the agent at authNoPriv with user "{user}" and password "{password}" sends to receivers "{receiver1}" and "{receiver2}" a trap with OID "{trap_oid}"'
)
def step_send_trap_auth_no_priv_to_two_receivers(
    context: SnmpAgentContext,
    user: str,
    password: str,
    receiver1: str,
    receiver2: str,
    trap_oid: str,
) -> None:
    dest1 = _receiver_dest(context, receiver1)
    dest2 = _receiver_dest(context, receiver2)
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": [dest1, dest2],
                "varbinds": [],
            }
        ],
        env_vars={
            "USM_ENGINE_ID": _TRAP_AUTH_NP_ENGINE_ID,
            "USM_USER": user,
            "USM_AUTH_PROTO": "SHA-256",
            "USM_AUTH_PASS": password,
            "USM_SECURITY_LEVEL": "authNoPriv",
        },
    )


@when(
    'the agent at authPriv with user "{user}" and auth password "{auth_password}" sends a trap with OID "{trap_oid}"'
)
def step_send_trap_auth_priv(
    context: SnmpAgentContext,
    user: str,
    auth_password: str,
    trap_oid: str,
) -> None:
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": ["snmptrapd:162"],
                "varbinds": [],
            }
        ],
        env_vars={
            "USM_ENGINE_ID": _TRAP_AUTH_PRIV_ENGINE_ID,
            "USM_USER": user,
            "USM_AUTH_PROTO": "SHA-256",
            "USM_AUTH_PASS": auth_password,
            "USM_PRIV_PROTO": "AES-128",
            "USM_SECURITY_LEVEL": "authPriv",
        },
    )


@when(
    'the agent at authPriv with user "{user}" and auth password "{auth_password}" sends a trap with OID "{trap_oid}" and varbinds'
)
def step_send_trap_auth_priv_with_varbinds(
    context: SnmpAgentContext,
    user: str,
    auth_password: str,
    trap_oid: str,
) -> None:
    varbinds = _parse_varbind_table(context)
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": ["snmptrapd:162"],
                "varbinds": varbinds,
            }
        ],
        env_vars={
            "USM_ENGINE_ID": _TRAP_AUTH_PRIV_ENGINE_ID,
            "USM_USER": user,
            "USM_AUTH_PROTO": "SHA-256",
            "USM_AUTH_PASS": auth_password,
            "USM_PRIV_PROTO": "AES-128",
            "USM_SECURITY_LEVEL": "authPriv",
        },
    )


@when(
    'the agent at authPriv with user "{user}" and auth password "{auth_password}" sends to receivers "{receiver1}" and "{receiver2}" a trap with OID "{trap_oid}"'
)
def step_send_trap_auth_priv_to_two_receivers(
    context: SnmpAgentContext,
    user: str,
    auth_password: str,
    receiver1: str,
    receiver2: str,
    trap_oid: str,
) -> None:
    dest1 = _receiver_dest(context, receiver1)
    dest2 = _receiver_dest(context, receiver2)
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": [dest1, dest2],
                "varbinds": [],
            }
        ],
        env_vars={
            "USM_ENGINE_ID": _TRAP_AUTH_PRIV_ENGINE_ID,
            "USM_USER": user,
            "USM_AUTH_PROTO": "SHA-256",
            "USM_AUTH_PASS": auth_password,
            "USM_PRIV_PROTO": "AES-128",
            "USM_SECURITY_LEVEL": "authPriv",
        },
    )


@when('the agent at noAuthNoPriv with user "{user}" sends a trap with OID "{trap_oid}"')
def step_send_trap_no_auth_no_priv(
    context: SnmpAgentContext, user: str, trap_oid: str
) -> None:
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": ["snmptrapd:162"],
                "varbinds": [],
            }
        ],
        env_vars={
            "USM_ENGINE_ID": _TRAP_NOAUTH_ENGINE_ID,
            "USM_USER": user,
            "USM_SECURITY_LEVEL": "noAuthNoPriv",
        },
    )


@when(
    'the agent at noAuthNoPriv with user "{user}" sends a trap with OID "{trap_oid}" and varbinds'
)
def step_send_trap_no_auth_no_priv_with_varbinds(
    context: SnmpAgentContext, user: str, trap_oid: str
) -> None:
    varbinds = _parse_varbind_table(context)
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": ["snmptrapd:162"],
                "varbinds": varbinds,
            }
        ],
        env_vars={
            "USM_ENGINE_ID": _TRAP_NOAUTH_ENGINE_ID,
            "USM_USER": user,
            "USM_SECURITY_LEVEL": "noAuthNoPriv",
        },
    )


@when(
    'the agent at noAuthNoPriv with user "{user}" sends to receivers "{receiver1}" and "{receiver2}" a trap with OID "{trap_oid}"'
)
def step_send_trap_no_auth_no_priv_to_two_receivers(
    context: SnmpAgentContext,
    user: str,
    receiver1: str,
    receiver2: str,
    trap_oid: str,
) -> None:
    dest1 = _receiver_dest(context, receiver1)
    dest2 = _receiver_dest(context, receiver2)
    _run_agent_docker(
        context,
        [
            {
                "request_id": 1,
                "trap_oid": trap_oid,
                "destinations": [dest1, dest2],
                "varbinds": [],
            }
        ],
        env_vars={
            "USM_ENGINE_ID": _TRAP_NOAUTH_ENGINE_ID,
            "USM_USER": user,
            "USM_SECURITY_LEVEL": "noAuthNoPriv",
        },
    )


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


@then('snmptrapd receives a trap named "{name}"')
def step_snmptrapd_receives_trap(context: SnmpAgentContext, name: str) -> None:
    traps = _poll_for_trap(context.snmptrapd_container)
    assert traps, "snmptrapd did not receive any trap within the timeout"
    context.named_traps[name] = traps[0]


@then('"{receiver_name}" receives a trap named "{name}"')
def step_receiver_receives_trap(
    context: SnmpAgentContext, receiver_name: str, name: str
) -> None:
    container = context.extra_container_map[receiver_name]
    traps = _poll_for_trap(container)
    assert traps, (
        f"Receiver '{receiver_name}' (container '{container}') did not receive "
        "any trap within the timeout"
    )
    context.named_traps[name] = traps[0]


@then('trap "{name}" has varbind "{oid}" with value "{expected_value}"')
def step_trap_has_varbind_with_value(
    context: SnmpAgentContext, name: str, oid: str, expected_value: str
) -> None:
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


@then('trap "{name}" has varbind "{oid}"')
def step_trap_has_varbind(context: SnmpAgentContext, name: str, oid: str) -> None:
    trap = context.named_traps[name]
    dot_oid = _dot(oid)
    matching = [v for v in trap["varbinds"] if v["oid"] == dot_oid]
    assert matching, (
        f"Trap '{name}' has no varbind with OID '{dot_oid}'.\n"
        f"Varbinds present: {trap['varbinds']}"
    )


@then('the agent reports an error containing "{substring}"')
def step_agent_reports_error(context: SnmpAgentContext, substring: str) -> None:
    assert (
        substring in context.last_agent_output
    ), f"Expected '{substring}' in agent output.\nOutput:\n{context.last_agent_output}"


@then("snmptrapd receives no traps")
def step_snmptrapd_receives_no_traps(context: SnmpAgentContext) -> None:
    # Wait briefly to give any errant datagram time to arrive and be recorded.
    time.sleep(1)
    traps = _read_traps(context.snmptrapd_container)
    assert (
        not traps
    ), f"Expected no traps but snmptrapd recorded {len(traps)}:\n" + "\n".join(
        json.dumps(t) for t in traps
    )
