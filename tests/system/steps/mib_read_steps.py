"""Behave step definitions for SNMP MIB read system tests.

The test-agent-mib container runs an agent pre-seeded with known MIB values.
Net-snmp CLI tools (snmpget, snmpgetnext, snmpbulkget) query the agent from
a snmp-client container on the same Docker bridge network.
"""

from __future__ import annotations

import subprocess
import time
import uuid

from behave import (  # pylint: disable=no-name-in-module  # behave uses lazy imports
    given,
    then,
    when,
)

from context_protocol import SnmpAgentContext

ENGINE_ID = "0x80001f8804746573742d6167656e742d6d6962"

# SNMPv3 noAuthNoPriv flags for net-snmp CLI tools.
# Net-snmp requires a non-empty security name even for noAuthNoPriv; the agent
# does not authenticate the username on the plain TCP path.
# -On prints OIDs in numeric form so step assertions can match on the dotted
# numeric string that appears in the feature file.
SNMPV3_FLAGS = ["-v3", "-l", "noAuthNoPriv", "-u", "noauth", "-On"]


def _snmp_client_run(
    context: SnmpAgentContext, snmp_cmd: list[str]
) -> subprocess.CompletedProcess[str]:
    """Run *snmp_cmd* inside a snmp-client container on the test network."""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            context.docker_network,
            context.snmp_client_image,
        ]
        + snmp_cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    return result


def _run_and_store(context: SnmpAgentContext, snmp_cmd: list[str]) -> None:
    """Run *snmp_cmd* via _snmp_client_run and store results on context."""
    result = _snmp_client_run(context, snmp_cmd)
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


def _agent_addr(context: SnmpAgentContext) -> str:
    assert context.agent_container is not None
    return f"tcp:{context.agent_container}:10161"


def _start_agent_container(
    context: SnmpAgentContext, name_prefix: str, image: str, ready_sentinel: str
) -> str:
    """Start a test-agent container on the test network and wait for it to signal readiness.

    Polls docker logs rather than using a fixed sleep so the step returns as
    soon as the agent is ready. This is faster on fast machines and more
    reliable on slow CI.
    """
    container_name = f"{name_prefix}-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--name",
            container_name,
            "--network",
            context.docker_network,
            image,
        ],
        check=True,
        capture_output=True,
    )
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        logs = subprocess.run(
            ["docker", "logs", container_name],
            capture_output=True,
            text=True,
            check=False,
        )
        if ready_sentinel in logs.stdout + logs.stderr:
            return container_name
        time.sleep(0.2)
    raise AssertionError(
        f"container {container_name!r} did not signal readiness within 10 seconds"
    )


@given('a test-agent-mib instance is running with engine ID "{engine_id}"')
def step_start_test_agent_mib(context: SnmpAgentContext, engine_id: str) -> None:
    context.agent_container = _start_agent_container(
        context, "test-agent-mib", context.test_agent_mib_image, "test-agent-mib ready"
    )
    context.agent_engine_id = engine_id


@when('snmpget queries OID "{oid}" from the agent')
def step_snmpget(context: SnmpAgentContext, oid: str) -> None:
    _run_and_store(
        context,
        ["snmpget"]
        + SNMPV3_FLAGS
        + ["-e", context.agent_engine_id, _agent_addr(context), oid],
    )
    context.last_snmp_oid = oid


@when('snmpgetnext queries OID "{oid}" from the agent')
def step_snmpgetnext(context: SnmpAgentContext, oid: str) -> None:
    _run_and_store(
        context,
        ["snmpgetnext"]
        + SNMPV3_FLAGS
        + ["-e", context.agent_engine_id, _agent_addr(context), oid],
    )


@when(
    'snmpbulkget with non-repeaters={non_repeaters:d} and max-repetitions={max_repetitions:d} queries OID "{oid}" from the agent'
)
def step_snmpbulkget(
    context: SnmpAgentContext, non_repeaters: int, max_repetitions: int, oid: str
) -> None:
    _run_and_store(
        context,
        ["snmpbulkget"]
        + SNMPV3_FLAGS
        + [
            "-e",
            context.agent_engine_id,
            f"-Cn{non_repeaters}",
            f"-Cr{max_repetitions}",
            _agent_addr(context),
            oid,
        ],
    )


@when(
    'snmpget with wrong context engine ID "{context_engine_id}" queries OID "{oid}" from the agent'
)
def step_snmpget_wrong_context_engine_id(
    context: SnmpAgentContext, context_engine_id: str, oid: str
) -> None:
    # -e sets the authoritative engine ID (correct), -E sets the contextEngineID
    # (wrong). This exercises the contextEngineID mismatch path (REQ-0104) while
    # keeping the message-level engine ID valid so the agent decodes the message.
    _run_and_store(
        context,
        ["snmpget"]
        + SNMPV3_FLAGS
        + [
            "-e",
            context.agent_engine_id,
            "-E",
            context_engine_id,
            "-t",
            "2",
            "-r",
            "0",
            _agent_addr(context),
            oid,
        ],
    )


@when('snmpget with context name "{context_name}" queries OID "{oid}" from the agent')
def step_snmpget_with_context_name(
    context: SnmpAgentContext, context_name: str, oid: str
) -> None:
    _run_and_store(
        context,
        ["snmpget"]
        + SNMPV3_FLAGS
        + [
            "-e",
            context.agent_engine_id,
            "-n",
            context_name,
            "-t",
            "2",
            "-r",
            "0",
            _agent_addr(context),
            oid,
        ],
    )


@when('snmpget without explicit engine ID queries OID "{oid}" from the agent')
def step_snmpget_no_engine_id(context: SnmpAgentContext, oid: str) -> None:
    # Other steps pass -e to skip discovery. Omitting it here forces net-snmp to
    # perform engine-ID discovery (RFC 3414 §4) before the actual GET.
    _run_and_store(
        context,
        ["snmpget"] + SNMPV3_FLAGS + ["-t", "5", "-r", "1", _agent_addr(context), oid],
    )


@then('the SNMP response contains OID "{oid}" with string value "{value}"')
def step_response_contains_oid_with_value(
    context: SnmpAgentContext, oid: str, value: str
) -> None:
    output = context.last_snmp_output
    assert oid in output, f"OID {oid!r} not found in output:\n{output}"
    assert value in output, f"Value {value!r} not found in output:\n{output}"


@then('the SNMP response contains OID "{oid}" with exception "{exception}"')
def step_response_contains_oid_with_exception(
    context: SnmpAgentContext, oid: str, exception: str
) -> None:
    output = context.last_snmp_output
    assert oid in output, f"OID {oid!r} not found in output:\n{output}"
    assert (
        exception in output
    ), f"Exception {exception!r} not found in output:\n{output}"


@then('the SNMP response contains exception "{exception}"')
def step_response_contains_exception(context: SnmpAgentContext, exception: str) -> None:
    output = context.last_snmp_output
    assert (
        exception in output
    ), f"Exception {exception!r} not found in output:\n{output}"


@then('the SNMP response contains OID "{oid}"')
def step_response_contains_oid(context: SnmpAgentContext, oid: str) -> None:
    output = context.last_snmp_output
    assert oid in output, f"OID {oid!r} not found in output:\n{output}"


@then('the SNMP response does not contain OID "{oid}"')
def step_response_not_contains_oid(context: SnmpAgentContext, oid: str) -> None:
    output = context.last_snmp_output
    assert oid not in output, f"OID {oid!r} unexpectedly found in output:\n{output}"


@when('snmpset queries OID "{oid}" with string value "{value}" from the agent')
def step_snmpset(context: SnmpAgentContext, oid: str, value: str) -> None:
    _run_and_store(
        context,
        ["snmpset"]
        + SNMPV3_FLAGS
        + ["-e", context.agent_engine_id, _agent_addr(context), oid, "s", value],
    )


@then('the SNMP response contains error "{error}"')
def step_response_contains_error(context: SnmpAgentContext, error: str) -> None:
    output = context.last_snmp_output
    assert error in output, f"Error {error!r} not found in output:\n{output}"


@then("the SNMP request times out or returns an error")
def step_request_times_out_or_error(context: SnmpAgentContext) -> None:
    output = context.last_snmp_output
    returncode = context.last_snmp_returncode
    assert returncode != 0 or "Timeout" in output, (
        f"Expected timeout or non-zero exit code, but got returncode={returncode} "
        f"and output:\n{output}"
    )


@then("the SNMP response is a Report PDU")
def step_response_is_report_pdu(context: SnmpAgentContext) -> None:
    output = context.last_snmp_output
    returncode = context.last_snmp_returncode
    # A Report PDU causes net-snmp to exit with non-zero return code and print
    # an error — but crucially it does NOT contain "Timeout", because the agent
    # actually responded (unlike the old silent-discard behaviour).
    assert returncode != 0, (
        f"Expected non-zero exit code for Report PDU, but got returncode=0 "
        f"and output:\n{output}"
    )
    assert "Timeout" not in output, (
        f"Expected Report PDU response (not a timeout), but output "
        f"contains 'Timeout':\n{output}"
    )


@given('a test-agent-mib-auth instance is running with engine ID "{engine_id}"')
def step_start_test_agent_mib_auth(context: SnmpAgentContext, engine_id: str) -> None:
    context.agent_container = _start_agent_container(
        context,
        "test-agent-mib-auth",
        context.test_agent_mib_auth_image,
        "test-agent-mib-auth ready",
    )
    context.agent_engine_id = engine_id


def _auth_no_priv_flags(user: str, password: str, engine_id: str) -> list[str]:
    # SNMPv3 authNoPriv flags: HMAC-SHA-256 authentication, no privacy encryption.
    # -u sets the security name, -a the auth protocol, -A the auth passphrase,
    # -e the authoritative engine ID, -On prints OIDs in numeric form.
    return [
        "-v3",
        "-l",
        "authNoPriv",
        "-u",
        user,
        "-a",
        "SHA-256",
        "-A",
        password,
        "-e",
        engine_id,
        "-On",
    ]


@when(
    'snmpget at authNoPriv with user "{user}" and password "{password}" queries OID "{oid}" from the agent'
)
def step_snmpget_auth_no_priv(
    context: SnmpAgentContext, user: str, password: str, oid: str
) -> None:
    _run_and_store(
        context,
        ["snmpget"]
        + _auth_no_priv_flags(user, password, context.agent_engine_id)
        + ["-t", "5", "-r", "1", _agent_addr(context), oid],
    )


@when(
    'snmpgetnext at authNoPriv with user "{user}" and password "{password}" queries OID "{oid}" from the agent'
)
def step_snmpgetnext_auth_no_priv(
    context: SnmpAgentContext, user: str, password: str, oid: str
) -> None:
    _run_and_store(
        context,
        ["snmpgetnext"]
        + _auth_no_priv_flags(user, password, context.agent_engine_id)
        + ["-t", "5", "-r", "1", _agent_addr(context), oid],
    )


@when(
    'snmpbulkget at authNoPriv with user "{user}" and password "{password}", non-repeaters={non_repeaters:d} and max-repetitions={max_repetitions:d} queries OID "{oid}" from the agent'
)
def step_snmpbulkget_auth_no_priv(
    context: SnmpAgentContext,
    user: str,
    password: str,
    non_repeaters: int,
    max_repetitions: int,
    oid: str,
) -> None:
    _run_and_store(
        context,
        ["snmpbulkget"]
        + _auth_no_priv_flags(user, password, context.agent_engine_id)
        + [
            "-t",
            "5",
            "-r",
            "1",
            f"-Cn{non_repeaters}",
            f"-Cr{max_repetitions}",
            _agent_addr(context),
            oid,
        ],
    )


@when(
    'snmpget at authNoPriv without explicit engine ID with user "{user}" and password "{password}" queries OID "{oid}" from the agent'
)
def step_snmpget_auth_no_priv_no_engine_id(
    context: SnmpAgentContext, user: str, password: str, oid: str
) -> None:
    # Omitting -e forces net-snmp to perform engine-ID discovery (RFC 3414 §4)
    # before sending the authenticated GET. This exercises REQ-0080: discovery
    # must succeed regardless of the configured security level.
    _run_and_store(
        context,
        [
            "snmpget",
            "-v3",
            "-l",
            "authNoPriv",
            "-u",
            user,
            "-a",
            "SHA-256",
            "-A",
            password,
            "-On",
            "-t",
            "5",
            "-r",
            "1",
            _agent_addr(context),
            oid,
        ],
    )


@when(
    'snmpget at authNoPriv with wrong context engine ID "{context_engine_id}" with user "{user}" and password "{password}" queries OID "{oid}" from the agent'
)
def step_snmpget_auth_no_priv_wrong_context_engine_id(
    context: SnmpAgentContext,
    context_engine_id: str,
    user: str,
    password: str,
    oid: str,
) -> None:
    # -e (from _auth_no_priv_flags) sets the authoritative engine ID correctly;
    # -E sets the contextEngineID to a wrong value to trigger REQ-0104.
    _run_and_store(
        context,
        ["snmpget"]
        + _auth_no_priv_flags(user, password, context.agent_engine_id)
        + ["-E", context_engine_id, "-t", "2", "-r", "0", _agent_addr(context), oid],
    )


@when('snmpget at noAuthNoPriv with user "{user}" queries OID "{oid}" from the agent')
def step_snmpget_no_auth_no_priv(
    context: SnmpAgentContext, user: str, oid: str
) -> None:
    # Short timeout with no retries: the agent rejects this request immediately,
    # so there is no need to wait for the default retry window.
    _run_and_store(
        context,
        [
            "snmpget",
            "-v3",
            "-l",
            "noAuthNoPriv",
            "-u",
            user,
            "-On",
            "-e",
            context.agent_engine_id,
            "-t",
            "2",
            "-r",
            "0",
            _agent_addr(context),
            oid,
        ],
    )


@given('a test-agent-mib-auth-priv instance is running with engine ID "{engine_id}"')
def step_start_test_agent_mib_auth_priv(
    context: SnmpAgentContext, engine_id: str
) -> None:
    context.agent_container = _start_agent_container(
        context,
        "test-agent-mib-auth-priv",
        context.test_agent_mib_auth_priv_image,
        "test-agent-mib-auth-priv ready",
    )
    context.agent_engine_id = engine_id


def _auth_priv_flags(
    user: str, auth_password: str, priv_password: str, engine_id: str
) -> list[str]:
    # SNMPv3 authPriv flags: HMAC-SHA-256 authentication and AES-128-CFB encryption.
    # -u sets the security name, -a the auth protocol, -A the auth passphrase,
    # -x the priv protocol, -X the priv passphrase,
    # -e the authoritative engine ID, -On prints OIDs in numeric form.
    return [
        "-v3",
        "-l",
        "authPriv",
        "-u",
        user,
        "-a",
        "SHA-256",
        "-A",
        auth_password,
        "-x",
        "AES",
        "-X",
        priv_password,
        "-e",
        engine_id,
        "-On",
    ]


@when(
    'snmpget at authPriv with user "{user}", auth password "{auth_password}", and priv password "{priv_password}" queries OID "{oid}" from the agent'
)
def step_snmpget_auth_priv(
    context: SnmpAgentContext,
    user: str,
    auth_password: str,
    priv_password: str,
    oid: str,
) -> None:
    _run_and_store(
        context,
        ["snmpget"]
        + _auth_priv_flags(user, auth_password, priv_password, context.agent_engine_id)
        + ["-t", "5", "-r", "1", _agent_addr(context), oid],
    )


@when(
    'snmpgetnext at authPriv with user "{user}", auth password "{auth_password}", and priv password "{priv_password}" queries OID "{oid}" from the agent'
)
def step_snmpgetnext_auth_priv(
    context: SnmpAgentContext,
    user: str,
    auth_password: str,
    priv_password: str,
    oid: str,
) -> None:
    _run_and_store(
        context,
        ["snmpgetnext"]
        + _auth_priv_flags(user, auth_password, priv_password, context.agent_engine_id)
        + ["-t", "5", "-r", "1", _agent_addr(context), oid],
    )


@when(
    'snmpbulkget at authPriv with user "{user}", auth password "{auth_password}", and priv password "{priv_password}", non-repeaters={non_repeaters:d} and max-repetitions={max_repetitions:d} queries OID "{oid}" from the agent'
)
def step_snmpbulkget_auth_priv(
    context: SnmpAgentContext,
    user: str,
    auth_password: str,
    priv_password: str,
    non_repeaters: int,
    max_repetitions: int,
    oid: str,
) -> None:
    _run_and_store(
        context,
        ["snmpbulkget"]
        + _auth_priv_flags(user, auth_password, priv_password, context.agent_engine_id)
        + [
            "-t",
            "5",
            "-r",
            "1",
            f"-Cn{non_repeaters}",
            f"-Cr{max_repetitions}",
            _agent_addr(context),
            oid,
        ],
    )


@when(
    'snmpget at authPriv without explicit engine ID with user "{user}", auth password "{auth_password}", and priv password "{priv_password}" queries OID "{oid}" from the agent'
)
def step_snmpget_auth_priv_no_engine_id(
    context: SnmpAgentContext,
    user: str,
    auth_password: str,
    priv_password: str,
    oid: str,
) -> None:
    # Omitting -e forces net-snmp to perform engine-ID discovery (RFC 3414 §4)
    # before sending the authenticated, encrypted GET. This exercises REQ-0080:
    # discovery must succeed regardless of the configured security level.
    _run_and_store(
        context,
        [
            "snmpget",
            "-v3",
            "-l",
            "authPriv",
            "-u",
            user,
            "-a",
            "SHA-256",
            "-A",
            auth_password,
            "-x",
            "AES",
            "-X",
            priv_password,
            "-On",
            "-t",
            "5",
            "-r",
            "1",
            _agent_addr(context),
            oid,
        ],
    )


@when(
    'snmpget at authPriv with wrong context engine ID "{context_engine_id}" with user "{user}", auth password "{auth_password}", and priv password "{priv_password}" queries OID "{oid}" from the agent'
)
def step_snmpget_auth_priv_wrong_context_engine_id(
    context: SnmpAgentContext,
    context_engine_id: str,
    user: str,
    auth_password: str,
    priv_password: str,
    oid: str,
) -> None:
    # -e (from _auth_priv_flags) sets the authoritative engine ID correctly;
    # -E sets the contextEngineID to a wrong value to trigger REQ-0104.
    _run_and_store(
        context,
        ["snmpget"]
        + _auth_priv_flags(user, auth_password, priv_password, context.agent_engine_id)
        + ["-E", context_engine_id, "-t", "2", "-r", "0", _agent_addr(context), oid],
    )
