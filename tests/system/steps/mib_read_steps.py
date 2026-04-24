"""Behave step definitions for SNMP MIB read system tests.

The test-agent-mib container runs an agent pre-seeded with known MIB values.
Net-snmp CLI tools (snmpget, snmpgetnext, snmpbulkget) query the agent from
a snmp-client container on the same Docker bridge network.
"""

import subprocess
import time
import uuid

from behave import given, then, when

ENGINE_ID = "0x80001f8804746573742d6167656e742d6d6962"

# SNMPv3 noAuthNoPriv flags for net-snmp CLI tools.
# Net-snmp requires a non-empty security name even for noAuthNoPriv; the agent
# does not authenticate the username on the plain TCP path.
# -On prints OIDs in numeric form so step assertions can match on the dotted
# numeric string that appears in the feature file.
SNMPV3_FLAGS = ["-v3", "-l", "noAuthNoPriv", "-u", "noauth", "-On"]


def _snmp_client_run(context, snmp_cmd: list[str]) -> subprocess.CompletedProcess:
    """Run *snmp_cmd* inside a snmp-client container on the test network."""
    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", context.docker_network,
            context.snmp_client_image,
        ] + snmp_cmd,
        capture_output=True,
        text=True,
    )
    return result


def _agent_addr(context) -> str:
    return f"tcp:{context.agent_container}:10161"


def _start_agent_container(context, name_prefix: str, image: str, ready_sentinel: str) -> str:
    """Start a test-agent container on the test network and wait for it to signal readiness.

    Polls docker logs rather than using a fixed sleep so the step returns as
    soon as the agent is ready. This is faster on fast machines and more
    reliable on slow CI.
    """
    container_name = f"{name_prefix}-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker", "run", "--rm", "-d",
            "--name", container_name,
            "--network", context.docker_network,
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
        )
        if ready_sentinel in logs.stdout + logs.stderr:
            return container_name
        time.sleep(0.2)
    raise AssertionError(
        f"container {container_name!r} did not signal readiness within 10 seconds"
    )


@given('a test-agent-mib instance is running with engine ID "{engine_id}"')
def step_start_test_agent_mib(context, engine_id):
    context.agent_container = _start_agent_container(
        context, "test-agent-mib", context.test_agent_mib_image, "test-agent-mib ready"
    )
    context.agent_engine_id = engine_id


@when('snmpget queries OID "{oid}" from the agent')
def step_snmpget(context, oid):
    result = _snmp_client_run(
        context,
        ["snmpget"]
        + SNMPV3_FLAGS
        + ["-e", context.agent_engine_id, _agent_addr(context), oid],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode
    context.last_snmp_oid = oid


@when('snmpgetnext queries OID "{oid}" from the agent')
def step_snmpgetnext(context, oid):
    result = _snmp_client_run(
        context,
        ["snmpgetnext"]
        + SNMPV3_FLAGS
        + ["-e", context.agent_engine_id, _agent_addr(context), oid],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


@when('snmpbulkget with non-repeaters={non_repeaters:d} and max-repetitions={max_repetitions:d} queries OID "{oid}" from the agent')
def step_snmpbulkget(context, non_repeaters, max_repetitions, oid):
    result = _snmp_client_run(
        context,
        ["snmpbulkget"]
        + SNMPV3_FLAGS
        + [
            "-e", context.agent_engine_id,
            f"-Cn{non_repeaters}",
            f"-Cr{max_repetitions}",
            _agent_addr(context),
            oid,
        ],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


@when('snmpget with wrong engine ID "{engine_id}" queries OID "{oid}" from the agent')
def step_snmpget_wrong_engine_id(context, engine_id, oid):
    result = _snmp_client_run(
        context,
        ["snmpget"]
        + SNMPV3_FLAGS
        + ["-e", engine_id, "-t", "2", "-r", "0", _agent_addr(context), oid],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


@when('snmpget with context name "{context_name}" queries OID "{oid}" from the agent')
def step_snmpget_with_context_name(context, context_name, oid):
    result = _snmp_client_run(
        context,
        ["snmpget"]
        + SNMPV3_FLAGS
        + [
            "-e", context.agent_engine_id,
            "-n", context_name,
            "-t", "2", "-r", "0",
            _agent_addr(context),
            oid,
        ],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


@when('snmpget without explicit engine ID queries OID "{oid}" from the agent')
def step_snmpget_no_engine_id(context, oid):
    # Other steps pass -e to skip discovery. Omitting it here forces net-snmp to
    # perform engine-ID discovery (RFC 3414 §4) before the actual GET.
    result = _snmp_client_run(
        context,
        ["snmpget"] + SNMPV3_FLAGS + ["-t", "5", "-r", "1",
         _agent_addr(context), oid],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


@then('the SNMP response contains OID "{oid}" with string value "{value}"')
def step_response_contains_oid_with_value(context, oid, value):
    output = context.last_snmp_output
    assert oid in output, f"OID {oid!r} not found in output:\n{output}"
    assert value in output, f"Value {value!r} not found in output:\n{output}"


@then('the SNMP response contains OID "{oid}" with exception "{exception}"')
def step_response_contains_oid_with_exception(context, oid, exception):
    output = context.last_snmp_output
    assert oid in output, f"OID {oid!r} not found in output:\n{output}"
    assert exception in output, f"Exception {exception!r} not found in output:\n{output}"


@then('the SNMP response contains exception "{exception}"')
def step_response_contains_exception(context, exception):
    output = context.last_snmp_output
    assert exception in output, f"Exception {exception!r} not found in output:\n{output}"


@then('the SNMP response contains OID "{oid}"')
def step_response_contains_oid(context, oid):
    output = context.last_snmp_output
    assert oid in output, f"OID {oid!r} not found in output:\n{output}"


@then('the SNMP response does not contain OID "{oid}"')
def step_response_not_contains_oid(context, oid):
    output = context.last_snmp_output
    assert oid not in output, f"OID {oid!r} unexpectedly found in output:\n{output}"


@when('snmpset queries OID "{oid}" with string value "{value}" from the agent')
def step_snmpset(context, oid, value):
    result = _snmp_client_run(
        context,
        ["snmpset"]
        + SNMPV3_FLAGS
        + ["-e", context.agent_engine_id, _agent_addr(context), oid, "s", value],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


@then('the SNMP response contains error "{error}"')
def step_response_contains_error(context, error):
    output = context.last_snmp_output
    assert error in output, f"Error {error!r} not found in output:\n{output}"


@then('the SNMP request times out or returns an error')
def step_request_times_out_or_error(context):
    output = context.last_snmp_output
    returncode = context.last_snmp_returncode
    assert returncode != 0 or "Timeout" in output, (
        f"Expected timeout or non-zero exit code, but got returncode={returncode} "
        f"and output:\n{output}"
    )


@given('a test-agent-mib-auth instance is running with engine ID "{engine_id}"')
def step_start_test_agent_mib_auth(context, engine_id):
    context.agent_container = _start_agent_container(
        context, "test-agent-mib-auth", context.test_agent_mib_auth_image, "test-agent-mib-auth ready"
    )
    context.agent_engine_id = engine_id


def _auth_no_priv_flags(user: str, password: str, engine_id: str) -> list[str]:
    # SNMPv3 authNoPriv flags: HMAC-SHA-256 authentication, no privacy encryption.
    # -u sets the security name, -a the auth protocol, -A the auth passphrase,
    # -e the authoritative engine ID, -On prints OIDs in numeric form.
    return [
        "-v3", "-l", "authNoPriv",
        "-u", user,
        "-a", "SHA-256", "-A", password,
        "-e", engine_id,
        "-On",
    ]


@when('snmpget at authNoPriv with user "{user}" and password "{password}" queries OID "{oid}" from the agent')
def step_snmpget_auth_no_priv(context, user, password, oid):
    result = _snmp_client_run(
        context,
        ["snmpget"]
        + _auth_no_priv_flags(user, password, context.agent_engine_id)
        + ["-t", "5", "-r", "1", _agent_addr(context), oid],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


@when('snmpgetnext at authNoPriv with user "{user}" and password "{password}" queries OID "{oid}" from the agent')
def step_snmpgetnext_auth_no_priv(context, user, password, oid):
    result = _snmp_client_run(
        context,
        ["snmpgetnext"]
        + _auth_no_priv_flags(user, password, context.agent_engine_id)
        + ["-t", "5", "-r", "1", _agent_addr(context), oid],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


@when('snmpbulkget at authNoPriv with user "{user}" and password "{password}", non-repeaters={non_repeaters:d} and max-repetitions={max_repetitions:d} queries OID "{oid}" from the agent')
def step_snmpbulkget_auth_no_priv(context, user, password, non_repeaters, max_repetitions, oid):
    result = _snmp_client_run(
        context,
        ["snmpbulkget"]
        + _auth_no_priv_flags(user, password, context.agent_engine_id)
        + [
            "-t", "5", "-r", "1",
            f"-Cn{non_repeaters}",
            f"-Cr{max_repetitions}",
            _agent_addr(context),
            oid,
        ],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


@when('snmpget at authNoPriv without explicit engine ID with user "{user}" and password "{password}" queries OID "{oid}" from the agent')
def step_snmpget_auth_no_priv_no_engine_id(context, user, password, oid):
    # Omitting -e forces net-snmp to perform engine-ID discovery (RFC 3414 §4)
    # before sending the authenticated GET. This exercises REQ-0080: discovery
    # must succeed regardless of the configured security level.
    result = _snmp_client_run(
        context,
        ["snmpget", "-v3", "-l", "authNoPriv", "-u", user, "-a", "SHA-256", "-A", password,
         "-On", "-t", "5", "-r", "1", _agent_addr(context), oid],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode


@when('snmpget at noAuthNoPriv with user "{user}" queries OID "{oid}" from the agent')
def step_snmpget_no_auth_no_priv(context, user, oid):
    # Short timeout with no retries: the agent rejects this request immediately,
    # so there is no need to wait for the default retry window.
    result = _snmp_client_run(
        context,
        ["snmpget", "-v3", "-l", "noAuthNoPriv", "-u", user, "-On",
         "-e", context.agent_engine_id, "-t", "2", "-r", "0",
         _agent_addr(context), oid],
    )
    context.last_snmp_output = result.stdout + result.stderr
    context.last_snmp_returncode = result.returncode
