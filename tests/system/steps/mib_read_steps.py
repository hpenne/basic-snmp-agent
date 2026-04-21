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


@given('a test-agent-mib instance is running with engine ID "{engine_id}"')
def step_start_test_agent_mib(context, engine_id):
    container_name = f"test-agent-mib-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker", "run", "--rm", "-d",
            "--name", container_name,
            "--network", context.docker_network,
            context.test_agent_mib_image,
        ],
        check=True,
        capture_output=True,
    )
    context.agent_container = container_name
    context.agent_engine_id = engine_id

    # Poll docker logs until the agent signals readiness, rather than using a
    # fixed sleep. This is faster on fast machines and more reliable on slow CI.
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        logs = subprocess.run(
            ["docker", "logs", container_name],
            capture_output=True,
            text=True,
        )
        if "test-agent-mib ready" in logs.stdout + logs.stderr:
            return
        time.sleep(0.2)
    raise AssertionError(
        f"test-agent-mib container {container_name!r} did not signal readiness "
        "within 10 seconds"
    )


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
