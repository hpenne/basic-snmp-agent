from __future__ import annotations

from typing import Any, Protocol


class SnmpAgentContext(Protocol):
    """Typed Protocol for the Behave context object used in SNMP agent system tests.

    Declares all attributes set by environment hooks and step functions so that
    mypy can check attribute access without depending on Behave's own (untyped)
    context object.
    """

    # Set by before_all
    snmptrapd_container: str
    docker_network: str
    test_agent_image: str
    snmptrapd_image: str
    test_agent_mib_image: str
    test_agent_mib_auth_image: str
    test_agent_mib_auth_priv_image: str
    snmp_client_image: str

    # Set by before_scenario
    named_traps: dict[str, dict[str, Any]]
    extra_container_map: dict[str, str]
    extra_containers: list[str]
    temp_files: list[str]
    last_agent_output: str
    agent_container: str | None

    # Set by mib steps
    last_snmp_output: str
    last_snmp_returncode: int
    last_snmp_oid: str
    agent_engine_id: str

    # Behave built-in
    # Behave's Table type has no type stubs; expressing its full
    # row-iteration and string-key indexing API is not worthwhile.
    table: Any
