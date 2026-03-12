"""Behave environment hooks for the SNMP trap system tests.

Lifecycle:
- before_all:     Build Docker images; start the primary snmptrapd container.
- before_scenario: Clear the trap store inside the primary container so each
                   scenario starts with an empty record; initialise per-scenario
                   context fields.
- after_scenario:  Stop any extra containers started by scenario steps; remove
                   temp files.
- after_all:       Tear down all Compose services.
"""

import os
import subprocess
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))

COMPOSE_FILE = os.path.join(_HERE, "docker-compose.yml")
PROJECT_NAME = os.environ.get("COMPOSE_PROJECT_NAME", "snmp-test")

# Container name assigned by Compose: <project>-<service>-<replica>.
SNMPTRAPD_CONTAINER = os.environ.get(
    "SNMPTRAPD_CONTAINER", f"{PROJECT_NAME}-snmptrapd-1"
)

# Docker network created by Compose: <project>_<network-name>.
DOCKER_NETWORK = f"{PROJECT_NAME}_snmp-test"

TEST_AGENT_IMAGE = "test-agent-test"
SNMPTRAPD_IMAGE = "snmptrapd-test"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compose(*args: str) -> list[str]:
    return ["docker", "compose", "-f", COMPOSE_FILE, "-p", PROJECT_NAME, *args]


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

def before_all(context):
    subprocess.run(_compose("build"), check=True)
    subprocess.run(_compose("up", "-d", "snmptrapd"), check=True)
    # Allow snmptrapd time to bind its UDP socket before tests send traps.
    time.sleep(2)

    context.snmptrapd_container = SNMPTRAPD_CONTAINER
    context.docker_network = DOCKER_NETWORK
    context.test_agent_image = TEST_AGENT_IMAGE
    context.snmptrapd_image = SNMPTRAPD_IMAGE


def before_scenario(context, scenario):
    # Clear the trap record file so each scenario starts with an empty store.
    subprocess.run(
        [
            "docker", "exec", context.snmptrapd_container,
            "sh", "-c", "rm -f /traps/received.jsonl",
        ],
        check=False,
        capture_output=True,
    )
    # named_traps: maps scenario-assigned trap name -> parsed trap record dict.
    context.named_traps = {}
    # extra_container_map: maps scenario-assigned receiver name -> container name.
    context.extra_container_map = {}
    context.extra_containers = []
    context.temp_files = []
    context.last_agent_output = ""


def after_scenario(context, scenario):
    for name in context.extra_containers:
        subprocess.run(["docker", "stop", name], check=False, capture_output=True)
    for path in context.temp_files:
        try:
            os.unlink(path)
        except OSError:
            pass


def after_all(context):
    subprocess.run(
        _compose("down", "--remove-orphans"), check=False, capture_output=True
    )
