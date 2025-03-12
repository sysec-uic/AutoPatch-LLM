# assets/create-docker-network.py
# This script idempotently creates a supporting docker network for the autopatch-llm project.
# and is not strictly a component of the application but rather a network as code defintion
# to be used by the docker-compose.yml file.
#
# Before we have gitops this is one way to to define networks as code
import subprocess

NETWORK_NAME = "autopatch-llm_autopatch-docker-network"


def network_exists(name):
    result = subprocess.run(
        ["docker", "network", "inspect", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def create_network(name):
    subprocess.run(["docker", "network", "create", name], check=True)


if network_exists(NETWORK_NAME):
    print(f"Docker network '{NETWORK_NAME}' already exists.")
else:
    print(f"Creating Docker network '{NETWORK_NAME}'...")
    create_network(NETWORK_NAME)
