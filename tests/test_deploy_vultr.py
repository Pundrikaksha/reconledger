from pathlib import Path
import re
import pytest

COMPOSE_FILE = Path(__file__).resolve().parents[1] / "deploy" / "vultr" / "docker-compose.yml"


def _parse_compose_text(text: str) -> dict:
    """Lightweight text parser for docker-compose services and networks."""
    services: dict[str, dict] = {}
    networks: dict[str, dict] = {}
    current_section = None
    current_item = None
    current_sub = None

    for line in text.splitlines():
        clean = line.split("#", 1)[0].rstrip()
        if not clean:
            continue
        indent = len(clean) - len(clean.lstrip())
        stripped = clean.strip()

        if indent == 0 and stripped.endswith(":"):
            current_section = stripped[:-1]
            current_item = None
            current_sub = None
            continue

        if current_section == "services":
            if indent == 2 and stripped.endswith(":"):
                current_item = stripped[:-1]
                services[current_item] = {"networks": {}}
                current_sub = None
            elif indent == 4 and current_item:
                if stripped.startswith("ports:"):
                    services[current_item]["ports"] = []
                elif stripped.startswith("networks:"):
                    current_sub = "networks"
                else:
                    current_sub = None
            elif indent == 6 and current_item and current_sub == "networks":
                net_name = stripped.rstrip(":")
                services[current_item]["networks"][net_name] = {}

        elif current_section == "networks":
            if indent == 2 and stripped.endswith(":"):
                current_item = stripped[:-1]
                networks[current_item] = {}
            elif indent == 4 and current_item:
                if ":" in stripped:
                    k, v = stripped.split(":", 1)
                    val = v.strip().lower()
                    if val == "true":
                        parsed_val = True
                    elif val == "false":
                        parsed_val = False
                    else:
                        parsed_val = v.strip()
                    networks[current_item][k.strip()] = parsed_val

    return {"services": services, "networks": networks}


def test_vultr_docker_compose_isolation():
    """Verify isolation guarantees in deploy/vultr/docker-compose.yml using text parsing."""
    assert COMPOSE_FILE.exists(), f"missing compose file at {COMPOSE_FILE}"
    content = COMPOSE_FILE.read_text(encoding="utf-8")
    data = _parse_compose_text(content)

    # juice-shop has no ports, attached only to sandbox-lab
    assert "juice-shop" in data["services"]
    assert "ports" not in data["services"]["juice-shop"]
    assert list(data["services"]["juice-shop"]["networks"].keys()) == ["sandbox-lab"]

    # dvwa has no ports, attached only to sandbox-lab
    assert "dvwa" in data["services"]
    assert "ports" not in data["services"]["dvwa"]
    assert list(data["services"]["dvwa"]["networks"].keys()) == ["sandbox-lab"]

    # control has no published ports
    assert "control" in data["services"]
    assert "ports" not in data["services"]["control"]

    # sandbox-lab network is internal with name reconledger-lab
    assert "sandbox-lab" in data["networks"]
    assert data["networks"]["sandbox-lab"].get("internal") is True
    assert data["networks"]["sandbox-lab"].get("name") == "reconledger-lab"


def test_vultr_docker_compose_yaml_if_installed():
    """Verify isolation guarantees with PyYAML if available."""
    yaml = pytest.importorskip("yaml")
    content = COMPOSE_FILE.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    assert "ports" not in data["services"]["juice-shop"]
    assert list(data["services"]["juice-shop"]["networks"].keys()) == ["sandbox-lab"]

    assert "ports" not in data["services"]["dvwa"]
    assert list(data["services"]["dvwa"]["networks"].keys()) == ["sandbox-lab"]

    assert "ports" not in data["services"]["control"]

    assert data["networks"]["sandbox-lab"]["internal"] is True
    assert data["networks"]["sandbox-lab"]["name"] == "reconledger-lab"


def test_vultr_docker_compose_env_safety():
    """Verify Caddy only gets RECONLEDGER_DOMAIN and control gets DOCKER_CONFIG."""
    content = COMPOSE_FILE.read_text(encoding="utf-8")
    assert "RECONLEDGER_DOMAIN=${RECONLEDGER_DOMAIN:?set RECONLEDGER_DOMAIN in deploy/vultr/.env}" in content
    assert "DOCKER_CONFIG=/tmp/.docker" in content
    # Caddy should not have env_file
    caddy_section = content.split("caddy:", 1)[1].split("control:", 1)[0]
    assert "env_file:" not in caddy_section


def test_vultr_docker_compose_yaml_env_safety():
    """Verify compose env safety using PyYAML if available."""
    yaml = pytest.importorskip("yaml")
    content = COMPOSE_FILE.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    caddy_svc = data["services"]["caddy"]
    assert "env_file" not in caddy_svc
    assert any("RECONLEDGER_DOMAIN" in env for env in caddy_svc.get("environment", []))

    control_svc = data["services"]["control"]
    assert any("DOCKER_CONFIG=/tmp/.docker" in env for env in control_svc.get("environment", []))


def test_vultr_dockerfile_control_editable_and_config():
    """Verify Dockerfile.control uses editable install for rule resolution and writable docker config."""
    dockerfile = COMPOSE_FILE.parents[0] / "Dockerfile.control"
    content = dockerfile.read_text(encoding="utf-8")
    assert 'pip install --no-cache-dir -e ".[web]"' in content
    assert "ENV DOCKER_CONFIG=/tmp/.docker" in content


def test_vultr_cloud_init():
    """Verify cloud-init creates a 2 GB swapfile and conditionally adds ubuntu to docker group."""
    cloud_init = COMPOSE_FILE.parents[0] / "cloud-init.yaml"
    content = cloud_init.read_text(encoding="utf-8")
    assert "fallocate -l 2G /swapfile" in content
    assert "mkswap /swapfile" in content
    assert "swapon /swapfile" in content
    assert "/swapfile none swap sw 0 0" in content
    assert "id ubuntu >/dev/null 2>&1 && usermod -aG docker ubuntu || true" in content


def test_vultr_makefile():
    """Verify Makefile uses bash with pipefail and runs demo-containment without TTY."""
    makefile = COMPOSE_FILE.parents[0] / "Makefile"
    content = makefile.read_text(encoding="utf-8")
    assert "SHELL := /bin/bash" in content
    assert ".SHELLFLAGS := -o pipefail -c" in content
    assert "exec -T control reconledger demo-containment 2>&1 | tee" in content


def test_vultr_gitignore():
    """Verify deploy/vultr/out/ is ignored."""
    gitignore = COMPOSE_FILE.parents[2] / ".gitignore"
    content = gitignore.read_text(encoding="utf-8")
    assert "deploy/vultr/out/" in content

