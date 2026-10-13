"""Studionet Integration Tests for ComplianceSanctionsSentinel v1.0.1.

Author: vix
Verifies canonical deployment and live on-chain consensus state on GenLayer Studionet (Chain ID 61999).
Canonical Contract Address: 0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53
Deployer Address: 0xb3b09558183aec6c2ff5aa547163b77a9266010a
"""

import subprocess
import urllib.request
import json
import re
import pytest

CANONICAL_ADDRESS = "0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53"
DEPLOYER_ADDRESS = "0xb3b09558183aec6c2ff5aa547163b77a9266010a"
RPC_URL = "https://studio.genlayer.com/api"


def rpc_call(method: str, params: list):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        RPC_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ComplianceIntegration/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        if "error" in res:
            raise RuntimeError(f"RPC Error: {res['error']}")
        return res.get("result")


def genlayer_call(method: str, *args):
    """Invoke contract view method via genlayer CLI and parse output."""
    cmd = ["genlayer.cmd", "call", CANONICAL_ADDRESS, method, "--rpc", RPC_URL]
    if args:
        cmd.extend(["--args"] + [str(a) for a in args])

    res = subprocess.run(
        cmd,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        shell=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"genlayer call failed: {res.stderr}\n{res.stdout}")

    match = re.search(r"Result:\s*\n(.*?)(?:\n\n√|\Z)", res.stdout, re.DOTALL)
    if not match:
        raise ValueError(f"Could not parse result from: {res.stdout}")

    raw = match.group(1).strip()
    if raw == "true":
        return True
    if raw == "false":
        return False
    if raw.isdigit():
        return int(raw)

    # If the output is a JS object or array representation, parse it into JSON
    if (raw.startswith("{") and raw.endswith("}")) or (raw.startswith("[") and raw.endswith("]")):
        node_script = "const obj = eval('(' + process.argv[1] + ')'); console.log(JSON.stringify(obj));"
        node_res = subprocess.run(
            ["node", "-e", node_script, raw],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
        if node_res.returncode == 0:
            return json.loads(node_res.stdout)

    return raw


def test_canonical_contract_schema_on_studionet():
    """Verify the deployed contract exposes the expected method schema on Studionet."""
    schema = rpc_call("gen_getContractSchema", [CANONICAL_ADDRESS])
    assert schema is not None, "Contract schema must exist"
    methods = schema.get("methods", {})

    expected_methods = [
        "register_entity",
        "screen_entity",
        "update_sources",
        "deactivate_entity",
        "get_entity",
        "get_screening",
        "latest_status",
        "is_compliant",
        "is_sanctioned",
        "validate_equivalence",
        "get_entity_count",
        "get_screening_count",
    ]
    for m in expected_methods:
        assert m in methods, f"Missing method {m} in deployed Studionet schema"


def test_studionet_entity_state():
    """Verify that entity #1 exists on Studionet with valid registered state."""
    entity = genlayer_call("get_entity", 1)
    assert isinstance(entity, dict), f"Expected dict for entity, got {type(entity)}"
    assert entity["id"] == 1
    assert "Ethereum Foundation" in entity["name"]
    assert entity["jurisdiction"] == "Switzerland"
    assert entity["identifier"] == "CHE-497.042.846"
    assert entity["regulatory_regime"] == "SWISS_SECO"
    assert entity["registrar"].lower() == DEPLOYER_ADDRESS.lower()
    assert entity["active"] is True
    assert "Python.gitignore" in entity["source_urls_json"]


def test_studionet_screening_receipt():
    """Verify that screening receipt #1 exists and reflects consensus evaluation."""
    sc = genlayer_call("get_screening", 1)
    assert isinstance(sc, dict), f"Expected dict for screening, got {type(sc)}"
    assert sc["id"] == 1
    assert sc["entity_id"] == 1
    assert sc["verdict"] == "INVESTIGATION_PENDING"
    assert sc["match_confidence"] == 0
    assert sc["sources_checked"] == 1
    assert len(sc["regulatory_notes"]) > 20


def test_studionet_downstream_compliance_gates():
    """Verify downstream clearance gates against live consensus screening receipt."""
    sc = genlayer_call("get_screening", 1)
    verdict, confidence = genlayer_call("latest_status", 1)

    assert verdict == sc["verdict"]
    assert confidence == sc["match_confidence"]

    # Inconclusive/non-responsive evidence must fail-closed:
    assert genlayer_call("is_compliant", 1) is False
    assert genlayer_call("is_sanctioned", 1) is False


def test_studionet_read_bounds_and_safety():
    """Verify total counts on canonical contract."""
    e_count = genlayer_call("get_entity_count")
    sc_count = genlayer_call("get_screening_count")
    assert isinstance(e_count, int)
    assert e_count >= 1
    assert isinstance(sc_count, int)
    assert sc_count >= 1
