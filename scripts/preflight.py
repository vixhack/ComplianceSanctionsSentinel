"""Static Preflight Linter and Assertion Suite for ComplianceSanctionsSentinel.

Author: vix
Verifies contract structure, AST compliance, storage patterns, GenLayer decorators,
parsed host/IP SSRF defenses, redirect validation, authoritative regime provenance,
fail-closed handlers, and builder identity isolation.
"""

import ast
import os
import re
import sys

CONTRACT_FILE = os.path.join(
    os.path.dirname(__file__), "..", "contracts", "compliance_sanctions_sentinel.py"
)


def run_checks():
    print("--- Running Preflight Verification for ComplianceSanctionsSentinel ---")

    # 1. Existence and non-empty
    assert os.path.isfile(CONTRACT_FILE), f"Missing contract file: {CONTRACT_FILE}"
    with open(CONTRACT_FILE, "r", encoding="utf-8") as f:
        src = f.read()
    assert len(src.strip()) > 500, "Contract file unexpectedly small"

    # 2. AST parsing
    tree = ast.parse(src)

    # 3. Class definition and inheritance
    contract_classes = [
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ComplianceSanctionsSentinel"
    ]
    assert len(contract_classes) == 1, "Must declare class ComplianceSanctionsSentinel"
    contract_cls = contract_classes[0]

    # 4. Storage dataclasses
    dataclass_names = [
        node.name for node in tree.body
        if isinstance(node, ast.ClassDef) and any(
            (isinstance(d, ast.Name) and d.id == "allow_storage")
            or (isinstance(d, ast.Attribute) and d.attr == "allow_storage")
            for d in node.decorator_list
        )
    ]
    assert "TargetEntity" in dataclass_names, "TargetEntity must have @allow_storage"
    assert "ComplianceScreening" in dataclass_names, "ComplianceScreening must have @allow_storage"

    # 5. Storage annotations
    class_assigns = [n.target.id for n in contract_cls.body if isinstance(n, ast.AnnAssign)]
    assert "entities" in class_assigns, "Contract missing entities TreeMap"
    assert "screenings" in class_assigns, "Contract missing screenings TreeMap"
    assert "entity_count" in class_assigns, "Contract missing entity_count field"
    assert "screening_count" in class_assigns, "Contract missing screening_count field"

    # 6. Version string
    version_matches = re.findall(r'VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']', src)
    assert len(version_matches) == 1, "Must declare semantic VERSION"

    # 7. Public write decorators
    write_methods = []
    view_methods = []
    for node in contract_cls.body:
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Attribute) and dec.attr == "write":
                    write_methods.append(node.name)
                elif isinstance(dec, ast.Attribute) and dec.attr == "view":
                    view_methods.append(node.name)

    assert "register_entity" in write_methods, "register_entity must be @gl.public.write"
    assert "screen_entity" in write_methods, "screen_entity must be @gl.public.write"
    assert "update_sources" in write_methods, "update_sources must be @gl.public.write"
    assert "deactivate_entity" in write_methods, "deactivate_entity must be @gl.public.write"

    # 8. Public view decorators
    assert "get_entity" in view_methods, "get_entity must be @gl.public.view"
    assert "get_screening" in view_methods, "get_screening must be @gl.public.view"
    assert "latest_status" in view_methods, "latest_status must be @gl.public.view"
    assert "is_compliant" in view_methods, "is_compliant must be @gl.public.view"
    assert "is_sanctioned" in view_methods, "is_sanctioned must be @gl.public.view"
    assert "validate_equivalence" in view_methods, "validate_equivalence must be @gl.public.view"
    assert "get_entity_count" in view_methods, "get_entity_count must be @gl.public.view"
    assert "get_screening_count" in view_methods, "get_screening_count must be @gl.public.view"

    # 9. Bounds constants
    assert "MAX_NAME_LENGTH" in src, "Missing MAX_NAME_LENGTH bound"
    assert "MAX_JURISDICTION_LENGTH" in src, "Missing MAX_JURISDICTION_LENGTH bound"
    assert "MAX_IDENTIFIER_LENGTH" in src, "Missing MAX_IDENTIFIER_LENGTH bound"
    assert "MAX_URL_LENGTH" in src, "Missing MAX_URL_LENGTH bound"
    assert "MAX_EXCERPT_CHARS" in src, "Missing MAX_EXCERPT_CHARS bound"

    # 10. Parsed Host/IP and Network Safety Defenses
    assert "ipaddress" in src, "Must use ipaddress module for IP safety validation"
    assert "urllib.parse" in src, "Must use urllib.parse for URL decomposition"
    assert "_check_ip_safety" in src, "Missing _check_ip_safety helper"
    assert "is_private" in src, "Missing is_private IP check"
    assert "is_loopback" in src, "Missing is_loopback IP check"
    assert "is_reserved" in src, "Missing is_reserved IP check"
    assert "is_link_local" in src, "Missing is_link_local IP check"

    # 11. Authoritative Sanctions-Source Provenance
    assert "AUTHORITATIVE_REGIME_DOMAINS" in src, "Missing AUTHORITATIVE_REGIME_DOMAINS mapping"
    assert "OFAC" in src, "Missing OFAC regime"
    assert "UK_OFSI" in src, "Missing UK_OFSI regime"
    assert "EU_FSF" in src, "Missing EU_FSF regime"
    assert "SWISS_SECO" in src, "Missing SWISS_SECO regime"
    assert "UN" in src, "Missing UN regime"

    # 12. Redirect validation covering private/reserved destinations
    assert "status in (301, 302, 303, 307, 308)" in src, "Missing HTTP redirect status validation"
    assert "redirect_target" in src, "Missing redirect target resolution and validation"

    # 13. Equivalence principle call
    assert "gl.vm.run_nondet_unsafe" in src, "Must use gl.vm.run_nondet_unsafe"

    # 14. Fail-closed fallback
    assert "VERDICT_UNAVAILABLE" in src, "Missing VERDICT_UNAVAILABLE fail-closed branch"

    # 15. Registrar access control
    assert "gl.message.sender_address" in src, "Must verify gl.message.sender_address for access control"

    # 16. Builder identity isolation (Strictly vix, zero 9ytshade/Adewale)
    assert "Author: vix" in src, "Contract author header must be 'vix'"
    assert "9ytshade" not in src, "Fatal: Found trace of 9ytshade in vix contract!"
    assert "adewale" not in src.lower(), "Fatal: Found trace of Adewale in vix contract!"

    print("Preflight checks passed: 16/16 assertions verified.")


if __name__ == "__main__":
    run_checks()
