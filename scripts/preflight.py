"""Static Preflight Linter and Assertion Suite for ComplianceSanctionsSentinel.

Author: vix
Verifies contract structure, AST compliance, storage patterns, GenLayer decorators,
SSRF defenses, equivalence logic, fail-closed handlers, and builder identity isolation.
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

    # 10. SSRF defense patterns
    ssrf_tokens = ["://localhost", "://127.0.0.1", "://169.254.169.254", "://10.", ".internal", ".local"]
    for token in ssrf_tokens:
        assert token in src, f"SSRF protection missing token: {token}"

    # 11. Equivalence principle call
    assert "gl.vm.run_nondet_unsafe" in src, "Must use gl.vm.run_nondet_unsafe"

    # 12. Fail-closed fallback
    assert "VERDICT_UNAVAILABLE" in src, "Missing VERDICT_UNAVAILABLE fail-closed branch"

    # 13. Registrar access control
    assert "gl.message.sender_address" in src, "Must verify gl.message.sender_address for access control"

    # 14. Monotonic counter tracking
    assert "self.entity_count += u256(1)" in src, "Must increment entity_count sequentially"
    assert "self.screening_count += u32(1)" in src, "Must increment screening_count sequentially"

    # 15. Downstream boolean clearance gates
    assert "def is_compliant" in src, "Missing is_compliant gate"
    assert "def is_sanctioned" in src, "Missing is_sanctioned gate"

    # 16. Builder identity isolation (Strictly vix, zero 9ytshade/Adewale)
    assert "Author: vix" in src, "Contract author header must be 'vix'"
    assert "9ytshade" not in src, "Fatal: Found trace of 9ytshade in vix contract!"
    assert "adewale" not in src.lower(), "Fatal: Found trace of Adewale in vix contract!"

    print("Preflight checks passed: 16/16 assertions verified.")


if __name__ == "__main__":
    run_checks()
