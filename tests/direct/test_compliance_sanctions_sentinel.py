"""Direct Mode Adversarial Test Suite for ComplianceSanctionsSentinel v1.0.1.

Author: vix
Comprehensive unit test suite for regulatory sanctions screening, entity disambiguation,
discrete canonical confidence buckets (100 vs 0), SSRF defense, fail-closed handling,
and downstream compliance clearance gates under the Equivalence Principle.
"""

import json
import pytest

CONTRACT_PATH = "contracts/compliance_sanctions_sentinel.py"


def deploy_contract(direct_deploy):
    return direct_deploy(CONTRACT_PATH)


def test_deployment_initial_state(direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    assert contract.get_entity_count() == 0
    assert contract.get_screening_count() == 0


def test_register_entity_success(direct_vm, direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = [
        "https://companieshouse.gov.uk/company/12345678",
        "https://sanctionssearch.ofac.treas.gov/details/12345678",
    ]
    entity_id = contract.register_entity(
        name="Apex Trading Technologies Ltd",
        jurisdiction="United Kingdom",
        identifier="CRN-12345678",
        source_urls_json=json.dumps(urls),
        regulatory_regime="UK_OFSI",
    )
    assert entity_id == 1
    assert contract.get_entity_count() == 1

    entity = contract.get_entity(1)
    assert entity["id"] == 1
    assert entity["name"] == "Apex Trading Technologies Ltd"
    assert entity["jurisdiction"] == "United Kingdom"
    assert entity["identifier"] == "CRN-12345678"
    assert entity["regulatory_regime"] == "UK_OFSI"
    assert entity["status"] == "PENDING"
    assert entity["active"] is True
    assert entity["latest_screening_id"] == 0
    assert entity["total_screenings"] == 0
    stored_urls = json.loads(entity["source_urls_json"])
    assert len(stored_urls) == 2


def test_register_entity_bounds_validation(direct_vm, direct_deploy):
    contract = deploy_contract(direct_deploy)
    valid_urls = json.dumps(["https://registry.gov/entity.html"])

    # Name too short (<2)
    with direct_vm.expect_revert("Entity name length out of bounds"):
        contract.register_entity("A", "UK", "ID123", valid_urls)

    # Name too long (>128)
    with direct_vm.expect_revert("Entity name length out of bounds"):
        contract.register_entity("A" * 129, "UK", "ID123", valid_urls)

    # Jurisdiction too short (<2)
    with direct_vm.expect_revert("Jurisdiction length out of bounds"):
        contract.register_entity("Valid Name", "U", "ID123", valid_urls)

    # Jurisdiction too long (>64)
    with direct_vm.expect_revert("Jurisdiction length out of bounds"):
        contract.register_entity("Valid Name", "U" * 65, "ID123", valid_urls)

    # Identifier too short (<2)
    with direct_vm.expect_revert("Identifier length out of bounds"):
        contract.register_entity("Valid Name", "UK", "I", valid_urls)

    # Identifier too long (>64)
    with direct_vm.expect_revert("Identifier length out of bounds"):
        contract.register_entity("Valid Name", "UK", "I" * 65, valid_urls)

    # Invalid JSON in source_urls_json
    with direct_vm.expect_revert("source_urls_json must be valid JSON array"):
        contract.register_entity("Valid Name", "UK", "ID123", "{bad json}")

    # Not a list
    with direct_vm.expect_revert("source_urls_json must be a JSON array of strings"):
        contract.register_entity("Valid Name", "UK", "ID123", json.dumps({"url": "https://a.com"}))

    # Empty list (<1)
    with direct_vm.expect_revert("Source URL count must be between 1 and 5"):
        contract.register_entity("Valid Name", "UK", "ID123", json.dumps([]))

    # More than 5 URLs
    with direct_vm.expect_revert("Source URL count must be between 1 and 5"):
        contract.register_entity("Valid Name", "UK", "ID123", json.dumps([f"https://a.com/{i}" for i in range(6)]))

    # Non-string URL element
    with direct_vm.expect_revert("All source URLs must be strings"):
        contract.register_entity("Valid Name", "UK", "ID123", json.dumps(["https://a.com", 999]))


def test_register_entity_invalid_url_and_ssrf(direct_vm, direct_deploy):
    contract = deploy_contract(direct_deploy)

    def test_ssrf(bad_url, err_msg):
        with direct_vm.expect_revert(err_msg):
            contract.register_entity(
                "Probe Co",
                "US",
                "ID001",
                json.dumps([bad_url]),
            )

    test_ssrf("http://insecure.com/registry", "Only secure HTTPS URLs are permitted")
    test_ssrf("https://localhost/admin", "Prohibited host or IP in URL")
    test_ssrf("https://127.0.0.1/status", "Prohibited host or IP in URL")
    test_ssrf("https://169.254.169.254/metadata", "Prohibited host or IP in URL")
    test_ssrf("https://10.0.0.1/internal", "Prohibited host or IP in URL")
    test_ssrf("https://192.168.1.1/secrets", "Prohibited host or IP in URL")
    test_ssrf("https://172.16.1.1/keys", "Prohibited host or IP in URL")
    test_ssrf("https://gateway.internal/api", "Prohibited host or IP in URL")
    test_ssrf("https://server.local/health", "Prohibited host or IP in URL")


def test_screen_entity_cleared_discrete_confidence_100(direct_vm, direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = ["https://official-registry.gov/entity/apex-trading.html"]
    entity_id = contract.register_entity(
        name="Apex Trading Technologies Ltd",
        jurisdiction="United Kingdom",
        identifier="CRN-12345678",
        source_urls_json=json.dumps(urls),
    )

    # Mock web response with official regulatory registry
    direct_vm.mock_web(
        r"official-registry\.gov/.*",
        {
            "status": 200,
            "body": "Apex Trading Technologies Ltd (CRN-12345678) is registered in the United Kingdom. Status: Active, Good Standing. No sanctions, enforcement, or winding-up orders found.",
        },
    )

    # Mock validator LLM response
    llm_payload = json.dumps({
        "verdict": "CLEARED",
        "regulatory_notes": "Official registry confirms active status in good standing with zero active sanctions or enforcement actions.",
    })
    direct_vm.mock_llm(r".*", llm_payload)

    screening_id = contract.screen_entity(entity_id)
    assert screening_id == 1
    assert contract.get_screening_count() == 1

    entity = contract.get_entity(entity_id)
    assert entity["status"] == "CLEARED"
    assert entity["latest_screening_id"] == 1
    assert entity["total_screenings"] == 1

    sc = contract.get_screening(screening_id)
    assert sc["verdict"] == "CLEARED"
    assert sc["match_confidence"] == 100  # Discrete canonical confidence
    assert sc["sources_checked"] == 1

    # Check downstream gates
    assert contract.is_compliant(entity_id) is True
    assert contract.is_sanctioned(entity_id) is False
    assert contract.latest_status(entity_id) == ("CLEARED", 100)


def test_screen_entity_sanctioned_discrete_confidence_100(direct_vm, direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = ["https://sanctions-gazette.gov/orders/designations.html"]
    entity_id = contract.register_entity(
        name="Volga Strategic Metals CJSC",
        jurisdiction="Russian Federation",
        identifier="INN-7701234567",
        source_urls_json=json.dumps(urls),
        regulatory_regime="OFAC",
    )

    direct_vm.mock_web(
        r"sanctions-gazette\.gov/.*",
        {
            "status": 200,
            "body": "Official Designation Order: Volga Strategic Metals CJSC (INN-7701234567) is designated under Executive Sanctions Order 14024. All assets subject to blocking freeze.",
        },
    )

    llm_payload = json.dumps({
        "verdict": "SANCTIONED",
        "regulatory_notes": "Entity matches official designation order INN-7701234567 subject to full blocking asset freeze.",
    })
    direct_vm.mock_llm(r".*", llm_payload)

    screening_id = contract.screen_entity(entity_id)
    assert screening_id == 1

    entity = contract.get_entity(entity_id)
    assert entity["status"] == "SANCTIONED"

    sc = contract.get_screening(screening_id)
    assert sc["verdict"] == "SANCTIONED"
    assert sc["match_confidence"] == 100  # Discrete canonical confidence

    # Downstream gates
    assert contract.is_compliant(entity_id) is False
    assert contract.is_sanctioned(entity_id) is True
    assert contract.latest_status(entity_id) == ("SANCTIONED", 100)


def test_screen_entity_investigation_pending_disambiguation(direct_vm, direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = ["https://enforcement-bulletin.org/cases/search.html"]
    entity_id = contract.register_entity(
        name="Global Maritime Logistics",
        jurisdiction="Singapore",
        identifier="UEN-201912345A",
        source_urls_json=json.dumps(urls),
    )

    # Evidence names an entity in a different jurisdiction with similar name
    direct_vm.mock_web(
        r"enforcement-bulletin\.org/.*",
        {
            "status": 200,
            "body": "Enforcement Notice: Global Maritime Logistics Corp (Panama Reg: 987654) sanctioned for illicit transshipments.",
        },
    )

    llm_payload = json.dumps({
        "verdict": "INVESTIGATION_PENDING",
        "regulatory_notes": "Name similarity detected with Panama entity, but target is registered in Singapore. Disambiguation pending manual review.",
    })
    direct_vm.mock_llm(r".*", llm_payload)

    screening_id = contract.screen_entity(entity_id)
    entity = contract.get_entity(entity_id)
    assert entity["status"] == "INVESTIGATION_PENDING"

    sc = contract.get_screening(screening_id)
    assert sc["verdict"] == "INVESTIGATION_PENDING"
    assert sc["match_confidence"] == 0  # Discrete canonical confidence

    assert contract.is_compliant(entity_id) is False
    assert contract.is_sanctioned(entity_id) is False
    assert contract.latest_status(entity_id) == ("INVESTIGATION_PENDING", 0)


def test_screen_entity_unreachable_fails_closed(direct_vm, direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = ["https://offline-registry.gov/lookup.html"]
    entity_id = contract.register_entity(
        name="Offline Corporate Target",
        jurisdiction="Delaware, US",
        identifier="DE-998877",
        source_urls_json=json.dumps(urls),
    )

    direct_vm.mock_web(
        r"offline-registry\.gov/.*",
        {"status": 503, "body": "Service Unavailable"},
    )

    screening_id = contract.screen_entity(entity_id)
    entity = contract.get_entity(entity_id)
    assert entity["status"] == "UNAVAILABLE"

    sc = contract.get_screening(screening_id)
    assert sc["verdict"] == "UNAVAILABLE"
    assert sc["match_confidence"] == 0

    assert contract.is_compliant(entity_id) is False
    assert contract.is_sanctioned(entity_id) is False


def test_validate_equivalence_exact_agreement(direct_deploy):
    contract = deploy_contract(direct_deploy)

    p1 = {
        "verdict": "CLEARED",
        "match_confidence": 100,
        "regulatory_notes": "Clear finding.",
    }
    p2 = {
        "verdict": "CLEARED",
        "match_confidence": 100,
        "regulatory_notes": "Slightly different phrasing.",
    }
    assert contract.validate_equivalence(json.dumps(p1), json.dumps(p2)) is True

    # Rejects divergence in verdict
    p_sanctioned = dict(p1)
    p_sanctioned["verdict"] = "SANCTIONED"
    assert contract.validate_equivalence(json.dumps(p1), json.dumps(p_sanctioned)) is False

    # Rejects divergence in confidence
    p_pending = dict(p1)
    p_pending["verdict"] = "INVESTIGATION_PENDING"
    assert contract.validate_equivalence(json.dumps(p1), json.dumps(p_pending)) is False


def test_screen_nonexistent_and_inactive_entity(direct_vm, direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    # Nonexistent entity
    with direct_vm.expect_revert("Entity does not exist"):
        contract.screen_entity(999)

    # Create and deactivate entity
    urls = json.dumps(["https://reg.gov/entity.html"])
    e_id = contract.register_entity("Inactive Co", "US", "ID-11", urls)
    contract.deactivate_entity(e_id)

    with direct_vm.expect_revert("Cannot screen an inactive entity"):
        contract.screen_entity(e_id)


def test_update_sources_success_and_access_control(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = json.dumps(["https://reg.gov/entity.html"])
    e_id = contract.register_entity("Update Sources Target", "UK", "ID-22", urls)

    new_urls = json.dumps(["https://new-registry.gov/entity.html"])

    # Non-registrar Bob attempts update -> revert
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Only registrar can update source URLs"):
        contract.update_sources(e_id, new_urls)

    # Registrar Alice updates -> success
    direct_vm.sender = direct_alice
    contract.update_sources(e_id, new_urls)

    entity = contract.get_entity(e_id)
    assert "new-registry.gov" in entity["source_urls_json"]
    assert entity["status"] == "PENDING"


def test_deactivate_entity_access_control(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = json.dumps(["https://reg.gov/entity.html"])
    e_id = contract.register_entity("Deactivate Target", "US", "ID-33", urls)

    # Non-registrar Bob attempts deactivate -> revert
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Only registrar can deactivate entity"):
        contract.deactivate_entity(e_id)

    # Registrar Alice deactivates -> success
    direct_vm.sender = direct_alice
    contract.deactivate_entity(e_id)

    entity = contract.get_entity(e_id)
    assert entity["active"] is False
    assert entity["status"] == "UNAVAILABLE"
    assert contract.is_compliant(e_id) is False


def test_is_compliant_and_is_sanctioned_boundary_conditions(direct_vm, direct_deploy):
    contract = deploy_contract(direct_deploy)

    # Nonexistent entity
    assert contract.is_compliant(999) is False
    assert contract.is_sanctioned(999) is False

    # Pending entity without screening
    urls = json.dumps(["https://reg.gov/entity.html"])
    e_id = contract.register_entity("Pending Entity", "US", "ID-44", urls)
    assert contract.latest_status(e_id) == ("PENDING", 0)
    assert contract.is_compliant(e_id) is False
    assert contract.is_sanctioned(e_id) is False


def test_malformed_llm_json_fallback(direct_vm, direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = ["https://reg.gov/entity.html"]
    e_id = contract.register_entity("Malformed Fallback Co", "UK", "ID-55", json.dumps(urls))

    direct_vm.mock_web(r"reg\.gov/.*", {"status": 200, "body": "Normal registry text."})
    direct_vm.mock_llm(r".*", "This is unstructured text not in JSON format.")

    sc_id = contract.screen_entity(e_id)
    entity = contract.get_entity(e_id)
    assert entity["status"] == "INVESTIGATION_PENDING"

    sc = contract.get_screening(sc_id)
    assert sc["verdict"] == "ERROR"
    assert sc["match_confidence"] == 0
    assert contract.is_compliant(e_id) is False


def test_author_isolation_invariant():
    """Verify strictly zero trace of other builder identities in the contract source."""
    with open(CONTRACT_PATH, "r", encoding="utf-8") as f:
        src = f.read()

    assert "Author: vix" in src
    assert "9ytshade" not in src
    assert "adewale" not in src.lower()
