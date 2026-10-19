"""Direct Mode Adversarial Test Suite for ComplianceSanctionsSentinel v1.1.0.

Author: vix
Comprehensive unit test suite for regulatory sanctions screening, authoritative
regime provenance enforcement, parsed host/IP safety, recursive redirect validation,
discrete canonical confidence buckets (100 vs 0), fail-closed handling,
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
        "https://sanctionslist.service.gov.uk/details/12345678",
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
    valid_urls = json.dumps(["https://sanctionssearch.ofac.treas.gov/details/entity.html"])

    # Name too short (<2)
    with direct_vm.expect_revert("Entity name length out of bounds"):
        contract.register_entity("A", "UK", "ID123", valid_urls, regulatory_regime="OFAC")

    # Name too long (>128)
    with direct_vm.expect_revert("Entity name length out of bounds"):
        contract.register_entity("A" * 129, "UK", "ID123", valid_urls, regulatory_regime="OFAC")

    # Jurisdiction too short (<2)
    with direct_vm.expect_revert("Jurisdiction length out of bounds"):
        contract.register_entity("Valid Name", "U", "ID123", valid_urls, regulatory_regime="OFAC")

    # Jurisdiction too long (>64)
    with direct_vm.expect_revert("Jurisdiction length out of bounds"):
        contract.register_entity("Valid Name", "U" * 65, "ID123", valid_urls, regulatory_regime="OFAC")

    # Identifier too short (<2)
    with direct_vm.expect_revert("Identifier length out of bounds"):
        contract.register_entity("Valid Name", "UK", "I", valid_urls, regulatory_regime="OFAC")

    # Identifier too long (>64)
    with direct_vm.expect_revert("Identifier length out of bounds"):
        contract.register_entity("Valid Name", "UK", "I" * 65, valid_urls, regulatory_regime="OFAC")

    # Invalid JSON in source_urls_json
    with direct_vm.expect_revert("source_urls_json must be valid JSON array"):
        contract.register_entity("Valid Name", "UK", "ID123", "{bad json}", regulatory_regime="OFAC")

    # Not a list
    with direct_vm.expect_revert("source_urls_json must be a JSON array of strings"):
        contract.register_entity(
            "Valid Name", "UK", "ID123", json.dumps({"url": "https://sanctionssearch.ofac.treas.gov"}), regulatory_regime="OFAC"
        )

    # Empty list (<1)
    with direct_vm.expect_revert("Source URL count must be between 1 and 5"):
        contract.register_entity("Valid Name", "UK", "ID123", json.dumps([]), regulatory_regime="OFAC")

    # More than 5 URLs
    with direct_vm.expect_revert("Source URL count must be between 1 and 5"):
        contract.register_entity(
            "Valid Name",
            "UK",
            "ID123",
            json.dumps([f"https://sanctionssearch.ofac.treas.gov/{i}" for i in range(6)]),
            regulatory_regime="OFAC",
        )

    # Non-string URL element
    with direct_vm.expect_revert("All source URLs must be strings"):
        contract.register_entity(
            "Valid Name", "UK", "ID123", json.dumps(["https://sanctionssearch.ofac.treas.gov", 999]), regulatory_regime="OFAC"
        )


def test_register_entity_invalid_url_and_ssrf(direct_vm, direct_deploy):
    contract = deploy_contract(direct_deploy)

    def test_ssrf(bad_url, err_msg, regime="GLOBAL"):
        with direct_vm.expect_revert(err_msg):
            contract.register_entity(
                "Probe Co",
                "US",
                "ID001",
                json.dumps([bad_url]),
                regulatory_regime=regime,
            )

    # Insecure scheme
    test_ssrf("http://sanctionssearch.ofac.treas.gov/registry", "Only secure HTTPS URLs are permitted")

    # Userinfo / credentials in URL
    test_ssrf("https://admin:pass@sanctionssearch.ofac.treas.gov/secrets", "Embedded userinfo or credentials in URL are forbidden")

    # Non-standard port
    test_ssrf("https://sanctionssearch.ofac.treas.gov:8443/registry", "Non-standard HTTPS port is forbidden")

    # Raw and private/reserved IP destinations
    test_ssrf("https://127.0.0.1/status", "Loopback destination is forbidden")
    test_ssrf("https://169.254.169.254/metadata", "Link-local destination is forbidden")
    test_ssrf("https://10.0.0.1/internal", "Private IP destination is forbidden")
    test_ssrf("https://192.168.1.1/secrets", "Private IP destination is forbidden")
    test_ssrf("https://172.16.1.1/keys", "Private IP destination is forbidden")
    test_ssrf("https://[::1]/status", "Loopback destination is forbidden")
    test_ssrf("https://8.8.8.8/status", "Raw IP destinations are forbidden")

    # Numeric and hexadecimal hostnames
    test_ssrf("https://2130706433/admin", "Numeric integer hostnames are forbidden")
    test_ssrf("https://0x7f000001/admin", "Hexadecimal hostnames are forbidden")

    # Local, test, and internal host domains
    test_ssrf("https://localhost/admin", "Prohibited local or internal host domain: localhost")
    test_ssrf("https://gateway.internal/api", "Prohibited local or internal host domain: internal")
    test_ssrf("https://server.local/health", "Prohibited local or internal host domain: local")
    test_ssrf("https://auth.corp/admin", "Prohibited local or internal host domain: corp")
    test_ssrf("https://router.lan/config", "Prohibited local or internal host domain: lan")

    # Arbitrary HTTPS pages rejected under regime provenance
    test_ssrf(
        "https://my-arbitrary-blog.com/clean.html",
        "does not match authoritative regulatory provenance for regime 'OFAC'",
        regime="OFAC",
    )
    test_ssrf(
        "https://random-registry.net/entity",
        "does not match authoritative regulatory provenance for regime 'UK_OFSI'",
        regime="UK_OFSI",
    )


def test_screen_entity_cleared_discrete_confidence_100(direct_vm, direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = ["https://companieshouse.gov.uk/company/apex-trading.html"]
    entity_id = contract.register_entity(
        name="Apex Trading Technologies Ltd",
        jurisdiction="United Kingdom",
        identifier="CRN-12345678",
        source_urls_json=json.dumps(urls),
        regulatory_regime="UK_OFSI",
    )

    # Mock web response with official regulatory registry
    direct_vm.mock_web(
        r"companieshouse\.gov\.uk/.*",
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

    urls = ["https://home.treasury.gov/policy-issues/financial-sanctions/orders/designations.html"]
    entity_id = contract.register_entity(
        name="Volga Strategic Metals CJSC",
        jurisdiction="Russian Federation",
        identifier="INN-7701234567",
        source_urls_json=json.dumps(urls),
        regulatory_regime="OFAC",
    )

    direct_vm.mock_web(
        r"home\.treasury\.gov/.*",
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

    urls = ["https://interpol.int/en/Notices/Red-Notices/search.html"]
    entity_id = contract.register_entity(
        name="Global Maritime Logistics",
        jurisdiction="Singapore",
        identifier="UEN-201912345A",
        source_urls_json=json.dumps(urls),
        regulatory_regime="GLOBAL",
    )

    # Evidence names an entity in a different jurisdiction with similar name
    direct_vm.mock_web(
        r"interpol\.int/.*",
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


def test_screen_entity_redirect_validation_and_fail_closed(direct_vm, direct_deploy, direct_alice):
    """Test redirect validation: redirects to private/reserved IPs or unauthoritative domains must fail closed."""
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = ["https://sanctionssearch.ofac.treas.gov/details/lookup.html"]
    entity_id = contract.register_entity(
        name="Redirect Defense Corp",
        jurisdiction="United States",
        identifier="US-991122",
        source_urls_json=json.dumps(urls),
        regulatory_regime="OFAC",
    )

    # Case A: Source returns 302 redirecting to a private cloud metadata IP
    direct_vm.mock_web(
        r"sanctionssearch\.ofac\.treas\.gov/details/lookup\.html",
        {
            "status": 302,
            "body": "Redirecting...",
            "headers": {"Location": "https://169.254.169.254/latest/meta-data"},
        },
    )

    screening_id = contract.screen_entity(entity_id)
    entity = contract.get_entity(entity_id)
    assert entity["status"] == "UNAVAILABLE"

    sc = contract.get_screening(screening_id)
    assert sc["verdict"] == "UNAVAILABLE"
    assert sc["match_confidence"] == 0
    assert sc["sources_checked"] == 0
    assert contract.is_compliant(entity_id) is False
    assert contract.is_sanctioned(entity_id) is False


def test_screen_entity_unreachable_fails_closed(direct_vm, direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = ["https://home.treasury.gov/policy-issues/financial-sanctions/offline.html"]
    entity_id = contract.register_entity(
        name="Offline Corporate Target",
        jurisdiction="Delaware, US",
        identifier="DE-998877",
        source_urls_json=json.dumps(urls),
        regulatory_regime="OFAC",
    )

    direct_vm.mock_web(
        r"home\.treasury\.gov/.*",
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
        "sources_checked": 1,
    }
    p2 = {
        "verdict": "CLEARED",
        "match_confidence": 100,
        "regulatory_notes": "Slightly different phrasing.",
        "sources_checked": 1,
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
    urls = json.dumps(["https://sanctionssearch.ofac.treas.gov/details/entity.html"])
    e_id = contract.register_entity("Inactive Co", "US", "ID-11", urls, regulatory_regime="OFAC")
    contract.deactivate_entity(e_id)

    with direct_vm.expect_revert("Cannot screen an inactive entity"):
        contract.screen_entity(e_id)


def test_update_sources_success_and_access_control(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = json.dumps(["https://companieshouse.gov.uk/company/12345"])
    e_id = contract.register_entity("Update Sources Target", "UK", "ID-22", urls, regulatory_regime="UK_OFSI")

    new_urls = json.dumps(["https://sanctionslist.service.gov.uk/company/12345"])

    # Non-registrar Bob attempts update -> revert
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Only registrar can update source URLs"):
        contract.update_sources(e_id, new_urls)

    # Registrar Alice updates with unauthorized regime domain -> revert
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("does not match authoritative regulatory provenance for regime 'UK_OFSI'"):
        contract.update_sources(e_id, json.dumps(["https://unapproved-site.com/entity"]))

    # Registrar Alice updates with valid authoritative URL -> success
    contract.update_sources(e_id, new_urls)

    entity = contract.get_entity(e_id)
    assert "sanctionslist.service.gov.uk" in entity["source_urls_json"]
    assert entity["status"] == "PENDING"


def test_deactivate_entity_access_control(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = json.dumps(["https://sanctionssearch.ofac.treas.gov/details/entity.html"])
    e_id = contract.register_entity("Deactivate Target", "US", "ID-33", urls, regulatory_regime="OFAC")

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
    urls = json.dumps(["https://sanctionssearch.ofac.treas.gov/details/entity.html"])
    e_id = contract.register_entity("Pending Entity", "US", "ID-44", urls, regulatory_regime="OFAC")
    assert contract.latest_status(e_id) == ("PENDING", 0)
    assert contract.is_compliant(e_id) is False
    assert contract.is_sanctioned(e_id) is False


def test_malformed_llm_json_fallback(direct_vm, direct_deploy, direct_alice):
    contract = deploy_contract(direct_deploy)
    direct_vm.sender = direct_alice

    urls = ["https://companieshouse.gov.uk/company/fallback.html"]
    e_id = contract.register_entity("Malformed Fallback Co", "UK", "ID-55", json.dumps(urls), regulatory_regime="UK_OFSI")

    direct_vm.mock_web(r"companieshouse\.gov\.uk/.*", {"status": 200, "body": "Normal registry text."})
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
