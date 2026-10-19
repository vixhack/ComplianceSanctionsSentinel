# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""ComplianceSanctionsSentinel v1.1.0: Autonomous Regulatory Sanctions & Compliance Oracle.

Author: vix
A standalone GenLayer Intelligent Contract primitive that evaluates counterparty
compliance and sanctions exposure across official regulatory gazettes, enforcement
registers, and public sanctions orders using decentralized validator consensus.

Validators independently fetch official regulatory gazettes under strict authoritative
provenance controls per regime, enforcing parsed host/IP network safety, recursive
redirect validation against private/reserved IPv4/IPv6 destinations, and zero-drift
exact consensus binding on discrete canonical clearance and sanctions outcomes
under the Equivalence Principle.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import re
import urllib.parse

from genlayer import *


def _coerce_to_str(val) -> str:
    if isinstance(val, int):
        return hex(val)
    return str(val)


# ---------------------------------------------------------------------------
# Authoritative Regulatory Domain Mapping per Regime
# ---------------------------------------------------------------------------

AUTHORITATIVE_REGIME_DOMAINS: dict[str, tuple[str, ...]] = {
    "OFAC": (
        "treasury.gov",
        "treas.gov",
        "trade.gov",
        "federalregister.gov",
        "state.gov",
    ),
    "UK_OFSI": (
        "gov.uk",
        "sanctionslist.service.gov.uk",
        "ofsistorage.blob.core.windows.net",
        "assets.publishing.service.gov.uk",
        "legislation.gov.uk",
    ),
    "EU_FSF": (
        "europa.eu",
        "sanctionsmap.eu",
        "data.europa.eu",
        "eeas.europa.eu",
        "eur-lex.europa.eu",
        "ec.europa.eu",
    ),
    "SWISS_SECO": (
        "admin.ch",
        "seco.admin.ch",
        "sesam.search.admin.ch",
    ),
    "UN": (
        "un.org",
        "scsanctions.un.org",
        "press.un.org",
    ),
    "GLOBAL": (
        # Union of all official national and multilateral regulatory gazette domains
        "treasury.gov",
        "treas.gov",
        "trade.gov",
        "federalregister.gov",
        "state.gov",
        "gov.uk",
        "sanctionslist.service.gov.uk",
        "ofsistorage.blob.core.windows.net",
        "assets.publishing.service.gov.uk",
        "legislation.gov.uk",
        "europa.eu",
        "sanctionsmap.eu",
        "data.europa.eu",
        "eeas.europa.eu",
        "eur-lex.europa.eu",
        "ec.europa.eu",
        "admin.ch",
        "seco.admin.ch",
        "sesam.search.admin.ch",
        "un.org",
        "scsanctions.un.org",
        "press.un.org",
        "worldbank.org",
        "interpol.int",
        "bis.doc.gov",
        "fbi.gov",
    ),
}

# Forbidden local, internal, test, or non-public domain suffixes
FORBIDDEN_HOST_SUFFIXES: tuple[str, ...] = (
    "localhost",
    "local",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "arpa",
    "invalid",
    "test",
    "example",
)


def _normalize_regime_name(regime: str) -> str:
    clean = (regime or "").strip().upper()
    if clean in ("UK", "OFSI", "UK_OFSI"):
        return "UK_OFSI"
    if clean in ("EU", "EU_FSF", "EU_SANCTIONS"):
        return "EU_FSF"
    if clean in ("OFAC", "US", "US_OFAC"):
        return "OFAC"
    if clean in ("SWISS", "SECO", "SWISS_SECO"):
        return "SWISS_SECO"
    if clean in ("UN", "UNSC"):
        return "UN"
    if clean == "GLOBAL":
        return "GLOBAL"
    if clean in AUTHORITATIVE_REGIME_DOMAINS:
        return clean
    return "GLOBAL"


def _check_ip_safety(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Validate that a parsed IP is not private, loopback, link-local, multicast, or reserved."""
    # If IPv6, unmap IPv4-mapped addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if ip_obj.is_loopback:
        raise gl.vm.UserError(f"Loopback destination is forbidden: {ip_obj}")
    if ip_obj.is_link_local:
        raise gl.vm.UserError(f"Link-local destination is forbidden: {ip_obj}")
    if ip_obj.is_private:
        raise gl.vm.UserError(f"Private IP destination is forbidden: {ip_obj}")
    if ip_obj.is_reserved:
        raise gl.vm.UserError(f"Reserved IP destination is forbidden: {ip_obj}")
    if ip_obj.is_multicast:
        raise gl.vm.UserError(f"Multicast destination is forbidden: {ip_obj}")
    if ip_obj.is_unspecified:
        raise gl.vm.UserError(f"Unspecified IP destination is forbidden: {ip_obj}")

    # Carrier-Grade NAT (RFC 6598: 100.64.0.0/10)
    if ip_obj in ipaddress.ip_network("100.64.0.0/10"):
        raise gl.vm.UserError(f"Carrier-grade NAT IP is forbidden: {ip_obj}")

    # IETF Protocol and documentation ranges
    doc_ranges = (
        ipaddress.ip_network("192.0.0.0/24"),
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("198.18.0.0/15"),
        ipaddress.ip_network("2001:db8::/32"),
    )
    for doc_range in doc_ranges:
        if ip_obj in doc_range:
            raise gl.vm.UserError(f"Documentation/benchmark IP range is forbidden: {ip_obj}")


def _validate_source_url_and_provenance(url: str, regime: str, max_url_len: int = 2048) -> str:
    """Rigorous network safety and authoritative sanctions-source provenance validation.
    Replaces substring checks with parsed host/IP validation, rejecting non-HTTPS,
    embedded credentials, non-standard ports, raw IPs, private/reserved ranges,
    and unauthoritative domains for the target regulatory regime.
    """
    clean = url.strip()
    if len(clean) == 0 or len(clean) > max_url_len:
        raise gl.vm.UserError("URL length out of bounds")

    try:
        parts = urllib.parse.urlsplit(clean)
    except Exception:
        raise gl.vm.UserError("Failed to parse URL syntax")

    if parts.scheme.lower() != "https":
        raise gl.vm.UserError("Only secure HTTPS URLs are permitted")

    if not parts.hostname:
        raise gl.vm.UserError("Missing valid hostname in URL")

    if parts.username or parts.password or "@" in parts.netloc:
        raise gl.vm.UserError("Embedded userinfo or credentials in URL are forbidden")

    if parts.port is not None and parts.port != 443:
        raise gl.vm.UserError("Non-standard HTTPS port is forbidden")

    raw_host = parts.hostname.lower().rstrip(".").strip("[]")
    if len(raw_host) == 0:
        raise gl.vm.UserError("Empty hostname in URL")

    # Check if raw_host is an IP address
    try:
        parsed_ip = ipaddress.ip_address(raw_host)
        _check_ip_safety(parsed_ip)
        # Official regulatory gazettes are never raw IPs
        raise gl.vm.UserError("Raw IP destinations are forbidden for official regulatory sources")
    except ValueError:
        # Not a standard IP literal, proceed to hostname checks
        pass

    # Check for integer or hex representations of IP addresses
    if raw_host.isdigit():
        raise gl.vm.UserError("Numeric integer hostnames are forbidden")
    if raw_host.startswith("0x") or raw_host.startswith("0X"):
        raise gl.vm.UserError("Hexadecimal hostnames are forbidden")

    # Check forbidden host domain suffixes
    for suff in FORBIDDEN_HOST_SUFFIXES:
        if raw_host == suff or raw_host.endswith("." + suff):
            raise gl.vm.UserError(f"Prohibited local or internal host domain: {suff}")

    # Enforce authoritative sanctions-source provenance for the regime
    norm_regime = _normalize_regime_name(regime)
    allowed_domains = AUTHORITATIVE_REGIME_DOMAINS.get(
        norm_regime, AUTHORITATIVE_REGIME_DOMAINS["GLOBAL"]
    )

    is_auth = False
    for auth_dom in allowed_domains:
        if raw_host == auth_dom or raw_host.endswith("." + auth_dom):
            is_auth = True
            break

    if not is_auth:
        raise gl.vm.UserError(
            f"URL host '{raw_host}' does not match authoritative regulatory provenance for regime '{norm_regime}'"
        )

    return clean


@allow_storage
@dataclass
class TargetEntity:
    id: u256
    registrar: Address
    name: str
    jurisdiction: str
    identifier: str  # e.g., LEI, Registration Number, or Tax ID
    regulatory_regime: str  # e.g., "OFAC", "EU_FSF", "UK_OFSI", "GLOBAL"
    source_urls_json: str
    status: str  # "PENDING", "CLEARED", "SANCTIONED", "INVESTIGATION_PENDING", "UNAVAILABLE"
    latest_screening_id: u32
    active: bool
    registered_at: u64
    total_screenings: u32


@allow_storage
@dataclass
class ComplianceScreening:
    id: u32
    entity_id: u256
    verdict: str  # "CLEARED", "SANCTIONED", "INVESTIGATION_PENDING", "UNAVAILABLE", "ERROR"
    match_confidence: u32  # Discrete canonical confidence: 100 or 0
    regulatory_notes: str
    sources_checked: u32
    screened_at: u64


class ComplianceSanctionsSentinel(gl.Contract):
    VERSION = "1.1.0"

    # Status Constants
    STATUS_PENDING = "PENDING"
    STATUS_CLEARED = "CLEARED"
    STATUS_SANCTIONED = "SANCTIONED"
    STATUS_INVESTIGATION_PENDING = "INVESTIGATION_PENDING"
    STATUS_UNAVAILABLE = "UNAVAILABLE"

    # Canonical Verdict Buckets
    VERDICT_CLEARED = "CLEARED"
    VERDICT_SANCTIONED = "SANCTIONED"
    VERDICT_INVESTIGATION_PENDING = "INVESTIGATION_PENDING"
    VERDICT_UNAVAILABLE = "UNAVAILABLE"
    VERDICT_ERROR = "ERROR"

    # Discrete Canonical Confidence Levels bound to Consensus Buckets
    CONFIDENCE_CLEARED = 100
    CONFIDENCE_SANCTIONED = 100
    CONFIDENCE_INVESTIGATION_PENDING = 0
    CONFIDENCE_UNAVAILABLE = 0
    CONFIDENCE_ERROR = 0

    # Bounds
    MIN_NAME_LENGTH = 2
    MAX_NAME_LENGTH = 128
    MIN_JURISDICTION_LENGTH = 2
    MAX_JURISDICTION_LENGTH = 64
    MIN_IDENTIFIER_LENGTH = 2
    MAX_IDENTIFIER_LENGTH = 64
    MIN_REGIME_LENGTH = 2
    MAX_REGIME_LENGTH = 32
    MIN_SOURCES_COUNT = 1
    MAX_SOURCES_COUNT = 5
    MAX_URL_LENGTH = 2048
    MAX_EXCERPT_CHARS = 2000

    entity_count: u256
    screening_count: u32

    entities: TreeMap[u256, TargetEntity]
    screenings: TreeMap[u32, ComplianceScreening]

    def __init__(self):
        self.entity_count = u256(0)
        self.screening_count = u32(0)

    # -------------------------------------------------------------
    # Internal Validation Helpers
    # -------------------------------------------------------------

    def _now(self) -> u64:
        return u64(int(datetime.now(timezone.utc).timestamp()))

    def _parse_and_validate_urls(self, raw_input, regime: str) -> list[str]:
        if isinstance(raw_input, list):
            urls = raw_input
        elif isinstance(raw_input, str):
            try:
                urls = json.loads(raw_input)
            except Exception:
                raise gl.vm.UserError("source_urls_json must be valid JSON array")
        else:
            raise gl.vm.UserError("source_urls_json must be valid JSON array")

        if not isinstance(urls, list):
            raise gl.vm.UserError("source_urls_json must be a JSON array of strings")

        if len(urls) < self.MIN_SOURCES_COUNT or len(urls) > self.MAX_SOURCES_COUNT:
            raise gl.vm.UserError(
                f"Source URL count must be between {self.MIN_SOURCES_COUNT} and {self.MAX_SOURCES_COUNT}"
            )

        cleaned_urls = []
        for u in urls:
            if not isinstance(u, str):
                raise gl.vm.UserError("All source URLs must be strings")
            cleaned_urls.append(_validate_source_url_and_provenance(u, regime, self.MAX_URL_LENGTH))

        return cleaned_urls

    def _normalize_screening_payload(self, raw: dict, sources_checked: int = 0) -> dict:
        """Map screening output to discrete canonical buckets and exact consensus confidence values.
        Enforces strict fail-closed security: a CLEARED or SANCTIONED outcome is impossible without
        at least one verified authoritative source (sources_checked > 0).
        """
        raw_verdict = str(raw.get("verdict", self.VERDICT_ERROR)).strip().upper()
        s_checked = int(raw.get("sources_checked", sources_checked))

        if raw_verdict in ("CLEARED", "VERDICT_CLEARED") and s_checked > 0:
            verdict = self.VERDICT_CLEARED
            confidence = self.CONFIDENCE_CLEARED
        elif raw_verdict in ("SANCTIONED", "VERDICT_SANCTIONED") and s_checked > 0:
            verdict = self.VERDICT_SANCTIONED
            confidence = self.CONFIDENCE_SANCTIONED
        elif raw_verdict in ("INVESTIGATION_PENDING", "PENDING", "AMBIGUOUS") and s_checked > 0:
            verdict = self.VERDICT_INVESTIGATION_PENDING
            confidence = self.CONFIDENCE_INVESTIGATION_PENDING
        elif raw_verdict == self.VERDICT_UNAVAILABLE or s_checked == 0:
            # Deterministic fail-closed if authority or network safety was not established
            verdict = self.VERDICT_UNAVAILABLE
            confidence = self.CONFIDENCE_UNAVAILABLE
        else:
            verdict = self.VERDICT_ERROR
            confidence = self.CONFIDENCE_ERROR

        regulatory_notes = str(raw.get("regulatory_notes", "")).strip()[:500]

        return {
            "verdict": verdict,
            "match_confidence": confidence,
            "regulatory_notes": regulatory_notes,
            "sources_checked": s_checked,
        }

    # -------------------------------------------------------------
    # Public State-Changing Write Methods
    # -------------------------------------------------------------

    @gl.public.write
    def register_entity(
        self,
        name: str,
        jurisdiction: str,
        identifier: str,
        source_urls_json: str,
        regulatory_regime: str = "GLOBAL",
    ) -> u256:
        clean_name = name.strip()
        clean_jurisdiction = jurisdiction.strip()
        clean_identifier = identifier.strip()
        clean_regime = _normalize_regime_name(regulatory_regime)

        cleaned_urls = self._parse_and_validate_urls(source_urls_json, clean_regime)

        if len(clean_name) < self.MIN_NAME_LENGTH or len(clean_name) > self.MAX_NAME_LENGTH:
            raise gl.vm.UserError("Entity name length out of bounds")
        if (
            len(clean_jurisdiction) < self.MIN_JURISDICTION_LENGTH
            or len(clean_jurisdiction) > self.MAX_JURISDICTION_LENGTH
        ):
            raise gl.vm.UserError("Jurisdiction length out of bounds")
        if (
            len(clean_identifier) < self.MIN_IDENTIFIER_LENGTH
            or len(clean_identifier) > self.MAX_IDENTIFIER_LENGTH
        ):
            raise gl.vm.UserError("Identifier length out of bounds")

        self.entity_count += u256(1)
        e_id = self.entity_count

        now_ts = self._now()
        entity = TargetEntity(
            id=e_id,
            registrar=gl.message.sender_address,
            name=clean_name,
            jurisdiction=clean_jurisdiction,
            identifier=clean_identifier,
            regulatory_regime=clean_regime,
            source_urls_json=json.dumps(cleaned_urls),
            status=self.STATUS_PENDING,
            latest_screening_id=u32(0),
            active=True,
            registered_at=now_ts,
            total_screenings=u32(0),
        )

        self.entities[e_id] = entity
        return e_id

    @gl.public.write
    def screen_entity(self, entity_id: u256) -> u32:
        if isinstance(entity_id, int):
            entity_id = u256(entity_id)

        if entity_id not in self.entities:
            raise gl.vm.UserError("Entity does not exist")

        entity = self.entities[entity_id]
        if not entity.active:
            raise gl.vm.UserError("Cannot screen an inactive entity")

        # Snapshot parameters for non-deterministic execution
        urls = json.loads(entity.source_urls_json)
        target_name = entity.name
        target_jurisdiction = entity.jurisdiction
        target_id = entity.identifier
        target_regime = entity.regulatory_regime
        max_chars = self.MAX_EXCERPT_CHARS

        def evaluate() -> dict:
            reachable_evidence = []
            for u in urls:
                # Re-validate source authority and parsed host/IP network safety
                try:
                    clean_u = _validate_source_url_and_provenance(u, target_regime, max_url_len=2048)
                except Exception:
                    # Non-authoritative or unsafe source: omit immediately
                    continue

                try:
                    resp = gl.nondet.web.get(clean_u)
                    status = getattr(resp, "status", 500)

                    # HTTP Redirect Validation (301, 302, 303, 307, 308)
                    if status in (301, 302, 303, 307, 308):
                        headers = getattr(resp, "headers", {})
                        loc = None
                        if isinstance(headers, dict):
                            loc = headers.get("location") or headers.get("Location")

                        if loc:
                            redirect_target = urllib.parse.urljoin(clean_u, loc)
                            try:
                                # Recursively validate redirect target against IP safety and regime authority
                                clean_target = _validate_source_url_and_provenance(
                                    redirect_target, target_regime, max_url_len=2048
                                )
                                resp = gl.nondet.web.get(clean_target)
                                status = getattr(resp, "status", 500)
                            except Exception:
                                # Redirect target violates network safety or authority: fail-closed on this source
                                continue
                        else:
                            continue

                    if status == 200:
                        raw_body = getattr(resp, "body", b"")
                        if isinstance(raw_body, str):
                            body = raw_body.strip()
                        elif isinstance(raw_body, (bytes, bytearray)):
                            body = raw_body.decode("utf-8", errors="replace").strip()
                        else:
                            body = str(raw_body).strip()

                        if len(body) > 0:
                            # Validate against HTML meta-refresh redirect manipulation
                            lower_header = body[:1000].lower()
                            if "http-equiv=\"refresh\"" in lower_header or "http-equiv='refresh'" in lower_header:
                                refresh_match = re.search(r'url=([^"\' >]+)', body[:1000], re.IGNORECASE)
                                if refresh_match:
                                    meta_target = urllib.parse.urljoin(clean_u, refresh_match.group(1).strip())
                                    try:
                                        _validate_source_url_and_provenance(
                                            meta_target, target_regime, max_url_len=2048
                                        )
                                    except Exception:
                                        # Meta refresh target is unauthorized or unsafe
                                        continue

                            reachable_evidence.append({
                                "url": clean_u,
                                "text": body[:max_chars],
                            })
                except Exception:
                    pass

            # Fail closed if source authority or network safety cannot be established
            if len(reachable_evidence) == 0:
                return self._normalize_screening_payload(
                    {
                        "verdict": self.VERDICT_UNAVAILABLE,
                        "regulatory_notes": "Official regulatory source endpoints could not be reached, or source authority / network safety could not be established.",
                    },
                    sources_checked=0,
                )

            evidence_blocks = ""
            for idx, item in enumerate(reachable_evidence):
                evidence_blocks += f"\n<official_register_{idx + 1} url=\"{item['url']}\">\n{item['text']}\n</official_register_{idx + 1}>\n"

            prompt = f"""You are an impartial regulatory compliance magistrate on GenLayer adjudicating sanctions exposure under the {target_regime} regime.
Evaluate whether the following TARGET ENTITY is listed on active sanctions lists, asset freeze orders, or regulatory enforcement actions within the provided official regulatory sources.

TARGET ENTITY SPECIFICATION:
Name: {target_name}
Jurisdiction: {target_jurisdiction}
Identifier / Registration: {target_id}
Regulatory Regime: {target_regime}

OFFICIAL REGULATORY EVIDENCE:
{evidence_blocks}

TASK & CLASSIFICATION RULES:
- If the official evidence conclusively names this entity (matching name and jurisdiction/identifier) under active sanctions or asset freeze, return verdict "SANCTIONED".
- If the evidence clearly documents this entity or registry without sanctions, or explicitly shows no enforcement sanctions apply, return verdict "CLEARED".
- If an entity with a similar name exists but jurisdiction/registration differs, or evidence is partial, conflicting, or ambiguous, return verdict "INVESTIGATION_PENDING".
- Summarize the specific finding in regulatory_notes citing evidence.

OUTPUT FORMAT:
Respond with ONLY valid JSON:
{{
  "verdict": "CLEARED" | "SANCTIONED" | "INVESTIGATION_PENDING",
  "regulatory_notes": "Concise summary citing findings"
}}
"""
            try:
                result = gl.nondet.exec_prompt(prompt, response_format="json")
                if isinstance(result, str):
                    result = json.loads(result)
            except Exception:
                result = {"verdict": self.VERDICT_ERROR, "regulatory_notes": "LLM adjudication failed"}

            if not isinstance(result, dict):
                result = {"verdict": self.VERDICT_ERROR, "regulatory_notes": "Malformed LLM response"}

            return self._normalize_screening_payload(
                result,
                sources_checked=len(reachable_evidence),
            )

        def validate(leader_result: gl.vm.Result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                leader_val = self._normalize_screening_payload(leader_result.calldata)
                validator_val = evaluate()

                # Verdict must match exactly (canonical discrete bucket)
                if leader_val["verdict"] != validator_val["verdict"]:
                    return False

                # Discrete match confidence must match exactly (100 vs 0) - zero tolerance!
                if int(leader_val["match_confidence"]) != int(validator_val["match_confidence"]):
                    return False

                # Exact agreement on material compliance outcome
                leader_compliant = (leader_val["verdict"] == self.VERDICT_CLEARED)
                validator_compliant = (validator_val["verdict"] == self.VERDICT_CLEARED)
                if leader_compliant != validator_compliant:
                    return False

                # Exact agreement on material sanctions outcome
                leader_sanctioned = (leader_val["verdict"] == self.VERDICT_SANCTIONED)
                validator_sanctioned = (validator_val["verdict"] == self.VERDICT_SANCTIONED)
                if leader_sanctioned != validator_sanctioned:
                    return False

                return True
            except Exception:
                return False

        screening_payload = gl.vm.run_nondet_unsafe(
            evaluate,
            validate,
        )

        self.screening_count += u32(1)
        sc_id = self.screening_count

        now_ts = self._now()
        screening = ComplianceScreening(
            id=sc_id,
            entity_id=entity_id,
            verdict=screening_payload["verdict"],
            match_confidence=u32(screening_payload["match_confidence"]),
            regulatory_notes=screening_payload["regulatory_notes"],
            sources_checked=u32(screening_payload["sources_checked"]),
            screened_at=now_ts,
        )
        self.screenings[sc_id] = screening

        # Deterministic state update directly bound to consensus bucket
        if screening.verdict == self.VERDICT_SANCTIONED:
            entity.status = self.STATUS_SANCTIONED
        elif screening.verdict == self.VERDICT_CLEARED:
            entity.status = self.STATUS_CLEARED
        elif screening.verdict == self.VERDICT_UNAVAILABLE:
            entity.status = self.STATUS_UNAVAILABLE
        else:
            entity.status = self.STATUS_INVESTIGATION_PENDING

        entity.latest_screening_id = sc_id
        entity.total_screenings += u32(1)
        self.entities[entity_id] = entity

        return sc_id

    @gl.public.write
    def update_sources(self, entity_id: u256, new_source_urls_json: str) -> None:
        if isinstance(entity_id, int):
            entity_id = u256(entity_id)

        if entity_id not in self.entities:
            raise gl.vm.UserError("Entity not found")

        entity = self.entities[entity_id]
        if gl.message.sender_address != entity.registrar:
            raise gl.vm.UserError("Only registrar can update source URLs")

        cleaned_urls = self._parse_and_validate_urls(new_source_urls_json, entity.regulatory_regime)
        entity.source_urls_json = json.dumps(cleaned_urls)
        entity.status = self.STATUS_PENDING
        self.entities[entity_id] = entity

    @gl.public.write
    def deactivate_entity(self, entity_id: u256) -> None:
        if isinstance(entity_id, int):
            entity_id = u256(entity_id)

        if entity_id not in self.entities:
            raise gl.vm.UserError("Entity not found")

        entity = self.entities[entity_id]
        if gl.message.sender_address != entity.registrar:
            raise gl.vm.UserError("Only registrar can deactivate entity")

        entity.active = False
        entity.status = self.STATUS_UNAVAILABLE
        self.entities[entity_id] = entity

    # -------------------------------------------------------------
    # Public View Interface
    # -------------------------------------------------------------

    @gl.public.view
    def get_entity(self, entity_id: u256) -> dict:
        if isinstance(entity_id, int):
            entity_id = u256(entity_id)
        if entity_id not in self.entities:
            raise gl.vm.UserError("Entity not found")
        e = self.entities[entity_id]
        return {
            "id": int(e.id),
            "registrar": _coerce_to_str(e.registrar),
            "name": e.name,
            "jurisdiction": e.jurisdiction,
            "identifier": e.identifier,
            "regulatory_regime": e.regulatory_regime,
            "source_urls_json": e.source_urls_json,
            "status": e.status,
            "latest_screening_id": int(e.latest_screening_id),
            "active": e.active,
            "registered_at": int(e.registered_at),
            "total_screenings": int(e.total_screenings),
        }

    @gl.public.view
    def get_screening(self, screening_id: u32) -> dict:
        if isinstance(screening_id, int):
            screening_id = u32(screening_id)
        if screening_id not in self.screenings:
            raise gl.vm.UserError("Screening not found")
        sc = self.screenings[screening_id]
        return {
            "id": int(sc.id),
            "entity_id": int(sc.entity_id),
            "verdict": sc.verdict,
            "match_confidence": int(sc.match_confidence),
            "regulatory_notes": sc.regulatory_notes,
            "sources_checked": int(sc.sources_checked),
            "screened_at": int(sc.screened_at),
        }

    @gl.public.view
    def latest_status(self, entity_id: u256) -> tuple[str, int]:
        if isinstance(entity_id, int):
            entity_id = u256(entity_id)
        if entity_id not in self.entities:
            raise gl.vm.UserError("Entity not found")
        e = self.entities[entity_id]
        sc_id = e.latest_screening_id
        if sc_id == 0 or sc_id not in self.screenings:
            return (self.STATUS_PENDING, 0)
        sc = self.screenings[sc_id]
        return (sc.verdict, int(sc.match_confidence))

    @gl.public.view
    def is_compliant(self, entity_id: u256) -> bool:
        """Determines if counterparty is cleared for RWA/DeFi interaction.
        Bound strictly to validator consensus on discrete canonical confidence (100)
        from verified authoritative regulatory sources.
        """
        if isinstance(entity_id, int):
            entity_id = u256(entity_id)
        if entity_id not in self.entities:
            return False
        e = self.entities[entity_id]
        if not e.active or e.status != self.STATUS_CLEARED:
            return False
        sc_id = e.latest_screening_id
        if sc_id == 0 or sc_id not in self.screenings:
            return False
        sc = self.screenings[sc_id]
        return sc.verdict == self.VERDICT_CLEARED and int(sc.match_confidence) == self.CONFIDENCE_CLEARED

    @gl.public.view
    def is_sanctioned(self, entity_id: u256) -> bool:
        """Determines if counterparty is confirmed on active sanctions/freeze list.
        Bound strictly to validator consensus on discrete canonical confidence (100)
        from verified authoritative regulatory sources.
        """
        if isinstance(entity_id, int):
            entity_id = u256(entity_id)
        if entity_id not in self.entities:
            return False
        e = self.entities[entity_id]
        if not e.active or e.status != self.STATUS_SANCTIONED:
            return False
        sc_id = e.latest_screening_id
        if sc_id == 0 or sc_id not in self.screenings:
            return False
        sc = self.screenings[sc_id]
        return sc.verdict == self.VERDICT_SANCTIONED and int(sc.match_confidence) == self.CONFIDENCE_SANCTIONED

    @gl.public.view
    def validate_equivalence(self, leader_payload_json: str, validator_payload_json: str) -> bool:
        """Deterministic public view of the Equivalence Principle consensus algorithm.
        Enforces exact agreement on canonical verdict, discrete confidence bucket,
        material compliance outcome, and material sanctions outcome.
        """
        try:
            if isinstance(leader_payload_json, str):
                leader_val = json.loads(leader_payload_json)
            else:
                leader_val = dict(leader_payload_json)

            if isinstance(validator_payload_json, str):
                validator_val = json.loads(validator_payload_json)
            else:
                validator_val = dict(validator_payload_json)

            leader_norm = self._normalize_screening_payload(leader_val)
            validator_norm = self._normalize_screening_payload(validator_val)

            # Exact verdict agreement
            if leader_norm["verdict"] != validator_norm["verdict"]:
                return False

            # Exact canonical discrete confidence agreement (100 vs 0) - zero tolerance!
            if int(leader_norm["match_confidence"]) != int(validator_norm["match_confidence"]):
                return False

            # Exact agreement on material compliance outcome
            leader_compliant = (leader_norm["verdict"] == self.VERDICT_CLEARED)
            validator_compliant = (validator_norm["verdict"] == self.VERDICT_CLEARED)
            if leader_compliant != validator_compliant:
                return False

            # Exact agreement on material sanctions outcome
            leader_sanctioned = (leader_norm["verdict"] == self.VERDICT_SANCTIONED)
            validator_sanctioned = (validator_norm["verdict"] == self.VERDICT_SANCTIONED)
            if leader_sanctioned != validator_sanctioned:
                return False

            return True
        except Exception:
            return False

    @gl.public.view
    def get_entity_count(self) -> int:
        return int(self.entity_count)

    @gl.public.view
    def get_screening_count(self) -> int:
        return int(self.screening_count)
