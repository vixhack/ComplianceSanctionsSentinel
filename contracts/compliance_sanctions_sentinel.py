# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""ComplianceSanctionsSentinel v1.0.1: Autonomous Regulatory Sanctions & Compliance Oracle.

Author: vix
A standalone GenLayer Intelligent Contract primitive that evaluates counterparty
compliance and sanctions exposure across official regulatory gazettes, enforcement
registers, and public sanctions orders using decentralized validator consensus.
Validators independently fetch official regulatory gazettes and enforce exact consensus
binding on discrete canonical clearance and sanctions outcomes under the Equivalence Principle.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import json

from genlayer import *


def _coerce_to_str(val) -> str:
    if isinstance(val, int):
        return hex(val)
    return str(val)


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
    VERSION = "1.0.1"

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

    def _validate_url(self, url: str) -> str:
        clean = url.strip()
        if len(clean) == 0 or len(clean) > self.MAX_URL_LENGTH:
            raise gl.vm.UserError("URL length out of bounds")
        if not clean.startswith("https://"):
            raise gl.vm.UserError("Only secure HTTPS URLs are permitted")

        lower = clean.lower()
        forbidden_patterns = (
            "://localhost",
            "://127.0.0.1",
            "://0.0.0.0",
            "://169.254.169.254",
            "://10.",
            "://192.168.",
            "://172.16.",
            "://172.17.",
            "://172.18.",
            "://172.19.",
            "://172.20.",
            ".internal",
            ".local",
        )
        for pattern in forbidden_patterns:
            if pattern in lower:
                raise gl.vm.UserError(f"Prohibited host or IP in URL: {pattern}")

        return clean

    def _parse_and_validate_urls(self, raw_input) -> list[str]:
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
            cleaned_urls.append(self._validate_url(u))

        return cleaned_urls

    def _normalize_screening_payload(self, raw: dict, sources_checked: int = 0) -> dict:
        """Map screening output to discrete canonical buckets and exact consensus confidence values."""
        raw_verdict = str(raw.get("verdict", self.VERDICT_ERROR)).strip().upper()

        if raw_verdict in ("CLEARED", "VERDICT_CLEARED"):
            verdict = self.VERDICT_CLEARED
            confidence = self.CONFIDENCE_CLEARED
        elif raw_verdict in ("SANCTIONED", "VERDICT_SANCTIONED"):
            verdict = self.VERDICT_SANCTIONED
            confidence = self.CONFIDENCE_SANCTIONED
        elif raw_verdict in ("INVESTIGATION_PENDING", "PENDING", "AMBIGUOUS"):
            verdict = self.VERDICT_INVESTIGATION_PENDING
            confidence = self.CONFIDENCE_INVESTIGATION_PENDING
        elif raw_verdict == self.VERDICT_UNAVAILABLE:
            verdict = self.VERDICT_UNAVAILABLE
            confidence = self.CONFIDENCE_UNAVAILABLE
        else:
            verdict = self.VERDICT_ERROR
            confidence = self.CONFIDENCE_ERROR

        regulatory_notes = str(raw.get("regulatory_notes", "")).strip()[:500]
        s_checked = int(raw.get("sources_checked", sources_checked))

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
        clean_regime = regulatory_regime.strip().upper() if regulatory_regime else "GLOBAL"
        if len(clean_regime) < self.MIN_REGIME_LENGTH:
            clean_regime = "GLOBAL"
        clean_regime = clean_regime[:self.MAX_REGIME_LENGTH]

        cleaned_urls = self._parse_and_validate_urls(source_urls_json)

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
                try:
                    resp = gl.nondet.web.get(u)
                    if resp.status == 200:
                        body = resp.body.decode("utf-8", errors="replace").strip()
                        if len(body) > 0:
                            reachable_evidence.append({
                                "url": u,
                                "text": body[:max_chars],
                            })
                except Exception:
                    pass

            # Fail closed if no official sources are reachable
            if len(reachable_evidence) == 0:
                return self._normalize_screening_payload(
                    {
                        "verdict": self.VERDICT_UNAVAILABLE,
                        "regulatory_notes": "Official regulatory source endpoints could not be reached.",
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

        cleaned_urls = self._parse_and_validate_urls(new_source_urls_json)
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
        Bound strictly to validator consensus on discrete canonical confidence (100).
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
        Bound strictly to validator consensus on discrete canonical confidence (100).
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
