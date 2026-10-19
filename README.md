# ComplianceSanctionsSentinel (v1.1.0)

[![GenLayer](https://img.shields.io/badge/GenLayer-Studionet-blue)](https://explorer-studio.genlayer.com/address/0x74eeB7232EBa3F55006D21BbF61A7e223517E350)
[![Version](https://img.shields.io/badge/version-1.1.0-green)](contracts/compliance_sanctions_sentinel.py)
[![License](https://img.shields.io/badge/license-MIT-purple)](LICENSE)
[![Tests: Direct](https://img.shields.io/badge/Direct_Mode-16%2F16_PASS-brightgreen)](tests/direct/)
[![Tests: Studionet](https://img.shields.io/badge/Studionet_Integration-5%2F5_PASS-brightgreen)](tests/integration/)

**ComplianceSanctionsSentinel** is an autonomous GenLayer Intelligent Contract primitive that evaluates counterparty compliance and sanctions exposure across official sovereign regulatory gazettes, enforcement registers, and public asset freeze orders using decentralized validator consensus.

---

## 1. Why GenLayer? (The Unbuildable Primitive)

Traditional EVM smart contracts cannot read natural-language legal texts, browse government gazettes, or resolve corporate identity aliases. Conventional compliance solutions in Web3 rely on:
1. **Centralized Off-Chain Oracles & APIs** (Chainalysis, Elliptic, TRM Labs): If the API server is compromised, goes offline, or is coerced by an operator, the entire DeFi protocol or RWA pool inherits catastrophic systemic risk.
2. **Centralized Admin Multisigs**: Operators manually toggling compliance status, which introduces single-point-of-failure governance capture, bribery risk, and censorship.

`ComplianceSanctionsSentinel` solves this natively on GenLayer:
- **Authoritative Sanctions-Source Provenance**: Enforces official regulatory gazette domains per regulatory regime (`OFAC`, `UK_OFSI`, `EU_FSF`, `SWISS_SECO`, `UN`, `GLOBAL`), guaranteeing a registrar cannot obtain a `CLEARED` result from an arbitrary HTTPS page.
- **Parsed Host/IP & SSRF Defenses**: Employs structured URL parsing (`urllib.parse`) and IP validation (`ipaddress`), defending against loopback, private RFC 1918/4193, link-local, multicast, carrier-grade NAT, documentation blocks, IPv4-mapped IPv6, integer/hexadecimal host representations, and internal domains.
- **Redirect Validation**: Evaluates HTTP 3xx redirects and HTML meta-refresh tags, recursively verifying redirect destinations against network safety and regime authority before following.
- **Independent Web Retrieval**: Round validators independently fetch official regulatory gazette and corporate registry endpoints.
- **Natural Language Disambiguation**: Validators perform semantic comparison across `name`, `jurisdiction`, corporate `identifier` (e.g. CRN, LEI, Tax ID), and `regulatory_regime`, distinguishing between genuine sanctioned entities and lookalike trade names.
- **Decentralized Equivalence Consensus**: Validators reach consensus under the **Equivalence Principle**, binding discrete canonical confidence scores (`100` for CLEARED/SANCTIONED, `0` for PENDING/UNAVAILABLE) with exact agreement and zero threshold drift.

---

## 2. Architecture & State Lifecycle

```
[Registrar] ---> register_entity(name, jurisdiction, identifier, source_urls_json, regime)
                    │   (Enforces Authoritative Provenance & Parsed Host/IP Safety)
                    ▼ (Status: PENDING)
[Any Caller] --> screen_entity(entity_id)
                    │
                    ├──> [Leader + Validators]
                    │      ├── Web GET (authoritative regulatory gazettes)
                    │      ├── Redirect & SSRF Defense (recursive host/IP safety)
                    │      ├── LLM Regulatory Entity Disambiguation
                    │      └── Equivalence Principle Agreement (Exact Match)
                    │
                    ▼ (Consensus: MAJORITY_AGREE)
[Contract State Updated]
  ├── ComplianceScreening receipt recorded
  └── Status transitions:
        ├── CLEARED               (verdict == CLEARED, confidence == 100, sources > 0)
        ├── SANCTIONED            (verdict == SANCTIONED, confidence == 100, sources > 0)
        ├── UNAVAILABLE           (sources unreachable / unauthoritative, fail-closed)
        └── INVESTIGATION_PENDING (ambiguous, disambiguation needed, confidence == 0)
```

### State Definitions

| State | Description |
| :--- | :--- |
| `PENDING` | Entity registered with official HTTPS gazettes/registries; awaiting initial consensus screening. |
| `CLEARED` | Consensus confirmed entity is in good standing with zero active sanctions orders (`is_compliant == true`). Requires `sources_checked > 0`. |
| `SANCTIONED` | Consensus confirmed entity is designated under active blocking asset freeze (`is_sanctioned == true`). |
| `INVESTIGATION_PENDING` | Disambiguation required or non-responsive evidence (fails closed, `is_compliant == false`). |
| `UNAVAILABLE` | Official sources could not be reached or network safety / authority could not be established (fails closed, `is_compliant == false`). |

---

## 3. Canonical Studionet Deployment

* **Contract Address:** [`0x74eeB7232EBa3F55006D21BbF61A7e223517E350`](https://explorer-studio.genlayer.com/address/0x74eeB7232EBa3F55006D21BbF61A7e223517E350)
* **Deployer:** `0xb3b09558183aec6c2ff5aa547163b77a9266010a` (`vixDeployer`)
* **Deploy Transaction:** `0x3eea3c5a13b5485ad1769e8b6129af0a510e5489715816a592c235557767b0ff` (`MAJORITY_AGREE`, `ACCEPTED`)
* **Live Registration Tx:** `0xa6ea0e5f72fc282c5ac821ee6878781ebde7dc7715a1b7a05e6095fcf43502d6` (`ACCEPTED`)
* **Live Screening Consensus Tx:** `0xe935d0d63a0f1fb1bb6a5fffc6d5b76d0ba9f64873d102df0fcb52ae3442e961` (Verified receipt #1: `INVESTIGATION_PENDING`, canonical confidence 0, fails closed)

---

## 4. Verification & Testing

The repository provides a complete 3-tier testing framework:

### 4.1 Preflight Static Verification (16/16 Checks)
```bash
python scripts/preflight.py
```
Validates AST syntax, GenLayer decorators (`@allow_storage`, `@gl.public.write`, `@gl.public.view`), bounds constants, parsed host/IP network safety defenses, redirect validation, authoritative regime mapping, fail-closed handlers, and strict builder isolation invariants.

### 4.2 Direct Mode Adversarial Unit Tests (16/16 Checks)
```bash
python -m pytest tests/direct/test_compliance_sanctions_sentinel.py -v
```
Simulates local GenVM execution with mocked web environments and adversarial LLM outputs:
- Input bounds validation (empty strings, oversized payloads, invalid JSON).
- SSRF exploit defense (loopback, private IPv4/IPv6, metadata endpoints, carrier-grade NAT, integer/hex representations, `.internal`).
- Authoritative regulatory regime provenance rejection of arbitrary HTTPS pages.
- Recursive redirect validation against private/reserved IPs and untrusted domains.
- Discrete canonical confidence mapping (100 for cleared/sanctioned, 0 for pending/unavailable).
- Equivalence Principle agreement on exact canonical buckets (`validate_equivalence`).
- Jurisdictional entity disambiguation.
- Unreachable endpoints failing closed.
- Access control for source updates and deactivation.
- Author isolation invariant verification.

### 4.3 Studionet Live Integration Suite (5/5 Checks)
```bash
python -m pytest tests/integration/test_compliance_sanctions_sentinel_studionet.py -v
```
Queries canonical contract `0x74eeB7232EBa3F55006D21BbF61A7e223517E350` on Studionet via JSON-RPC and validates live contract schema, entity state, consensus screening receipt, downstream clearance gates, and total counter bounds.

---

## 5. Public Views & Auditing

- `is_compliant(entity_id: u256) -> bool`: Verifies counterparty is in good standing based strictly on canonical consensus confidence (100) from authoritative gazettes.
- `is_sanctioned(entity_id: u256) -> bool`: Verifies counterparty is active on blocking sanctions list.
- `validate_equivalence(leader_json: str, val_json: str) -> bool`: Public view exposing the exact consensus algorithm for external auditing.
- `latest_status(entity_id: u256) -> tuple[str, int]`: Returns latest verdict string and discrete match confidence.
