# ComplianceSanctionsSentinel (v1.0.1)

[![GenLayer](https://img.shields.io/badge/GenLayer-Studionet-blue)](https://explorer-studio.genlayer.com/address/0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53)
[![Version](https://img.shields.io/badge/version-1.0.1-green)](contracts/compliance_sanctions_sentinel.py)
[![License](https://img.shields.io/badge/license-MIT-purple)](LICENSE)
[![Tests: Direct](https://img.shields.io/badge/Direct_Mode-15%2F15_PASS-brightgreen)](tests/direct/)
[![Tests: Studionet](https://img.shields.io/badge/Studionet_Integration-5%2F5_PASS-brightgreen)](tests/integration/)

**ComplianceSanctionsSentinel** is an autonomous GenLayer Intelligent Contract primitive that evaluates counterparty compliance and sanctions exposure across official sovereign regulatory gazettes, enforcement registers, and public asset freeze orders using decentralized validator consensus.

---

## 1. Why GenLayer? (The Unbuildable Primitive)

Traditional EVM smart contracts cannot read natural-language legal texts, browse government gazettes, or resolve corporate identity aliases. Conventional compliance solutions in Web3 rely on:
1. **Centralized Off-Chain Oracles & APIs** (Chainalysis, Elliptic, TRM Labs): If the API server is compromised, goes offline, or is coerced by an operator, the entire DeFi protocol or RWA pool inherits catastrophic systemic risk.
2. **Centralized Admin Multisigs**: Operators manually toggling compliance status, which introduces single-point-of-failure governance capture, bribery risk, and censorship.

`ComplianceSanctionsSentinel` solves this natively on GenLayer:
- **Independent Web Retrieval**: Round validators independently fetch official regulatory gazette and corporate registry endpoints.
- **Natural Language Disambiguation**: Validators perform semantic comparison across `name`, `jurisdiction`, corporate `identifier` (e.g. CRN, LEI, Tax ID), and `regulatory_regime` (e.g. `OFAC`, `SWISS_SECO`), distinguishing between genuine sanctioned entities and coincidental lookalike trade names.
- **Decentralized Equivalence Consensus**: Validators reach consensus under the **Equivalence Principle**, binding discrete canonical confidence scores (`100` for CLEARED/SANCTIONED, `0` for PENDING/UNAVAILABLE) with exact agreement and zero threshold drift.

---

## 2. Architecture & State Lifecycle

```
[Registrar] ---> register_entity(name, jurisdiction, identifier, source_urls_json, regime)
                    │
                    ▼ (Status: PENDING)
[Any Caller] --> screen_entity(entity_id)
                    │
                    ├──> [Leader + Validators]
                    │      ├── Web GET (official regulatory sources)
                    │      ├── LLM Regulatory Entity Disambiguation
                    │      └── Equivalence Principle Agreement (Exact Match)
                    │
                    ▼ (Consensus: MAJORITY_AGREE)
[Contract State Updated]
  ├── ComplianceScreening receipt recorded
  └── Status transitions:
        ├── CLEARED               (verdict == CLEARED, confidence == 100)
        ├── SANCTIONED            (verdict == SANCTIONED, confidence == 100)
        ├── UNAVAILABLE           (sources unreachable, fail-closed)
        └── INVESTIGATION_PENDING (ambiguous, disambiguation needed, confidence == 0)
```

### State Definitions

| State | Description |
| :--- | :--- |
| `PENDING` | Entity registered with official HTTPS gazettes/registries; awaiting initial consensus screening. |
| `CLEARED` | Consensus confirmed entity is in good standing with zero active sanctions orders (`is_compliant == true`). |
| `SANCTIONED` | Consensus confirmed entity is designated under active blocking asset freeze (`is_sanctioned == true`). |
| `INVESTIGATION_PENDING` | Disambiguation required or non-responsive evidence (fails closed, `is_compliant == false`). |
| `UNAVAILABLE` | Official sources could not be reached (fails closed, `is_compliant == false`). |

---

## 3. Canonical Studionet Deployment

* **Contract Address:** [`0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53`](https://explorer-studio.genlayer.com/address/0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53)
* **Deployer:** `0xb3b09558183aec6c2ff5aa547163b77a9266010a` (`vixDeployer`)
* **Deploy Transaction:** `0x2e8bbc901183d7282914d5727ddf4c5143f6e1e3f95cd9e0116974edf0456555` (`MAJORITY_AGREE`, `ACCEPTED`)
* **Live Registration Tx:** `0xaf3c7208cda5457ac0aadb3030daae9dd7b5a885705c1ae657b727897901b03f` (`ACCEPTED`)
* **Live Screening Consensus Tx:** `0xf0a7eccf52c860570a4fafe612de61c9859c161eb96dbba077c5789ecfa4377e` (Verified receipt #1: `INVESTIGATION_PENDING`, canonical confidence 0, fails closed)

---

## 4. Verification & Testing

The repository provides a complete 3-tier testing framework:

### 4.1 Preflight Static Verification (16/16 Checks)
```bash
python scripts/preflight.py
```
Validates AST syntax, GenLayer decorators (`@allow_storage`, `@gl.public.write`, `@gl.public.view`), bounds constants, SSRF blocklists, fail-closed handlers, and strict builder isolation invariants.

### 4.2 Direct Mode Adversarial Unit Tests (15/15 Checks)
```bash
python -m pytest tests/direct/test_compliance_sanctions_sentinel.py -v
```
Simulates local GenVM execution with mocked web environments and adversarial LLM outputs:
- Input bounds validation (empty strings, oversized payloads, invalid JSON).
- SSRF exploit defense (`localhost`, `127.0.0.1`, `169.254.169.254`, `.internal`).
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
Queries canonical contract `0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53` on Studionet via JSON-RPC and validates live contract schema, entity state, consensus screening receipt, downstream clearance gates, and total counter bounds.

---

## 5. Security & Threat Mitigation

- **SSRF Hardening**: Prohibits plain HTTP, loopback IPs, cloud metadata IPs, and private subnet ranges.
- **Fail-Closed Guarantees**: Any source fetch failure defaults to `UNAVAILABLE` with 0 confidence, blocking downstream fund releases.
- **Equivalence Principle Exact Binding**: Exact match enforced on categorical verdicts, discrete confidence scores, material compliance outcomes, and material sanctions outcomes.
- **Bounded State & Inputs**: All strings and excerpts strictly capped to prevent gas spikes and memory exhaustion.

---

## 6. Project Layout

```text
ComplianceSanctionsSentinel/
├── contracts/
│   └── compliance_sanctions_sentinel.py           # Canonical Intelligent Contract v1.0.1
├── docs/
│   ├── CONSENSUS.md                               # Equivalence principle & exact consensus binding
│   ├── DEPLOYMENT.md                              # Studionet addresses & transaction receipts
│   ├── INTEGRATION.md                             # Solidity & Web3 consumer guide
│   └── SECURITY.md                                # Threat model & threshold drift defense
├── fixtures/
│   ├── cleared_entity_filing.md                   # Sample good standing certificate
│   ├── regulatory_gazette_notice.md               # Sample official gazette notice
│   └── sanctions_enforcement_order.md             # Sample blocking order fixture
├── scripts/
│   ├── deploy_studionet.py                        # Studionet deployment script
│   ├── preflight.py                               # 16-point static assertion verifier
│   ├── register_live_entity.py                    # Entity registration runner
│   └── screen_live_entity.py                      # Multi-validator consensus screening
├── tests/
│   ├── conftest.py                                # GenVM test harness
│   ├── direct/
│   │   └── test_compliance_sanctions_sentinel.py # 15 Direct mode tests
│   └── integration/
│       └── test_compliance_sanctions_sentinel_studionet.py # 5 Studionet RPC tests
├── DECISION.md                                    # Architecture & thesis
├── LICENSE                                        # MIT (vix)
├── README.md                                      # Primary project documentation
├── SUBMISSION.md                                  # Official hackathon submission brief
└── gltest.config.yaml                             # gltest network configuration
```

---

## 7. License

MIT License. Copyright (c) 2026 vix.
