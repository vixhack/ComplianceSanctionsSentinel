# GenLayer Intelligent Contract Submission (v1.0.1)

## Basic Information

- **Contract Name**: ComplianceSanctionsSentinel
- **Builder / Submitter**: vix
- **Category**: Decentralized Infrastructure / Compliance & Security / Real World Assets (RWA)
- **License**: MIT
- **Canonical Address**: `0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53`
- **Network**: GenLayer Studionet (Chain ID `61999`)
- **Explorer Link**: [https://explorer-studio.genlayer.com/address/0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53](https://explorer-studio.genlayer.com/address/0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53)

---

## 280-Character Short Pitch

> ComplianceSanctionsSentinel screens counterparties against official regulatory gazettes & sanctions orders. Validators independently fetch gazette texts, disambiguate corporate targets, and reach exact consensus on discrete compliance buckets (100 vs 0).

---

## Long Description

Real World Asset (RWA) protocols, tokenized treasuries (e.g. Ondo USDY, BlackRock BUIDL), and institutional DeFi lending pools require verifiable, tamper-proof compliance checks before disbursing loans, minting tokens, or releasing capital to institutional counterparties.

Conventional compliance solutions rely on centralized third-party APIs (Chainalysis, TRM Labs) or private admin multisigs, reintroducing the exact single point of failure and censorship risks that Web3 was created to eliminate.

`ComplianceSanctionsSentinel` solves this natively on GenLayer. Anyone can register a corporate or individual entity specifying legal name, jurisdiction, official corporate registration identifier (e.g. CRN, LEI, Tax ID), and authoritative regulatory regime (e.g. `OFAC`, `SWISS_SECO`) along with official regulatory registry endpoints.

GenLayer validators independently fetch official regulatory gazettes and asset freeze orders, execute semantic disambiguation to distinguish between lookalike trade names and genuine sanctioned targets, and reach consensus under the **Equivalence Principle**.

### Consensus Architecture & Downstream Binding
- **Discrete Canonical Confidence**:
  - `CLEARED`: Canonical confidence **`100`** (`is_compliant` = `True`)
  - `SANCTIONED`: Canonical confidence **`100`** (`is_sanctioned` = `True`)
  - `INVESTIGATION_PENDING`: Canonical confidence **`0`** (fails closed, `is_compliant` = `False`, `is_sanctioned` = `False`)
  - `UNAVAILABLE`: Canonical confidence **`0`** (fails closed, `is_compliant` = `False`, `is_sanctioned` = `False`)
- **Exact Validator Agreement**:
  In `validate()`, validators require exact agreement on the canonical verdict, discrete confidence, material compliance outcome, and material sanctions outcome, eliminating any threshold-crossing drift.
- **Auditable Equivalence View**:
  Exposes `@gl.public.view def validate_equivalence(leader_json, validator_json) -> bool` for transparent on-chain auditing.

---

## Verified On-Chain Evidence

- **Deployment Tx**: `0x2e8bbc901183d7282914d5727ddf4c5143f6e1e3f95cd9e0116974edf0456555` (`MAJORITY_AGREE`, `ACCEPTED`)
- **Registration Tx**: `0xaf3c7208cda5457ac0aadb3030daae9dd7b5a885705c1ae657b727897901b03f` (`MAJORITY_AGREE`, `ACCEPTED`)
- **Live Multi-Validator Screening Consensus Tx**: `0xf0a7eccf52c860570a4fafe612de61c9859c161eb96dbba077c5789ecfa4377e` (`MAJORITY_AGREE`, `ACCEPTED`):
  - **Screening Receipt ID**: 1
  - **Entity ID**: 1 (`Ethereum Foundation`, `Switzerland`, `CHE-497.042.846`, `SWISS_SECO`)
  - **Verdict**: `INVESTIGATION_PENDING` (non-responsive technical evidence correctly identified by validators as non-gazette)
  - **Match Confidence**: `0` (discrete canonical confidence)
  - **Downstream Gate Verification**: `is_compliant(1) == False`, `is_sanctioned(1) == False` (fail-closed confirmed live on Studionet)

---

## Verification Reproducibility

1. **Preflight Static Verification**: `python scripts/preflight.py` (16/16 assertions pass).
2. **Direct Mode Adversarial Unit Tests**: `python -m pytest tests/direct/test_compliance_sanctions_sentinel.py -v` (15/15 tests pass).
3. **Studionet Integration Tests**: `python -m pytest tests/integration/test_compliance_sanctions_sentinel_studionet.py -v` (5/5 tests pass in 39.34s).
