# GenLayer Intelligent Contract Submission (v1.1.0)

## Basic Information

- **Contract Name**: ComplianceSanctionsSentinel
- **Builder / Submitter**: vix
- **Category**: Decentralized Infrastructure / Compliance & Security / Real World Assets (RWA)
- **License**: MIT
- **Canonical Address**: `0x74eeB7232EBa3F55006D21BbF61A7e223517E350`
- **Network**: GenLayer Studionet (Chain ID `61999`)
- **Explorer Link**: [https://explorer-studio.genlayer.com/address/0x74eeB7232EBa3F55006D21BbF61A7e223517E350](https://explorer-studio.genlayer.com/address/0x74eeB7232EBa3F55006D21BbF61A7e223517E350)
- **Deployer Account**: `0xb3b09558183aec6c2ff5aa547163b77a9266010a` (`vixDeployer`)

---

## 280-Character Short Pitch

> ComplianceSanctionsSentinel screens counterparties against official regulatory gazettes across OFAC, UK_OFSI, EU_FSF, SECO, and UN regimes. Validators enforce parsed host/IP safety, redirect validation, and reach exact consensus on discrete compliance buckets (100 vs 0).

---

## Long Description

Real World Asset (RWA) protocols, tokenized treasuries (e.g. Ondo USDY, BlackRock BUIDL), and institutional DeFi lending pools require verifiable, tamper-proof compliance checks before disbursing loans, minting tokens, or releasing capital to institutional counterparties.

Conventional compliance solutions rely on centralized third-party APIs (Chainalysis, TRM Labs) or private admin multisigs, reintroducing the exact single point of failure and censorship risks that Web3 was created to eliminate.

`ComplianceSanctionsSentinel` solves this natively on GenLayer. Anyone can register a corporate or individual entity specifying legal name, jurisdiction, official corporate registration identifier (e.g. CRN, LEI, Tax ID), and authoritative regulatory regime (e.g. `OFAC`, `UK_OFSI`, `EU_FSF`, `SWISS_SECO`, `UN`, `GLOBAL`) along with official regulatory registry endpoints.

GenLayer validators independently fetch official regulatory gazettes and asset freeze orders, execute semantic disambiguation to distinguish between lookalike trade names and genuine sanctioned targets, and reach consensus under the **Equivalence Principle**.

---

## Response to Steward Request & Security Architecture (v1.1.0)

In response to the steward's guidance on authoritative provenance and network safety:

### 1. Authoritative Sanctions-Source Provenance per Regulatory Regime
- **Provenance Registry**: Implemented `AUTHORITATIVE_REGIME_DOMAINS` mapping supported regulatory regimes (`OFAC`, `UK_OFSI`, `EU_FSF`, `SWISS_SECO`, `UN`, `GLOBAL`) to official government and multilateral regulatory gazette domains (e.g., `treasury.gov`, `gov.uk`, `europa.eu`, `admin.ch`, `un.org`, `worldbank.org`, `interpol.int`).
- **Enforced at Ingestion and Screening**: Both `register_entity` and `update_sources` validate that submitted URLs strictly match the authoritative domains for the entity's declared regime.
- **Arbitrary HTTPS Pages Prevented**: A registrar cannot obtain a `CLEARED` result from an arbitrary HTTPS page. In `_normalize_screening_payload`, a `CLEARED` outcome requires `sources_checked > 0` from verified authoritative gazettes. If authority cannot be established or `sources_checked == 0`, the contract deterministically fails closed (`VERDICT_UNAVAILABLE`, confidence `0`).

### 2. Parsed Host/IP and Comprehensive SSRF Defenses
- Replaced the substring blocklist with structured URL decomposition via `urllib.parse.urlsplit` and IP validation via `ipaddress.ip_address`.
- Rejects non-HTTPS schemes, userinfo/credentials in URLs (`user:pass@host`), and non-standard HTTPS ports.
- Blocks raw IP destinations and rigorously inspects IPv4 and IPv6 destinations for:
  - Loopback (`127.0.0.0/8`, `::1`)
  - Private ranges (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, RFC 4193 `fc00::/7`)
  - Link-local (`169.254.0.0/16`, `fe80::/10`)
  - Multicast (`224.0.0.0/4`, `ff00::/8`)
  - Unspecified (`0.0.0.0`, `::`)
  - Carrier-Grade NAT (RFC 6598 `100.64.0.0/10`)
  - Documentation / benchmark ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`, `2001:db8::/32`)
  - IPv4-mapped IPv6 addresses (`::ffff:0:0/96`)
  - Numeric integer and hexadecimal host representations
  - Local/internal host domain suffixes (`.localhost`, `.local`, `.internal`, `.lan`, `.corp`, etc.)

### 3. Redirect Validation Covering Private/Reserved Destinations
- In `evaluate()`, HTTP 3xx redirect status codes (301, 302, 303, 307, 308) and HTML meta-refresh redirect tags are intercepted.
- Redirect targets are parsed, resolved against the origin URL, and re-validated against parsed host/IP network safety and authoritative regime provenance before being fetched.
- If a redirect attempts to reach a private/reserved IP or an unauthoritative domain, the source is discarded and the screening fails closed.

### 4. Consensus Invariance & Equivalence Principle
- **Discrete Canonical Confidence**:
  - `CLEARED`: Canonical confidence **`100`** (`is_compliant` = `True`)
  - `SANCTIONED`: Canonical confidence **`100`** (`is_sanctioned` = `True`)
  - `INVESTIGATION_PENDING`: Canonical confidence **`0`** (fails closed, `is_compliant` = `False`, `is_sanctioned` = `False`)
  - `UNAVAILABLE`: Canonical confidence **`0`** (fails closed, `is_compliant` = `False`, `is_sanctioned` = `False`)
- **Zero Threshold-Crossing Drift**:
  Validators in `validate()` must reach exact agreement on canonical verdict, discrete confidence bucket, material compliance outcome, and material sanctions outcome.
- **Public Auditing View**:
  Exposes `@gl.public.view def validate_equivalence(leader_json, validator_json) -> bool`.

---

## Verified On-Chain Evidence on Studionet

- **Deployment Transaction**:
  - Tx Hash: `0x3eea3c5a13b5485ad1769e8b6129af0a510e5489715816a592c235557767b0ff`
  - Consensus: `MAJORITY_AGREE`, Status: `ACCEPTED`
  - Canonical Contract Address: `0x74eeB7232EBa3F55006D21BbF61A7e223517E350`
  - Explorer: [https://explorer-studio.genlayer.com/address/0x74eeB7232EBa3F55006D21BbF61A7e223517E350](https://explorer-studio.genlayer.com/address/0x74eeB7232EBa3F55006D21BbF61A7e223517E350)
- **Entity Registration Transaction**:
  - Tx Hash: `0xa6ea0e5f72fc282c5ac821ee6878781ebde7dc7715a1b7a05e6095fcf43502d6`
  - Consensus: `MAJORITY_AGREE`, Status: `ACCEPTED`
  - Registered Target: `Ethereum Foundation`, `Switzerland`, `CHE-497.042.846`, `SWISS_SECO`
  - Authoritative Source: `https://www.seco.admin.ch/seco/en/home/Aussenwirtschaftspolitik_Wirtschaftliche_Zusammenarbeit/Wirtschaftsbeziehungen/exportkontrollen-und-sanktionen/sanktionen-embargos.html`
- **Live Multi-Validator Screening Consensus Transaction**:
  - Tx Hash: `0xe935d0d63a0f1fb1bb6a5fffc6d5b76d0ba9f64873d102df0fcb52ae3442e961`
  - Consensus: `MAJORITY_AGREE`, Status: `ACCEPTED`
  - Screening Receipt ID: 1
  - Verdict: `INVESTIGATION_PENDING` (Discrete Confidence: `0`)
  - Sources Checked: 1
  - Live Gate Verification: `is_compliant(1) == False`, `is_sanctioned(1) == False` (Fail-closed verified on-chain)

---

## Verification Reproducibility

1. **Preflight Static Verification**:
   ```bash
   python scripts/preflight.py
   # 16/16 assertions pass
   ```
2. **Direct Mode Unit Tests**:
   ```bash
   python -m pytest tests/direct/test_compliance_sanctions_sentinel.py -v
   # 16/16 tests pass
   ```
3. **Studionet Integration Tests**:
   ```bash
   python -m pytest tests/integration/test_compliance_sanctions_sentinel_studionet.py -v
   # 5/5 live Studionet integration tests pass
   ```
