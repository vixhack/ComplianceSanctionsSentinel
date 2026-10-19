# DECISION.md — ComplianceSanctionsSentinel

## 1. Executive Primitive Thesis

`ComplianceSanctionsSentinel` is a reusable GenLayer Intelligent Contract primitive that evaluates counterparty compliance and sanctions risk across official regulatory gazettes, enforcement registers, and sanctions bulletins. It establishes decentralized on-chain validator consensus on whether an individual or legal corporate entity is **SANCTIONED**, **CLEARED**, or under **INVESTIGATION_PENDING**, while resolving alias variations, corporate jurisdiction mismatches, and entity disambiguation.

---

## 2. Builder Identity & Isolation

- **Builder**: `vix`
- **Deployer Signer**: `vixDeployer` (`0xb3b09558183aec6c2ff5aa547163b77a9266010a`)
- **Dedicated Testers**: `vixTesterOne` (`0x3359ba0bcbe153b37f5d0c71359ca745405a112b`), `vixTesterTwo` (`0x9f1a87fcdf0f808dd122b5013d28e3a5ad76f56e`)
- **Delivery Protocol**: Local standalone preparation for manual drag-and-drop to vix GitHub account (zero CLI git history).

---

## 3. Portfolio Collision Audit

Collision audit across `vix`'s portfolio:

| Existing Contract | Core Trust Question | Evidence | Consensus Output | Overlap with ComplianceSanctionsSentinel? |
| :--- | :--- | :--- | :--- | :--- |
| `SyndicationFirewall` | Is submitted content original vs. syndicated vs. plagiarized? | Web article URL | Originality score & verdict (`ORIGINAL`, `SYNDICATED`, `PLAGIARIZED`) | **No** — Intellectual property & content verification |
| **`ComplianceSanctionsSentinel`** | **Is an entity subject to active sanctions or regulatory enforcement?** | **Official regulatory bulletins & gazettes** | **Sanctions determination (`CLEARED`, `SANCTIONED`, `INVESTIGATION_PENDING`)** | **NEW PRIMITIVE (Zero Collision)** |

---

## 4. Candidate Exploration & Selection Matrix

Ten candidate primitives evaluated during architecture scouting:

| Candidate Primitive | Core Trust Question | GenLayer Necessity (0-10) | State Reusability | Status / Rejection Rationale |
| :--- | :--- | :---: | :---: | :--- |
| 1. `ComplianceSanctionsSentinel` | Is an entity named in official sanctions gazettes or enforcement actions? | **10** | High | **SELECTED**: High-value compliance primitive for RWAs, DeFi pools, and cross-border settlement. |
| 2. `SocialCreditScore` | What is an entity's Twitter social reputation? | 3 | Low | **REJECTED**: Noisy, Sybil-prone social media sentiment. |
| 3. `KycSelfAttestation` | Did user complete passport KYC off-chain? | 5 | Low | **REJECTED**: Better handled via zero-knowledge proofs (zk-KYC). |
| 4. `CourtJudgmentRegistry` | Did a local civil court award damages? | 8 | Medium | **REJECTED**: Fragmented municipal court filings lack uniform web access. |
| 5. `TaxResidencyVerifier` | Is an entity a tax resident of country X? | 6 | Medium | **REJECTED**: Private sovereign tax records inaccessible to validators. |
| 6. `CreditRatingOracle` | What is corporate bond rating for issuer Y? | 4 | Medium | **REJECTED**: Simple numerical feed; existing oracles suffice. |
| 7. `RegulatoryLicenseValidator` | Does broker hold an active SEC/FCA license? | 8 | Medium | **REJECTED**: Covered as a sub-feature of sanctions/regulatory screening. |
| 8. `AntiMoneyLaunderingGraph` | Did address hop through privacy pools? | 5 | Low | **REJECTED**: On-chain graph analysis; belongs in native VM indexing. |
| 9. `TrademarkDisputeCourt` | Does applicant own trademark for domain Z? | 7 | Medium | **REJECTED**: ICANN dispute arbitration procedures exceed timeout bounds. |
| 10. `CarbonCreditRetirement` | Was renewable energy certificate retired? | 6 | Low | **REJECTED**: Centralized registry API numbers; lacks semantic consensus requirement. |

---

## 5. Candidate Scoring & The Delete-GenLayer Test

### Scoring Dimensions (0–10)
1. **GenLayer Necessity**: 10/10 — Official sanctions bulletins (OFAC notices, EU official journals, UK OFSI orders) are published in natural language, PDFs, and official legislative gazettes. Matching entity names against aliases, corporate registration numbers, and subsidiary hierarchies requires natural-language comprehension that EVM smart contracts cannot perform.
2. **Ecosystem Utility**: 10/10 — RWAs (Real World Assets) like BlackRock BUIDL, Ondo USDY, and institutional DeFi pools must legally verify counterparty sanctions compliance before processing distributions or token transfers.
3. **State Machine & Failure Bounds**: 10/10 — Fail-closed on unreachable government registries; strict tolerance on match confidence scores.

### The "Delete-GenLayer" Test
> *If GenLayer is removed, what exact trust property disappears?*
Without GenLayer, an RWA protocol verifying counterparty compliance must either:
1. Rely on a **centralized off-chain compliance vendor API** (e.g. Chainalysis or Elliptic), which creates a centralized point of failure, censorship vulnerability, and single-operator exploit risk.
2. Rely on an **off-chain admin multisig** that can arbitrarily censor users or collude with bad actors.

GenLayer is load-bearing because independent validators fetch the official regulatory bulletins, perform semantic identity matching, and achieve decentralized consensus under the **Equivalence Principle**.

---

## 6. The Three-Consumer Test

`ComplianceSanctionsSentinel` exposes a concise view interface (`is_compliant`, `is_sanctioned`, `latest_status`, `get_entity`) consumed by three distinct architectures:

1. **Permissioned RWA Institutional Lending Pool (e.g. Centrifuge / Maple)**:
   - Queries `is_compliant(entity_id)`.
   - Blocks deposit and borrow operations if the counterparty is not certified `CLEARED` with discrete canonical confidence 100.

2. **Cross-Border Compliant Stablecoin Transfer Gate**:
   - Queries `is_sanctioned(entity_id)`.
   - Freezes mint/burn operations if an entity transitions to `SANCTIONED` status following an official government executive order.

3. **Autonomous DAO Treasury Compliance Whitelist**:
   - Verifies contractor entities before treasury disbursements are approved by decentralized governance.

---

## 7. Hardest Technical Risk & Mitigation

- **Risk**: Entity Disambiguation (e.g. "Acme Trading Ltd" registered in UK vs "Acme Trading Corp" registered in Panama).
- **Mitigation**: The contract mandates registration of both `name`, `jurisdiction`, and unique `identifier` (e.g., LEI, CRN, or tax ID). The validator LLM prompt explicitly performs disambiguation: if name matches but jurisdiction/registration number differs, the entity is evaluated as `CLEARED` or `INVESTIGATION_PENDING` rather than false-positive `SANCTIONED`.
