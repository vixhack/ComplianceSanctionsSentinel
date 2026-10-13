# Security & Threat Model (v1.0.1)

Author: vix

## 1. Threat Vectors & Defenses

`ComplianceSanctionsSentinel` operates in an adversarial environment where malicious actors may attempt to bypass KYC/sanctions checks, forge regulatory filings, probe internal validator network topologies, or exploit ambiguities in entity names.

### 1.1 Server-Side Request Forgery (SSRF)
* **Threat:** Malicious actors attempt to submit URLs targeting validator private endpoints, internal microservices, or cloud instance metadata (`169.254.169.254`) to exfiltrate validator private keys.
* **Defense:** Strict URL verification before state admission:
  - Protocol must strictly start with `https://`.
  - Prohibited hosts and IP blocklists:
    - `://localhost`, `://127.0.0.1`, `://0.0.0.0`
    - Cloud metadata: `://169.254.169.254`
    - Private IP ranges: `://10.`, `://192.168.`, `://172.16.` through `://172.20.`
    - Internal TLDs: `.internal`, `.local`
  - Strict length capping (`MAX_URL_LENGTH = 2048`).

### 1.2 Entity Disambiguation & Jurisdiction Spoofing
* **Threat:** A sanctioned entity creates a lookalike shell company in another jurisdiction with the same trade name (e.g., "Volga Metals Corp" in Seychelles vs "Volga Strategic Metals CJSC" in Moscow) to claim false clearance or trigger false-positive competitor freezes.
* **Defense:**
  - Registration requires four binding fields: `name`, `jurisdiction`, unique `identifier` (e.g. CRN, LEI, or Tax ID), and `regulatory_regime` (e.g. `OFAC`, `SWISS_SECO`).
  - The validator LLM prompt explicitly analyzes jurisdictional and registration alignment:
    - If trade name is similar but jurisdiction or corporate identifier differs, the entity is evaluated as `INVESTIGATION_PENDING` rather than `SANCTIONED` or `CLEARED`.
    - Downstream gates (`is_compliant`) fail closed on `INVESTIGATION_PENDING`.

### 1.3 Denial-of-Service (DoS) via Payload Inflation
* **Threat:** Adversaries submit multi-megabyte gazette texts to exhaust node memory and gas limits.
* **Defense:**
  - Strict input limits: `MAX_NAME_LENGTH = 128`, `MAX_JURISDICTION_LENGTH = 64`, `MAX_IDENTIFIER_LENGTH = 64`, `MAX_REGIME_LENGTH = 32`.
  - Max sources per entity: `MAX_SOURCES_COUNT = 5`.
  - Body excerpt cap: `MAX_EXCERPT_CHARS = 2000` per source.
  - Overall prompt length bounded to safe limits.

### 1.4 Downstream Decision Threshold Drift Mitigation (v1.0.1)
* **Threat:** Continuous numerical scores differing by tolerance cross decision boundaries (e.g. Leader = 75 -> Cleared, Validator = 62 -> Not Cleared).
* **Defense:**
  - Replaced continuous scores with **discrete canonical confidence buckets**:
    - `CLEARED`: Canonical confidence **`100`**
    - `SANCTIONED`: Canonical confidence **`100`**
    - `INVESTIGATION_PENDING`: Canonical confidence **`0`**
    - `UNAVAILABLE`: Canonical confidence **`0`**
  - In `validate()`, validators enforce **EXACT agreement** on:
    - Canonical `verdict`
    - Discrete `match_confidence` (100 vs 0)
    - Material compliance outcome (`is_compliant` equivalence)
    - Material sanctions outcome (`is_sanctioned` equivalence)
  - Zero tolerance window across decision boundaries.

---

## 2. Access Control Model

| Method | Role | Restriction / Condition |
| :--- | :--- | :--- |
| `register_entity` | Any Address | Must provide valid bounds, identifier, regulatory regime, and HTTPS URLs |
| `screen_entity` | Any Address | Entity must exist and be active; executes multi-validator consensus |
| `update_sources` | Registrar Only | `gl.message.sender_address == entity.registrar` |
| `deactivate_entity` | Registrar Only | `gl.message.sender_address == entity.registrar` |
| View methods | Public / Any | Zero state modification, gasless queries |
