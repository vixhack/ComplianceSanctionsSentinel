# Security & Threat Model (v1.1.0)

Author: vix

## 1. Threat Vectors & Defenses

`ComplianceSanctionsSentinel` operates in an adversarial environment where malicious actors may attempt to bypass KYC/sanctions checks, forge regulatory filings, probe internal validator network topologies, exploit open redirects, or obtain unwarranted clearance from arbitrary websites.

### 1.1 Authoritative Regulatory Provenance & Arbitrary HTTPS Page Defense (v1.1.0)
* **Threat:** A registrar submits a link to an arbitrary attacker-controlled HTTPS website (e.g. `https://my-arbitrary-blog.com/clean.html`) claiming that a sanctioned entity has no active sanctions, attempting to obtain a fraudulent `CLEARED` result.
* **Defense:**
  - Enforces authoritative domain provenance per regulatory regime (`AUTHORITATIVE_REGIME_DOMAINS`):
    - `OFAC`: `treasury.gov`, `treas.gov`, `trade.gov`, `federalregister.gov`, `state.gov`
    - `UK_OFSI`: `gov.uk`, `sanctionslist.service.gov.uk`, `ofsistorage.blob.core.windows.net`, `assets.publishing.service.gov.uk`, `legislation.gov.uk`
    - `EU_FSF`: `europa.eu`, `sanctionsmap.eu`, `data.europa.eu`, `eeas.europa.eu`, `eur-lex.europa.eu`, `ec.europa.eu`
    - `SWISS_SECO`: `admin.ch`, `seco.admin.ch`, `sesam.search.admin.ch`
    - `UN`: `un.org`, `scsanctions.un.org`, `press.un.org`
    - `GLOBAL`: Union of all authorized government & multilateral regulatory domains (`worldbank.org`, `interpol.int`, `bis.doc.gov`, `fbi.gov`).
  - Both `register_entity` and `update_sources` reject any non-authoritative URL with `gl.vm.UserError`.
  - In `_normalize_screening_payload`, a `CLEARED` outcome strictly requires `sources_checked > 0` from verified authoritative gazettes. If authority cannot be established or `sources_checked == 0`, the contract deterministically fails closed (`VERDICT_UNAVAILABLE`, confidence `0`).

### 1.2 Parsed Host/IP & Server-Side Request Forgery (SSRF) Defense (v1.1.0)
* **Threat:** Malicious actors attempt to submit URLs targeting validator private endpoints, internal microservices, loopback interfaces, or cloud instance metadata (`169.254.169.254`) using numeric representations, IPv6 encodings, or local domain names.
* **Defense:**
  - Structured URL parsing via `urllib.parse.urlsplit` and IP verification via `ipaddress.ip_address`.
  - Protocol must strictly be `https`.
  - Userinfo / credentials in URLs (`user:pass@host`) are forbidden.
  - Non-standard HTTPS ports (!= 443) are forbidden.
  - Raw IP destinations are forbidden for official regulatory sources.
  - Comprehensive IP safety checks (`_check_ip_safety`):
    - Loopback destinations (`127.0.0.0/8`, `::1`)
    - Private IP ranges (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, RFC 4193 `fc00::/7`)
    - Link-local destinations (`169.254.0.0/16`, `fe80::/10`)
    - Multicast destinations (`224.0.0.0/4`, `ff00::/8`)
    - Unspecified addresses (`0.0.0.0`, `::`)
    - Carrier-Grade NAT (RFC 6598 `100.64.0.0/10`)
    - Documentation / benchmark ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`, `2001:db8::/32`)
    - IPv4-mapped IPv6 destinations (`::ffff:0:0/96`)
  - Numeric integer and hexadecimal host representations are forbidden.
  - Prohibited host suffixes: `.localhost`, `.local`, `.internal`, `.intranet`, `.lan`, `.home`, `.corp`, `.arpa`, etc.

### 1.3 Redirect Validation Covering Private/Reserved Destinations (v1.1.0)
* **Threat:** An authoritative endpoint or open redirect redirects validators (via HTTP 3xx or HTML meta-refresh) to a private internal network resource or an unauthoritative external site.
* **Defense:**
  - In `evaluate()`, HTTP redirect status codes (301, 302, 303, 307, 308) and HTML meta-refresh tags are intercepted.
  - The redirect destination is parsed, joined, and subjected to the exact same network safety and regime authority validation as the initial URL.
  - If a redirect points to a private/reserved IP or an unauthorized domain, the source is discarded and the screening fails closed.

### 1.4 Downstream Decision Threshold Drift Mitigation
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
| `register_entity` | Any Address | Must provide valid bounds, identifier, authoritative regime, and approved HTTPS URLs |
| `screen_entity` | Any Address | Entity must exist and be active; executes multi-validator consensus |
| `update_sources` | Registrar Only | `gl.message.sender_address == entity.registrar`; requires authoritative URLs for regime |
| `deactivate_entity` | Registrar Only | `gl.message.sender_address == entity.registrar` |
| View methods | Public / Any | Zero state modification, gasless queries |
