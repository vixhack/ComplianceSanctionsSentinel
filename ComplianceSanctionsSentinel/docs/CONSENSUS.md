# Consensus Architecture & Equivalence Principle Binding (v1.1.0)

Author: vix

## 1. Overview & Re-Architecture

`ComplianceSanctionsSentinel` v1.1.0 implements strict Equivalence Principle consensus binding between non-deterministic regulatory entity disambiguation and deterministic on-chain compliance gates:

1. **Authoritative Regulatory Regime Grounding**:
   Entities specify regulatory regimes (`OFAC`, `UK_OFSI`, `EU_FSF`, `SWISS_SECO`, `UN`, `GLOBAL`). Validators enforce authoritative domain provenance, guaranteeing that registrars cannot obtain a `CLEARED` result from arbitrary HTTPS pages.
2. **Parsed Host/IP & Recursive Redirect Validation**:
   Replaces substring checks with structured URL parsing and IP validation, defending against private/reserved IPv4/IPv6 destinations and open redirects.
3. **Elimination of Fuzzy Score Drift**:
   Confidence is mapped strictly to discrete canonical buckets (`100` for CLEARED/SANCTIONED, `0` for PENDING/UNAVAILABLE).
4. **Exact Consensus Agreement**:
   Validators in `validate()` must agree **EXACTLY** on the canonical verdict, discrete confidence bucket, material compliance outcome, and material sanctions outcome.

```
       +-----------------------------------------------------------+
       |                  GenLayer Studionet                       |
       |                                                           |
       |   Leader Node                      Validator Nodes        |
       |   +-----------------------+        +------------------+   |
       |   | 1. HTTP GET (auth)    |        | 1. Independent   |   |
       |   | 2. Redirect/SSRF Chk  |        |    Web Fetches   |   |
       |   | 3. Regulatory Entity  |        | 2. Redirect/SSRF |   |
       |   |    Matching Prompt    |        |    Validation    |   |
       |   | 4. Propose Verdict &  |        | 3. Equivalence   |   |
       |   |    Discrete Bucket    |        |    Verification  |   |
       |   +-----------+-----------+        +--------+---------+   |
       |               |                             |             |
       |               +--------------+--------------+             |
       |                              |                            |
       |                    Consensus Agreement                    |
       |                      (MAJORITY_AGREE)                     |
       |                              |                            |
       |                              v                            |
       |                  +-----------------------+                |
       |                  |  Deterministic State  |                |
       |                  |  - Canonical Scores   |                |
       |                  |    (100 vs 0)         |                |
       |                  |  - Screening Receipt  |                |
       |                  |  - Clearance Gates    |                |
       |                  +-----------------------+                |
       +-----------------------------------------------------------+
```

---

## 2. Non-Deterministic Boundary

Non-deterministic operations are encapsulated strictly within `gl.vm.run_nondet_unsafe(evaluate, validate)` during `screen_entity`:

1. **Official Regulatory Source Retrieval & Redirect Validation**:
   - Each validator node validates source URL network safety and regime authority before fetching.
   - HTTP 3xx redirects and HTML meta-refresh targets are recursively validated against private/reserved destinations and regime provenance.
   - Text bodies are sanitized, capped at `MAX_EXCERPT_CHARS = 2000`, and structured into labeled XML blocks (`<official_register_1>`, etc.).
   - If no official endpoints are reachable or if authority/network safety cannot be established, the node fails closed immediately with `VERDICT_UNAVAILABLE` and zero confidence.

2. **Entity Disambiguation & Sanctions Matching**:
   - Executed via `gl.nondet.exec_prompt(prompt, response_format="json")`.
   - The LLM compares target entity specifications (`name`, `jurisdiction`, `identifier`, `regulatory_regime`) against official regulatory evidence.
   - Strict output normalization maps results to discrete canonical buckets:
     - `CLEARED`: Canonical confidence **`100`** (strictly requires `sources_checked > 0`)
     - `SANCTIONED`: Canonical confidence **`100`** (strictly requires `sources_checked > 0`)
     - `INVESTIGATION_PENDING`: Canonical confidence **`0`**
     - `UNAVAILABLE`: Canonical confidence **`0`**

3. **Equivalence Principle & Custom Validator**:
   - The `validate(leader_result)` closure inspects leader proposed calldata against validator re-execution:
     ```python
     # Exact canonical verdict agreement
     if leader_val["verdict"] != validator_val["verdict"]:
         return False

     # Exact canonical discrete confidence agreement (100 vs 0)
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
     ```

---

## 3. Deterministic Boundary

Once multi-validator consensus resolves the screening payload, all state updates execute deterministically:

1. **Deterministic Entity Transitions**:
   - If `verdict == "SANCTIONED"`: entity status transitions to `SANCTIONED`.
   - If `verdict == "CLEARED"`: entity status transitions to `CLEARED`.
   - If `verdict == "UNAVAILABLE"`: entity status transitions to `UNAVAILABLE`.
   - All other conditions: entity status transitions to `INVESTIGATION_PENDING`.

2. **Auditable Verification**:
   External callers and auditors can run `@gl.public.view def validate_equivalence(leader_json, validator_json) -> bool` to independently inspect equivalence execution on-chain.
