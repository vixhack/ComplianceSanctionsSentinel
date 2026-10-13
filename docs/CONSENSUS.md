# Consensus Architecture & Equivalence Principle Binding (v1.0.1)

Author: vix

## 1. Overview & Re-Architecture

`ComplianceSanctionsSentinel` v1.0.1 implements strict Equivalence Principle consensus binding between non-deterministic regulatory entity disambiguation and deterministic on-chain compliance gates:

1. **Elimination of Fuzzy Score Drift**:
   In v1.0.0, a $\pm 15$ point confidence tolerance allowed a leader score of 75 (cleared) and validator score of 62 (not cleared) to both pass consensus, creating downstream ambiguity. In v1.0.1, confidence is mapped strictly to discrete canonical buckets (`100` for CLEARED/SANCTIONED, `0` for PENDING/UNAVAILABLE).
2. **Exact Consensus Agreement**:
   Validators in `validate()` must agree **EXACTLY** on the canonical verdict, discrete confidence bucket, material compliance outcome, and material sanctions outcome.
3. **Regulatory Regime Grounding**:
   Entities specify authoritative regulatory regimes (`OFAC`, `EU_FSF`, `UK_OFSI`, `UN_SC`, `SWISS_SECO`, `GLOBAL`). Validators independently fetch and audit official gazette text.

```
       +-----------------------------------------------------------+
       |                  GenLayer Studionet                       |
       |                                                           |
       |   Leader Node                      Validator Nodes        |
       |   +-----------------------+        +------------------+   |
       |   | 1. HTTP GET (urls)    |        | 1. Independent   |   |
       |   | 2. Regulatory Entity  |        |    Web Fetches   |   |
       |   |    Matching Prompt    |        | 2. Equivalence   |   |
       |   | 3. Propose Verdict &  |        |    Verification  |   |
       |   |    Discrete Bucket    |        |    (Exact Match) |   |
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

1. **Official Regulatory Source Retrieval**:
   - Each validator node independently executes `gl.nondet.web.get(u)` for all registered regulatory URLs.
   - Text bodies are sanitized, capped at `MAX_EXCERPT_CHARS = 2000`, and structured into labeled XML blocks (`<official_register_1>`, etc.).
   - If no official endpoints are reachable, the node fails closed immediately with `VERDICT_UNAVAILABLE` and zero confidence.

2. **Entity Disambiguation & Sanctions Matching**:
   - Executed via `gl.nondet.exec_prompt(prompt, response_format="json")`.
   - The LLM compares target entity specifications (`name`, `jurisdiction`, `identifier`, `regulatory_regime`) against official regulatory evidence.
   - Strict output normalization maps results to discrete canonical buckets:
     - `CLEARED`: Canonical confidence **`100`**
     - `SANCTIONED`: Canonical confidence **`100`**
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

2. **Downstream Clearance Gates (`is_compliant`, `is_sanctioned`)**:
   - Pure view functions that verify active status and high-confidence receipt values:
     ```python
     # is_compliant
     return entity.active and entity.status == STATUS_CLEARED and receipt.verdict == VERDICT_CLEARED and receipt.match_confidence == 100

     # is_sanctioned
     return entity.active and entity.status == STATUS_SANCTIONED and receipt.verdict == VERDICT_SANCTIONED and receipt.match_confidence == 100
     ```

3. **Public Auditable View**:
   - `@gl.public.view def validate_equivalence(leader_json, validator_json) -> bool` exposes the deterministic equivalence verification logic for third-party explorers and verification pipelines.
