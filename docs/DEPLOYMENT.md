# Canonical Deployment & Live Consensus Receipts (v1.0.1)

Author: vix

## 1. Studionet Network Profile

* **Network Name:** GenLayer Studionet
* **Chain ID:** `61999`
* **RPC Endpoint:** `https://studio.genlayer.com/api`
* **Block Explorer:** `https://explorer-studio.genlayer.com`

---

## 2. Canonical Contract Deployment

* **Contract Name:** `ComplianceSanctionsSentinel`
* **Contract Version:** `1.0.1`
* **Canonical Address:** `0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53`
* **Deployer Address:** `0xb3b09558183aec6c2ff5aa547163b77a9266010a` (`vixDeployer`)
* **Deploy Transaction Hash:** `0x2e8bbc901183d7282914d5727ddf4c5143f6e1e3f95cd9e0116974edf0456555`
* **Consensus Result:** `MAJORITY_AGREE` (Round 0, Status `ACCEPTED`)
* **Explorer Link:** [View Contract on Studionet Explorer](https://explorer-studio.genlayer.com/address/0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53)

---

## 3. Live On-Chain Consensus Transactions

### 3.1 Entity Registration Transaction
* **Transaction ID:** `0xaf3c7208cda5457ac0aadb3030daae9dd7b5a885705c1ae657b727897901b03f`
* **Method:** `register_entity`
* **Sender:** `0xb3b09558183aec6c2ff5aa547163b77a9266010a` (`vixDeployer`)
* **Parameters:**
  - **Name:** `"Ethereum Foundation"`
  - **Jurisdiction:** `"Switzerland"`
  - **Identifier:** `"CHE-497.042.846"`
  - **Sources:** `["https://raw.githubusercontent.com/github/gitignore/main/Python.gitignore"]`
  - **Regulatory Regime:** `"SWISS_SECO"`
* **Consensus Status:** `ACCEPTED` (`MAJORITY_AGREE`)

### 3.2 Live Multi-Validator Compliance Screening
* **Transaction ID:** `0xf0a7eccf52c860570a4fafe612de61c9859c161eb96dbba077c5789ecfa4377e`
* **Method:** `screen_entity(1)`
* **Consensus Status:** `ACCEPTED` (`MAJORITY_AGREE`)
* **Screening Receipt State:**
  ```json
  {
    "id": 1,
    "entity_id": 1,
    "verdict": "INVESTIGATION_PENDING",
    "match_confidence": 0,
    "regulatory_notes": "The provided official source is a Python .gitignore file from a GitHub repository, not a Swiss SECO sanctions, asset-freeze, or enforcement register. It contains no reference to 'Ethereum Foundation', 'CHE-497.042.846', or any sanctions determination. Therefore the evidence is non-responsive and insufficient to conclusively classify the target under the SWISS_SECO regime.",
    "sources_checked": 1,
    "screened_at": 1791853553
  }
  ```
* **Downstream Gate Verification:**
  - `is_compliant(1) == False` (fails closed on non-responsive official source)
  - `is_sanctioned(1) == False` (no active sanctions listing)
  - `latest_status(1) == ("INVESTIGATION_PENDING", 0)`

---

## 4. Live Studionet CLI Verification Commands

```powershell
# Read registered entity record #1
genlayer call 0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53 get_entity --args 1

# Read consensus screening receipt #1
genlayer call 0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53 get_screening --args 1

# Verify compliance gate
genlayer call 0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53 is_compliant --args 1

# Verify sanctions gate
genlayer call 0xA51BfC839a0D9564c5A1A328036FA526DB1ccD53 is_sanctioned --args 1
```
