# Canonical Deployment & Live Consensus Receipts (v1.1.0)

Author: vix

## 1. Studionet Network Profile

* **Network Name:** GenLayer Studionet
* **Chain ID:** `61999`
* **RPC Endpoint:** `https://studio.genlayer.com/api`
* **Block Explorer:** `https://explorer-studio.genlayer.com`

---

## 2. Canonical Contract Deployment

* **Contract Name:** `ComplianceSanctionsSentinel`
* **Contract Version:** `1.1.0`
* **Canonical Address:** `0x74eeB7232EBa3F55006D21BbF61A7e223517E350`
* **Deployer Address:** `0xb3b09558183aec6c2ff5aa547163b77a9266010a` (`vixDeployer`)
* **Deploy Transaction Hash:** `0x3eea3c5a13b5485ad1769e8b6129af0a510e5489715816a592c235557767b0ff`
* **Consensus Result:** `MAJORITY_AGREE` (Round 0, Status `ACCEPTED`)
* **Explorer Link:** [View Contract on Studionet Explorer](https://explorer-studio.genlayer.com/address/0x74eeB7232EBa3F55006D21BbF61A7e223517E350)

---

## 3. Live On-Chain Consensus Transactions

### 3.1 Entity Registration Transaction
* **Transaction ID:** `0xa6ea0e5f72fc282c5ac821ee6878781ebde7dc7715a1b7a05e6095fcf43502d6`
* **Method:** `register_entity`
* **Sender:** `0xb3b09558183aec6c2ff5aa547163b77a9266010a` (`vixDeployer`)
* **Parameters:**
  - **Name:** `"Ethereum Foundation"`
  - **Jurisdiction:** `"Switzerland"`
  - **Identifier:** `"CHE-497.042.846"`
  - **Authoritative Source:** `["https://www.seco.admin.ch/seco/en/home/Aussenwirtschaftspolitik_Wirtschaftliche_Zusammenarbeit/Wirtschaftsbeziehungen/exportkontrollen-und-sanktionen/sanktionen-embargos.html"]`
  - **Regulatory Regime:** `"SWISS_SECO"`
* **Consensus Status:** `ACCEPTED` (`MAJORITY_AGREE`)

### 3.2 Live Multi-Validator Compliance Screening
* **Transaction ID:** `0xe935d0d63a0f1fb1bb6a5fffc6d5b76d0ba9f64873d102df0fcb52ae3442e961`
* **Method:** `screen_entity(1)`
* **Consensus Status:** `ACCEPTED` (`MAJORITY_AGREE`)
* **Screening Receipt State:**
  ```json
  {
    "id": 1,
    "entity_id": 1,
    "verdict": "INVESTIGATION_PENDING",
    "match_confidence": 0,
    "regulatory_notes": "The provided official SECO source is only the sanctions search webpage shell/title ('Searching for subjects of sanctions') and does not include any search results or listing data for 'Ethereum Foundation' or identifier CHE-497.042.846. Based on the supplied evidence alone, there is no conclusive confirmation of a sanctions listing, asset freeze, or explicit clearance for the target entity.",
    "sources_checked": 1,
    "screened_at": 1792438772
  }
  ```
* **Downstream Gate Verification:**
  - `is_compliant(1) == False` (fails closed on non-cleared evidence)
  - `is_sanctioned(1) == False` (no active sanctions designation confirmed)
  - `latest_status(1) == ("INVESTIGATION_PENDING", 0)`

---

## 4. Live Studionet CLI Verification Commands

```powershell
# Read registered entity record #1
genlayer call 0x74eeB7232EBa3F55006D21BbF61A7e223517E350 get_entity --args 1

# Read consensus screening receipt #1
genlayer call 0x74eeB7232EBa3F55006D21BbF61A7e223517E350 get_screening --args 1

# Verify compliance gate
genlayer call 0x74eeB7232EBa3F55006D21BbF61A7e223517E350 is_compliant --args 1

# Verify sanctions gate
genlayer call 0x74eeB7232EBa3F55006D21BbF61A7e223517E350 is_sanctioned --args 1
```
