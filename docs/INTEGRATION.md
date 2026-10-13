# Integration Guide & Consumer Patterns

`ComplianceSanctionsSentinel` provides a lightweight, composable view interface that enables RWA protocols, permissioned DeFi lending pools, and institutional stablecoin issuers to query on-chain compliance status without managing web retrieval or LLM inference.

---

## 1. On-Chain Solidity Consumer Pattern

Downstream EVM or GenLayer smart contracts can query `is_compliant` or `is_sanctioned` to guard sensitive financial operations:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IComplianceSentinel {
    function is_compliant(uint256 entityId) external view returns (bool);
    function is_sanctioned(uint256 entityId) external view returns (bool);
    function latest_status(uint256 entityId) external view returns (string memory verdict, uint32 matchConfidence);
}

contract CompliantRwaLendingPool {
    IComplianceSentinel public immutable complianceOracle;
    address public poolAdmin;

    mapping(address => uint256) public borrowerEntityIds;

    event LoanDisbursed(address indexed borrower, uint256 amount);

    constructor(address _oracle) {
        complianceOracle = IComplianceSentinel(_oracle);
        poolAdmin = msg.sender;
    }

    function registerBorrower(address borrower, uint256 entityId) external {
        require(msg.sender == poolAdmin, "Admin only");
        borrowerEntityIds[borrower] = entityId;
    }

    /// @notice Borrowers can only take loans if certified CLEARED on-chain
    function borrow(uint256 amount) external {
        uint256 entityId = borrowerEntityIds[msg.sender];
        require(entityId > 0, "Borrower not registered");

        // Verify active compliance
        bool compliant = complianceOracle.is_compliant(entityId);
        require(compliant, "Borrower does not have active CLEARED compliance attestation");

        // Failsafe check
        bool sanctioned = complianceOracle.is_sanctioned(entityId);
        require(!sanctioned, "Borrower is subject to active sanctions");

        emit LoanDisbursed(msg.sender, amount);
    }
}
```

---

## 2. Python Consumer Example

```python
from genlayer_py import GenLayerClient

RPC_URL = "https://studio.genlayer.com/api"
SENTINEL_ADDRESS = "0xCc33a4D359b3F9420d7835944F9DED9CA30010E4"

def verify_counterparty_compliance(entity_id: int):
    client = GenLayerClient(RPC_URL)
    
    # 1. Query compliance clearance gate
    compliant = client.call(SENTINEL_ADDRESS, "is_compliant", [entity_id])
    sanctioned = client.call(SENTINEL_ADDRESS, "is_sanctioned", [entity_id])
    verdict, confidence = client.call(SENTINEL_ADDRESS, "latest_status", [entity_id])

    print(f"Entity #{entity_id} Status: {verdict} (Confidence: {confidence}%)")
    print(f"Is Compliant: {compliant} | Is Sanctioned: {sanctioned}")

    if compliant:
        print("Entity certified CLEARED. Proceeding with transfer.")
    else:
        print("Compliance check failed or pending investigation. Freezing transaction.")
```

---

## 3. JavaScript / GenLayer-JS Integration

```typescript
import { createClient } from "genlayer-js";

const client = createClient({ endpoint: "https://studio.genlayer.com/api" });
const SENTINEL_ADDRESS = "0xCc33a4D359b3F9420d7835944F9DED9CA30010E4";

async function checkEntity(entityId: number) {
  const isCompliant = await client.readContract({
    address: SENTINEL_ADDRESS,
    functionName: "is_compliant",
    args: [entityId],
  });

  if (isCompliant) {
    console.log(`Entity ${entityId} is cleared for RWA operations.`);
  } else {
    console.log(`Entity ${entityId} requires screening or investigation.`);
  }
}
```
