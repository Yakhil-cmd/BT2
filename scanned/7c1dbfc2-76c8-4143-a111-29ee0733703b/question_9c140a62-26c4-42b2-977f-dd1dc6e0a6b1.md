[File: 'L1/starkware/solidity/components/Roles.sol'] [Function: registerGovernanceAdmin / registerAppRoleAdmin / registerTokenAdmin / MintManager.setMintingAllowance / MintManager.mintRequest] Can an attacker who obtains GOVERNANCE_ADMIN via initialization front-run execute the full escalation chain registerGovernanceAdmin(attacker) -> registerAppRoleAdmin(attacker) -> registerTokenAdmin(attacker) -> setMintingAllowance(token, attacker, PERIOD_MINT_CAP) -> mintRequest(token, PERIOD_MINT_CAP), under the precondition that attacker is also a registered

### Citations

**File:** L1/starkware/solidity/components/Roles.sol (L1-50)
```text
// SPDX-License-Identifier: Apache-2.0.
pragma solidity ^0.8.0;

import
