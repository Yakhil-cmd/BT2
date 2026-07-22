[File: 'metric-periphery/contracts/interfaces/IMetricOmmSwapQuoter.sol -> Scope: Critical. Unprivileged or semi-trusted pool-admin path bypasses fee caps, provider timelock, or pause boundaries and causes direct loss of funds.'] [Symbol: MetricOmmSwapQuoter._validateQuotePath] Can attacker-controlled fake pool address under no factory-registry check in _validateQuotePath reach poolsAreConnected via getImmutables() and violate canonical-pool

### Citations

**File:** metric-periphery/contracts/interfaces/IMetricOmmSwapQuoter.sol (L1-33)
```text
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {IMetricOmmSwapCallback} from
