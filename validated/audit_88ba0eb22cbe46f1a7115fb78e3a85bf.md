I was unable to complete the full investigation — I ran out of tool calls before reading the `collectFees` implementation bodies in `MetricOmmPool.sol` and `MetricOmmPoolFactory.sol`. I could not verify whether a sign-error analog (e.g., a negated or inverted amount check that causes fee collection to always revert or silently skip) exists in those functions.

**What was confirmed:**
- `collectFees` in `IMetricOmmPoolCollectFees.sol` accepts protocol/admin fee rates and an `adminFeeDestination` [1](#0-0) 
- The factory (`MetricOmmPoolFactory.sol`) is the sole authorized caller of `collectFees` on pools [2](#0-1) 
- The implementation bodies in `MetricOmmPool.sol` and `MetricOmmPoolFactory.sol` were not read

**What remains unknown:**
- Whether the actual `collectFees` or `_redeemAndTransfer`-equivalent logic in `MetricOmmPool.sol` contains a sign inversion on transfer amounts
- Whether any `> 0` / `< 0` guard on a fee transfer amount is applied to a value whose sign convention makes it always fail

Without reading those implementation bodies, I cannot responsibly assert a finding or a clean rejection. A Devin session with full file access to `metric-core/contracts/MetricOmmPool.sol` (fee collection section) and `metric-core/contracts/MetricOmmPoolFactory.sol` (the `collectFees` call site) is needed to complete this audit pivot.

### Citations

**File:** metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolCollectFees.sol (L6-6)
```text
/// @dev Only `MetricOmmPoolFactory` should call this; the pool enforces `msg.sender == FACTORY`. Emits `ProtocolFeesCollected` with token amounts allocated to protocol vs admin destinations according to the rates passed in.
```

**File:** metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolCollectFees.sol (L27-33)
```text
  function collectFees(
    uint256 protocolSpreadFeeE6,
    uint256 adminSpreadFeeE6,
    uint256 protocolNotionalFeeE8,
    uint256 adminNotionalFeeE8,
    address adminFeeDestination
  ) external;
```
