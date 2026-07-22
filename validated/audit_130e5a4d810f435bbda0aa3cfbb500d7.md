I have found the vulnerability. Let me verify the exact lines before writing the final output.

### Title
`setPoolAdminFeeDestination` Retroactively Redirects Already-Accrued Admin Fees to New Destination Without Prior Collection - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`setPoolAdminFeeDestination` overwrites `poolAdminFeeDestination[pool]` immediately without first flushing accrued fees to the old destination. Every other fee-parameter mutator (`setPoolAdminFees`, `setPoolProtocolFee`) calls `collectFees` with the current destination before making any change. The omission in `setPoolAdminFeeDestination` means all spread surplus and notional fee accumulator balances that accrued under the old destination are silently redirected to the new one on the next collection.

### Finding Description

`MetricOmmPoolFactory.setPoolAdminFeeDestination` (lines 438–447) is the only fee-configuration mutator that does not call `collectFees` before modifying its parameter:

```solidity
// MetricOmmPoolFactory.sol L438-447
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
  poolAdminFeeDestination[pool] = newAdminFeeDestination;   // ❌ no prior collectFees
  emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

Compare with `setPoolAdminFees` (lines 408–435), which explicitly flushes accrued fees to the old destination before updating rates:

```solidity
// MetricOmmPoolFactory.sol L418-425
IMetricOmmPoolCollectFees(pool).collectFees(
  c.protocolSpreadFeeE6,
  c.adminSpreadFeeE6,
  c.protocolNotionalFeeE8,
  c.adminNotionalFeeE8,
  poolAdminFeeDestination[pool]   // ✅ old destination used before change
);
```

`setPoolProtocolFee` (lines 318–360) follows the same correct pattern.

The pool's `collectFees` function distributes the entire current spread surplus and notional fee accumulators (`notionalFeeToken0Scaled`, `notionalFeeToken1Scaled`) to whichever `adminFeeDestination_` is passed at call time. Because `setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` before any flush, the next call to `collectPoolFees` (or any fee-changing function that triggers collection) will send all previously accrued admin fees to the new address.

### Impact Explanation

The old admin fee destination loses all fees that accrued during its tenure. The new destination receives those fees instead. This is a direct, quantifiable loss of ERC-20 principal for the old fee recipient. The magnitude equals the full admin share of all spread surplus and notional fees accumulated since the last collection — potentially large for high-volume pools with infrequent collection.

### Likelihood Explanation

The pool admin is a semi-trusted role. The admin legitimately needs to change the fee destination (e.g., rotating a treasury address, updating a revenue-sharing contract). The bug fires on every such routine operation, not only in adversarial scenarios. A malicious admin can also exploit it deliberately: accumulate fees for a long period, then atomically redirect the destination to their own address before triggering collection, stealing the entire accrued admin balance from the intended recipient.

### Recommendation

Mirror the pattern used by `setPoolAdminFees` and `setPoolProtocolFee`: collect accrued fees to the old destination before updating the mapping.

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
  external override nonReentrant onlyPoolAdmin(pool)
{
  if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

  // ✅ flush accrued fees to the OLD destination first
  PoolFeeConfig memory c = poolFeeConfig[pool];
  IMetricOmmPoolCollectFees(pool).collectFees(
    c.protocolSpreadFeeE6,
    c.adminSpreadFeeE6,
    c.protocolNotionalFeeE8,
    c.adminNotionalFeeE8,
    poolAdminFeeDestination[pool]
  );

  poolAdminFeeDestination[pool] = newAdminFeeDestination;
  emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

### Proof of Concept

1. Pool is deployed with `adminFeeDestination = A` (e.g., a revenue-sharing partner).
2. Swaps occur; spread surplus and notional fee accumulators grow. No `collectPoolFees` is called.
3. Pool admin calls `setPoolAdminFeeDestination(pool, B)` where `B` is the admin's own wallet.
   - `poolAdminFeeDestination[pool]` is immediately overwritten to `B`.
   - No fees are flushed to `A`.
4. Anyone calls `collectPoolFees(pool)`.
   - `collectFees` is invoked with `adminFeeDestination_ = B` (the new value).
   - All spread surplus and notional fees that accrued while `A` was the destination are transferred to `B`.
   - `A` receives nothing.

**Corrupted value:** `poolAdminFeeDestination[pool]` is updated before the accrued fee state is settled, causing `collectFees` to route the admin share of `surplus0Scaled`, `surplus1Scaled`, `notionalFeeToken0Scaled`, and `notionalFeeToken1Scaled` to the wrong recipient. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L327-335)
```text
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L417-425)
```text
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L438-447)
```text
  function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L382-432)
```text
    uint256 notionalFee0AmountScaled = notionalFeeToken0Scaled;
    uint256 notionalFee1AmountScaled = notionalFeeToken1Scaled;

    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;

    unchecked {
      uint256 spreadFee0ToAdminScaled = spreadSumE6 == 0 ? 0 : (surplus0Scaled * adminSpreadFeeE6_) / spreadSumE6;
      uint256 spreadFee1ToAdminScaled = spreadSumE6 == 0 ? 0 : (surplus1Scaled * adminSpreadFeeE6_) / spreadSumE6;

      uint256 spreadFee0ToProtocolScaled = spreadSumE6 == 0 ? 0 : (surplus0Scaled * protocolSpreadFeeE6_) / spreadSumE6;
      uint256 spreadFee1ToProtocolScaled = spreadSumE6 == 0 ? 0 : (surplus1Scaled * protocolSpreadFeeE6_) / spreadSumE6;

      uint256 notionalFee0ToAdminScaled =
        notionalSumE8 == 0 ? 0 : (notionalFee0AmountScaled * adminNotionalFeeE8_) / notionalSumE8;
      uint256 notionalFee1ToAdminScaled =
        notionalSumE8 == 0 ? 0 : (notionalFee1AmountScaled * adminNotionalFeeE8_) / notionalSumE8;

      uint256 notionalFee0ToProtocolScaled = notionalFee0AmountScaled - notionalFee0ToAdminScaled;
      uint256 notionalFee1ToProtocolScaled = notionalFee1AmountScaled - notionalFee1ToAdminScaled;

      uint256 totalFee0ToAdminScaled = spreadFee0ToAdminScaled + notionalFee0ToAdminScaled;
      uint256 totalFee1ToAdminScaled = spreadFee1ToAdminScaled + notionalFee1ToAdminScaled;

      uint256 totalFee0ToProtocolScaled = spreadFee0ToProtocolScaled + notionalFee0ToProtocolScaled;
      uint256 totalFee1ToProtocolScaled = spreadFee1ToProtocolScaled + notionalFee1ToProtocolScaled;

      (uint256 totalFee0ToAdmin, uint256 totalFee1ToAdmin) =
        deltasScaledToExternal(totalFee0ToAdminScaled, totalFee1ToAdminScaled, Math.Rounding.Floor);
      (uint256 totalFee0ToProtocol, uint256 totalFee1ToProtocol) =
        deltasScaledToExternal(totalFee0ToProtocolScaled, totalFee1ToProtocolScaled, Math.Rounding.Floor);

      if (totalFee0ToAdmin > 0) {
        transferToken0(adminFeeDestination_, totalFee0ToAdmin);
      }
      if (totalFee1ToAdmin > 0) {
        transferToken1(adminFeeDestination_, totalFee1ToAdmin);
      }
      if (totalFee0ToProtocol > 0) {
        transferToken0(FACTORY, totalFee0ToProtocol);
      }
      if (totalFee1ToProtocol > 0) {
        transferToken1(FACTORY, totalFee1ToProtocol);
      }

      notionalFeeToken0Scaled = 0;
      notionalFeeToken1Scaled = 0;

      emit ProtocolFeesCollected(totalFee0ToProtocol, totalFee1ToProtocol, totalFee0ToAdmin, totalFee1ToAdmin);
```
