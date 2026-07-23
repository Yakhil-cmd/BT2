### Title
`setPoolAdminFeeDestination` Does Not Collect Accrued Fees Before Updating Destination, Causing Already-Accrued Admin Fees to Be Redirected — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first flushing accrued fees to the old destination. Every other fee-configuration mutator (`setPoolAdminFees`, `setPoolProtocolFee`) calls `collectFees` before making its change. The missing flush means that all spread-surplus and notional fees that accrued while the old destination was active are silently redirected to the new destination on the next `collectPoolFees` call.

---

### Finding Description

`setPoolAdminFees` and `setPoolProtocolFee` both follow the same safe pattern: collect all accrued fees at the current rates and to the current destination **before** writing any new configuration. [1](#0-0) 

`setPoolAdminFeeDestination` does not follow this pattern. It writes the new destination directly with no prior flush: [2](#0-1) 

`collectPoolFees` is permissionless and always reads `poolAdminFeeDestination[pool]` at call time: [3](#0-2) 

Inside `collectFees` on the pool, the admin share of both the spread surplus and the tracked notional fee balance is transferred to whichever `adminFeeDestination_` is passed in at that moment: [4](#0-3) 

Because the destination is resolved at collection time, not at accrual time, any fees that built up while `oldDest` was the destination are paid to `newDest` the next time anyone calls `collectPoolFees`.

---

### Impact Explanation

**Direct loss of owed admin fees.** The old fee destination (`oldDest`) loses every token of spread surplus and notional fee that accrued since the last collection. Those tokens are transferred to `newDest` instead. The loss is bounded only by how long fees have been accumulating and the pool's trading volume — it can be material.

The most impactful trigger is the two-step admin transfer flow:

1. Old admin proposes transfer → new admin accepts (`acceptPoolAdmin`).
2. New admin immediately calls `setPoolAdminFeeDestination(pool, newTreasury)`.
3. Any caller (or the new admin) calls `collectPoolFees`.
4. All fees accrued under the old admin's treasury are paid to `newTreasury`.

The old treasury has no on-chain recourse; it cannot front-run `acceptPoolAdmin` because the new admin's acceptance and the destination change can be bundled in a single transaction.

Even without an admin transfer, a negligent or malicious admin can redirect their own treasury's accrued fees by changing the destination before collecting.

---

### Likelihood Explanation

The trigger is a normal, documented admin operation (`setPoolAdminFeeDestination`) that any pool admin can call at any time with no timelock. Admin transfers are expected lifecycle events. The missing `collectFees` call is a consistent omission relative to every other fee-config mutator, making it likely to be hit in practice whenever the destination is changed without an explicit prior `collectPoolFees`.

---

### Recommendation

Add a `collectFees` call at the top of `setPoolAdminFeeDestination`, mirroring the pattern in `setPoolAdminFees`:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Flush accrued fees to the current destination before switching.
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool).collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]   // old destination
    );

    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

---

### Proof of Concept

```
State: pool has been trading; spread surplus S > 0 and notional fees N > 0 have accrued.
       poolAdminFeeDestination[pool] = oldTreasury

Step 1 (admin): setPoolAdminFeeDestination(pool, newTreasury)
       → poolAdminFeeDestination[pool] = newTreasury
       → NO collectFees called; S and N still sit in the pool

Step 2 (anyone): collectPoolFees(pool)
       → collectFees(..., adminFeeDestination_ = newTreasury)
       → admin share of S and N transferred to newTreasury

Result: oldTreasury receives 0 tokens despite having earned the admin share of S and N.
        newTreasury receives fees it did not earn.

Compare: if collectPoolFees had been called BEFORE setPoolAdminFeeDestination,
         oldTreasury would have received its earned fees correctly.
         The outcome depends entirely on call order — identical to the vesting H-01 pattern.
```

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L379-389)
```text
  function collectPoolFees(address pool) external override nonReentrant {
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );
  }
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

**File:** metric-core/contracts/MetricOmmPool.sol (L385-421)
```text
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
```
