### Title
`setPoolAdminFeeDestination` Does Not Flush Accrued Fees Before Updating Destination, Causing Loss of Owed Admin Fees - (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first calling `collectFees` to flush already-accrued admin fees to the old destination. Every other fee-parameter setter (`setPoolAdminFees`, `setPoolProtocolFee`) performs this flush as a mandatory first step. The missing flush causes all previously accrued admin fees — both spread surplus and the notional accumulator (`notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`) — to be paid to the **new** destination the next time `collectFees` is called, permanently depriving the old destination of fees it was owed.

---

### Finding Description

`setPoolAdminFees` and `setPoolProtocolFee` both follow the same invariant: collect all accrued fees at the current rates and destination **before** mutating any fee-related state. [1](#0-0) 

`setPoolAdminFeeDestination` breaks this invariant. It updates `poolAdminFeeDestination[pool]` directly without any prior flush: [2](#0-1) 

After the update, the next call to `collectPoolFees` (permissionless) or any fee-collecting setter reads the **new** destination from storage and passes it to `collectFees` on the pool: [3](#0-2) 

Inside `collectFees`, the admin share of both spread surplus and the notional accumulator is transferred to whichever `adminFeeDestination_` was passed in — which is now the new address: [4](#0-3) 

---

### Impact Explanation

All admin fees accrued between the last collection and the `setPoolAdminFeeDestination` call are irrecoverably redirected to the new destination. The old destination receives nothing for the period it was the registered recipient. This is a direct, permanent loss of owed protocol-adjacent assets (admin fees) with no recovery path, because `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` are zeroed on collection and the spread surplus is consumed in the same pass. [5](#0-4) 

---

### Likelihood Explanation

The trigger is a routine, valid admin action: changing the fee destination (e.g., treasury rotation, multisig migration, or admin role handover). It requires no special conditions beyond uncollected fees existing at the time of the call, which is the normal state between collection cycles. The permissionless `collectPoolFees` can be front-run by anyone immediately after the destination change to crystallize the loss before the old destination can react.

---

### Recommendation

Add a `collectFees` call at the top of `setPoolAdminFeeDestination`, mirroring the pattern in `setPoolAdminFees`:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Flush accrued fees to the OLD destination before switching
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

1. Pool accumulates 1 000 USDC in admin spread surplus and 500 USDC in `notionalFeeToken0Scaled` over several swaps.
2. Pool admin calls `setPoolAdminFeeDestination(pool, newTreasury)`. No fees are flushed; `poolAdminFeeDestination[pool]` is now `newTreasury`.
3. Anyone calls `collectPoolFees(pool)`. The factory reads `poolAdminFeeDestination[pool]` → `newTreasury` and passes it to `collectFees`.
4. `collectFees` transfers the full admin share (≈ 1 500 USDC) to `newTreasury`.
5. `oldTreasury` receives 0 USDC despite being the registered destination for the entire accrual period. [6](#0-5) [2](#0-1)

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-435)
```text
  function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();

    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );

    c.adminSpreadFeeE6 = newAdminSpreadFeeE6;
    c.adminNotionalFeeE8 = newAdminNotionalFeeE8;
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolAdminSpreadFeeUpdated(pool, newAdminSpreadFeeE6);
    emit PoolAdminNotionalFeeUpdated(pool, newAdminNotionalFeeE8);
  }
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

**File:** metric-core/contracts/MetricOmmPool.sol (L416-421)
```text
      if (totalFee0ToAdmin > 0) {
        transferToken0(adminFeeDestination_, totalFee0ToAdmin);
      }
      if (totalFee1ToAdmin > 0) {
        transferToken1(adminFeeDestination_, totalFee1ToAdmin);
      }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L429-430)
```text
      notionalFeeToken0Scaled = 0;
      notionalFeeToken1Scaled = 0;
```
