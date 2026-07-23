### Title
Admin Fee Destination Change Without Prior Fee Collection Redirects Accumulated Spread Fees to New Destination — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first flushing accumulated spread fees via `collectFees`. All spread fees earned while the old destination was set are silently redirected to the new destination on the next `collectFees` call, causing the old destination to lose funds it rightfully earned.

---

### Finding Description

In `MetricOmmPoolFactory`, spread fees accumulate as an implicit surplus in the pool contract — the difference between the pool's actual token balances and what is owed to LPs plus notional fees: [1](#0-0) 

This surplus is not tracked in a per-destination ledger. When `collectFees` is called, it reads the **current** `poolAdminFeeDestination` and sends the entire accumulated surplus to that address: [2](#0-1) 

The factory's `setPoolAdminFeeDestination` changes this destination without first settling the accumulated surplus: [3](#0-2) 

The design intent is clearly to flush fees before any fee-related parameter change. Both `setPoolAdminFees` and `setPoolProtocolFee` call `collectFees` before modifying their respective parameters: [4](#0-3) [5](#0-4) 

`setPoolAdminFeeDestination` is the only fee-related mutator that omits this flush, creating an inconsistency that causes the old destination to lose all fees accrued before the change.

---

### Impact Explanation

The old admin fee destination — which may be a separate entity from the pool admin (e.g., a DAO treasury, a revenue-sharing contract, or a partner address) — loses all accumulated spread fees earned during its tenure. These fees are instead paid to the new destination, which did not earn them. In a high-volume pool, the accumulated surplus can be substantial. This is a direct, quantifiable loss of protocol/admin fee revenue.

---

### Likelihood Explanation

The pool admin is semi-trusted and has legitimate reasons to call `setPoolAdminFeeDestination` (e.g., rotating a treasury address, migrating to a new contract). The loss occurs automatically on the next `collectFees` call — no further attacker action is needed. The trigger is a normal, expected admin operation, making accidental loss highly likely and intentional exploitation trivially achievable by a malicious admin targeting a third-party fee recipient.

---

### Recommendation

Call `collectFees` inside `setPoolAdminFeeDestination` before updating `poolAdminFeeDestination[pool]`, following the same pattern used in `setPoolAdminFees` and `setPoolProtocolFee`:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    // Flush accumulated fees to the current destination before changing it
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

1. Pool is deployed with `adminFeeDestination = Alice`. Swaps accumulate a spread-fee surplus of `S` tokens in the pool.
2. Pool admin calls `setPoolAdminFeeDestination(pool, Bob)`. No `collectFees` is triggered; `poolAdminFeeDestination[pool]` is updated to `Bob`.
3. Anyone calls `collectPoolFees(pool)`. Inside `collectFees`, the surplus `S` is computed and sent to `poolAdminFeeDestination[pool]` — now `Bob`.
4. Alice receives `0` despite having been the rightful fee destination when `S` was earned.
5. Bob receives `S` without having earned it.

The corrupted value is the entire accumulated spread-fee surplus `S = balance * scaleMultiplier - binTotals - notionalFees` at the time of the destination change, which flows to the wrong address on the next `collectFees` invocation.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L385-388)
```text
    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L328-335)
```text
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
