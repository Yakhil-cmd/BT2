### Title
Admin Fee Destination Change Without Prior Fee Collection Causes Loss of Owed Spread Fees — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first collecting accumulated spread fees, causing the old fee destination to permanently lose all earned but uncollected spread fees at the moment of the change.

---

### Finding Description

In `MetricOmmPoolFactory`, both `setPoolAdminFees` and `setPoolProtocolFee` follow a consistent pattern: they call `collectFees` on the pool **before** modifying any fee configuration, ensuring all accumulated fees are settled to the correct destination first.

`setPoolAdminFees` (lines 417–425): [1](#0-0) 

`setPoolProtocolFee` (lines 327–335): [2](#0-1) 

However, `setPoolAdminFeeDestination` (lines 438–447) updates the destination directly with **no prior fee collection**: [3](#0-2) 

The pool's spread fees accumulate as a **surplus** — the difference between the pool's actual token balance and LP-owed amounts plus notional fees — computed inside `collectFees`: [4](#0-3) 

When `collectFees` is eventually called after the destination change, the entire surplus (including fees earned while the old destination was active) is distributed to the **new** `adminFeeDestination_`. The old destination receives nothing.

This is the direct analog to the Alchemix bug: just as `merge` burns a token without claiming ALCX rewards first (while `withdraw` correctly claims before burning), `setPoolAdminFeeDestination` changes the recipient without settling owed fees first (while `setPoolAdminFees` and `setPoolProtocolFee` correctly settle first).

---

### Impact Explanation

The old admin fee destination permanently loses all accumulated but uncollected spread fees at the time of the destination change. These fees are real token balances already held in the pool and owed to the old destination. They are redirected to the new destination with no recourse. This is a direct loss of owed protocol/admin assets.

---

### Likelihood Explanation

The pool admin is a valid semi-trusted actor who can call `setPoolAdminFeeDestination` at any time. The pool admin and admin fee destination are separate addresses set independently at pool creation: [5](#0-4) 

In any deployment where the admin fee destination is a distinct entity (e.g., a DAO treasury, a revenue-sharing contract), a destination change without prior collection silently steals that entity's earned fees. No malicious intent is required — even an accidental destination update (e.g., migrating to a new treasury) triggers the loss.

---

### Recommendation

Mirror the pattern used by `setPoolAdminFees` and `setPoolProtocolFee`: call `collectFees` with the **current** destination before updating `poolAdminFeeDestination`:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    // Settle accumulated fees to the old destination first
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

1. Pool is created with `adminFeeDestination = oldDest`. Trading occurs and spread fees accumulate as surplus in the pool.
2. Pool admin calls `setPoolAdminFeeDestination(pool, newDest)` — no `collectFees` is triggered.
3. `poolAdminFeeDestination[pool]` is now `newDest`.
4. Anyone calls `collectPoolFees(pool)`. Inside `collectFees`, `adminFeeDestination_` is `newDest`.
5. The entire surplus — including all fees earned while `oldDest` was the destination — is transferred to `newDest`.
6. `oldDest` receives zero tokens despite having earned spread fees. The loss is permanent and unrecoverable.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L212-220)
```text
    poolAdmin[pool] = params.admin;
    priceProviderTimelock[pool] = params.priceProviderTimelock;
    poolFeeConfig[pool] = PoolFeeConfig({
      protocolSpreadFeeE6: spreadProtocolFeeE6,
      adminSpreadFeeE6: params.adminSpreadFeeE6,
      protocolNotionalFeeE8: protocolNotionalFeeE8,
      adminNotionalFeeE8: params.adminNotionalFeeE8
    });
    poolAdminFeeDestination[pool] = params.adminFeeDestination;
```

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

**File:** metric-core/contracts/MetricOmmPool.sol (L385-388)
```text
    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;
```
