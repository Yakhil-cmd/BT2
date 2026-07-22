### Title
Missing `collectFees` Before Fee Destination Change Allows Pool Admin to Redirect Accrued Admin Fees - (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`setPoolAdminFeeDestination` changes the admin fee recipient without first flushing accrued spread fees to the old destination. Every other fee-configuration mutator (`setPoolAdminFees`, `setPoolProtocolFee`) calls `collectFees` before updating state. The missing flush lets the pool admin silently redirect all previously accrued admin spread fees to a new address they control.

### Finding Description

The pool's spread-fee accounting works as follows: every swap leaves a `surplus` in the pool's token balance above `binTotals + notionalFeeScaled`. This surplus is the combined protocol + admin spread fee. It is only distributed when `collectFees` is called, using the `adminFeeDestination` stored in the factory at that moment. [1](#0-0) 

Both `setPoolAdminFees` and `setPoolProtocolFee` flush accrued fees to the **old** destination before updating any configuration: [2](#0-1) [3](#0-2) 

`setPoolAdminFeeDestination` does **not** follow this pattern — it updates `poolAdminFeeDestination[pool]` immediately with no prior collection: [4](#0-3) 

`collectPoolFees` (permissionless) then uses the **current** stored destination, so all surplus that accumulated under the old destination is paid to the new one: [5](#0-4) 

### Impact Explanation

The `adminFeeDestination` may be a separate entity from the pool admin (e.g., a DAO treasury, a revenue-sharing contract, or a previous operator). When the pool admin calls `setPoolAdminFeeDestination` before `collectPoolFees`, all accrued admin spread fees — which were earned while the old destination was in effect — are transferred to the new address instead. The old destination receives nothing for the period it was entitled to. The loss equals the full admin share of the surplus at the time of the destination change, which can be material after a high-volume trading period.

### Likelihood Explanation

The pool admin is a semi-trusted role with no timelock on `setPoolAdminFeeDestination`. Any pool admin who controls a destination address separate from their admin key can exploit this at will. The trigger requires only two sequential transactions (destination change, then `collectPoolFees`), and `collectPoolFees` is permissionless so the admin does not even need to call it themselves.

### Recommendation

Add a `collectFees` call at the old destination before updating `poolAdminFeeDestination`, mirroring the pattern used in `setPoolAdminFees` and `setPoolProtocolFee`:

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

### Proof of Concept

1. Pool is deployed; `adminFeeDestination` = DAO treasury (`T`). Pool admin key = `A`.
2. Many swaps occur; a large spread-fee surplus accumulates in the pool.
3. `A` calls `setPoolAdminFeeDestination(pool, A_wallet)` — no fees collected, destination silently updated.
4. Anyone calls `collectPoolFees(pool)` — the entire accrued surplus (admin share) is sent to `A_wallet`.
5. `T` receives zero despite being the entitled destination for the entire accrual period.

The invariant broken: every fee-configuration change must flush accrued fees at the old rates/destination before the new configuration takes effect. `setPoolAdminFees` and `setPoolProtocolFee` enforce this; `setPoolAdminFeeDestination` does not. [6](#0-5) [4](#0-3)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L385-388)
```text
    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;
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
