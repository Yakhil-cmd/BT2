### Title
`setPoolAdminFeeDestination` Does Not Flush Accrued Fees Before Redirecting the Admin Fee Recipient — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first collecting accrued fees. Every other fee-config mutator (`setPoolAdminFees`, `setPoolProtocolFee`) calls `pool.collectFees(…)` before writing new state. The missing flush means all fees that accrued under the old destination are silently redirected to the new destination the next time anyone calls the permissionless `collectPoolFees`.

---

### Finding Description

The factory stores two independent, fee-routing state variables per pool:

| Variable | Updated by | Flushes first? |
|---|---|---|
| `poolFeeConfig[pool]` | `setPoolAdminFees`, `setPoolProtocolFee` | **Yes** |
| `poolAdminFeeDestination[pool]` | `setPoolAdminFeeDestination` | **No** |

`setPoolAdminFees` collects all accrued fees at the current rates and destination before writing the new split: [1](#0-0) 

`setPoolProtocolFee` does the same: [2](#0-1) 

`setPoolAdminFeeDestination` does **not**: [3](#0-2) 

`collectPoolFees` is permissionless and reads both variables together at call time: [4](#0-3) 

Inside `pool.collectFees`, the entire current surplus (spread fees) and the entire `notionalFeeToken0Scaled`/`notionalFeeToken1Scaled` accumulator are distributed to whichever `adminFeeDestination_` is passed in at that moment: [5](#0-4) 

Because the pool stores no per-destination accounting, there is no way to recover fees that accrued before the destination was changed.

---

### Impact Explanation

All admin-share fees that accrued under the old `poolAdminFeeDestination` are permanently redirected to the new address the next time `collectPoolFees` is called. The old destination receives nothing for the period it was the legitimate recipient. This is a direct, irreversible loss of owed protocol/admin fee assets. The magnitude equals the total admin-share of spread surplus plus notional fee accumulators outstanding at the moment of the destination change — potentially large for high-volume pools with infrequent collection.

---

### Likelihood Explanation

The trigger is a valid semi-trusted pool admin action (`onlyPoolAdmin`). The audit pivots explicitly list "fee collection destinations" as an admin-path area to examine. The pool admin is semi-trusted only within caps and timelocks; no cap or timelock governs `setPoolAdminFeeDestination`. `collectPoolFees` is permissionless, so the redirect can be executed atomically in the same block as the destination change by any caller, including the pool admin themselves.

---

### Recommendation

Mirror the pattern used by `setPoolAdminFees` and `setPoolProtocolFee`: collect accrued fees at the **current** destination before overwriting `poolAdminFeeDestination[pool]`.

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Flush fees to the OLD destination before redirecting
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

1. Pool is created; `poolAdminFeeDestination[pool] = treasury`.
2. Swaps occur; spread surplus and notional accumulators grow — all economically owed to `treasury`.
3. Pool admin calls `setPoolAdminFeeDestination(pool, attacker)`. No fees are flushed; `poolAdminFeeDestination[pool]` is now `attacker`.
4. Anyone (including the pool admin) calls `collectPoolFees(pool)`.
5. `pool.collectFees(…, attacker)` is invoked. The entire surplus and notional accumulators are transferred to `attacker`.
6. `treasury` receives zero despite having been the legitimate recipient for the entire accrual period.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L385-432)
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
