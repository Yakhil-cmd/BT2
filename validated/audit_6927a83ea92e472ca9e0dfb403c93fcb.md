### Title
`setPoolAdminFeeDestination` Redirects Accumulated Spread Fees Without Prior Collection — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory.setPoolAdminFeeDestination` updates the admin fee destination without first flushing accumulated spread fees to the old destination. Because spread fees sit as an untracked surplus in the pool's token balance, any fees earned before the destination change are silently redirected to the new address when `collectPoolFees` is next called. The pool admin can exploit this to steal fees that were owed to the previous destination.

### Finding Description

The protocol accumulates two kinds of fees inside `MetricOmmPool`:

1. **Notional fees** — tracked explicitly in `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`.
2. **Spread fees** — not tracked in a dedicated accumulator; they accumulate implicitly as the difference between the pool's real token balance and `binTotals`: [1](#0-0) 

When `collectFees` is called, the entire current surplus is split between admin and protocol using the fee rates and `adminFeeDestination_` passed in at call time: [2](#0-1) 

The factory's `setPoolAdminFees` correctly flushes accumulated fees **before** changing the fee split, so that fees earned at the old rates go to the old destination: [3](#0-2) 

However, `setPoolAdminFeeDestination` changes the destination **without** any prior collection: [4](#0-3) 

After this call, the next invocation of `collectPoolFees` (callable by anyone, no access control) passes the **new** destination to `collectFees`: [5](#0-4) 

All spread-fee surplus that accumulated before the destination change is therefore sent to the new address, not the old one.

### Impact Explanation

The old admin fee destination loses all spread fees that accrued before the destination change. These fees are owed to the old destination (e.g., a DAO treasury or a separate fee-recipient contract) but are silently redirected to the new destination. The pool admin can time this call to maximise the redirected amount — for example, waiting until a large volume of swaps has built up a significant surplus, then changing the destination to themselves before triggering collection. Protocol fees (sent to `FACTORY`) are unaffected; only the admin fee share is misdirected.

### Likelihood Explanation

The pool admin is semi-trusted and can call `setPoolAdminFeeDestination` at any time with no timelock and no cap. `collectPoolFees` is permissionless, so the admin does not even need to trigger collection themselves — they can simply wait for the next organic collection call. The inconsistency with `setPoolAdminFees` (which does flush first) makes this an easy-to-miss but straightforward exploit path.

### Recommendation

Mirror the pattern used in `setPoolAdminFees`: call `collectFees` with the **current** stored config and the **old** destination before updating `poolAdminFeeDestination[pool]`.

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Flush accumulated fees to the OLD destination before switching.
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

1. Pool runs for a period; swaps generate a spread-fee surplus of, say, 1 000 token0 sitting in the pool balance above `binTotals.scaledToken0`.
2. Pool admin calls `setPoolAdminFeeDestination(pool, attackerAddress)`. No fees are collected; `poolAdminFeeDestination[pool]` is now `attackerAddress`.
3. Anyone (or the admin) calls `collectPoolFees(pool)`. The factory reads `poolAdminFeeDestination[pool]` → `attackerAddress` and passes it to `collectFees`.
4. Inside `collectFees`, `surplus0Scaled` includes the 1 000 token0 earned before the destination change. The admin share is transferred to `attackerAddress`.
5. The original fee destination (e.g., a DAO treasury) receives nothing for the fees it was owed.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L385-388)
```text
    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;
```

**File:** metric-core/contracts/MetricOmmPool.sol (L391-421)
```text
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
