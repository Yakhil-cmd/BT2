### Title
`setPoolAdminFeeDestination` Silently Redirects All Accrued Admin Fees to New Destination Without Prior Collection — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first calling `collectFees` at the old destination. Every other fee-config mutator (`setPoolAdminFees`, `setPoolProtocolFee`) collects accrued fees at the old rates/destination before making any change. The missing collect step means all admin fees that accrued under the old destination are silently redirected to the new one on the next `collectPoolFees` call.

### Finding Description

`setPoolAdminFees` and `setPoolProtocolFee` both follow the same pattern: call `collectFees(…, poolAdminFeeDestination[pool])` with the current (old) config, then update state. [1](#0-0) 

`setPoolAdminFeeDestination` skips this step entirely: [2](#0-1) 

After the destination is updated, the next call to `collectPoolFees` (permissionless) passes the **new** destination to `collectFees`: [3](#0-2) 

Inside `collectFees`, the admin share of both the spread surplus and the notional fee accumulators is transferred to `adminFeeDestination_`: [4](#0-3) 

The two fee pools that are redirected are:

1. **Spread surplus** — `balance0() * TOKEN_0_SCALE_MULTIPLIER - binTotals.scaledToken0 - notionalFeeToken0Scaled` (all swap spread profit since the last collection).
2. **Notional fee accumulators** — `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` (withheld from swappers and sitting on the pool).

Both are cleared and sent to whoever `poolAdminFeeDestination[pool]` points to at collection time.

### Impact Explanation

The old admin fee destination loses all admin fees that accrued since the last `collectPoolFees` call. The new destination receives fees it did not earn. Because `collectPoolFees` is permissionless, the pool admin can atomically:

1. Call `setPoolAdminFeeDestination(pool, attackerAddress)`.
2. Call `collectPoolFees(pool)`.

This drains the entire accrued admin fee balance (spread surplus + notional accumulators) to an address of the pool admin's choosing, bypassing the old destination entirely. The loss is bounded only by the volume of swaps since the last collection and the configured admin fee rates — in an active pool this can be material.

### Likelihood Explanation

The pool admin is a semi-trusted role that legitimately calls `setPoolAdminFeeDestination` during treasury migrations or multisig rotations. The missing collect step is a latent defect that fires on every destination change. A malicious or negligent pool admin can trigger it with a single transaction; no special market conditions are required.

### Recommendation

Add a `collectFees` call at the old destination before updating `poolAdminFeeDestination`, mirroring the pattern used in `setPoolAdminFees` and `setPoolProtocolFee`:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Settle accrued fees to the OLD destination before switching.
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

```
State before attack:
  poolAdminFeeDestination[pool] = treasury          // legitimate old destination
  notionalFeeToken0Scaled       = 1_000_000         // accrued from swaps
  surplus0Scaled (spread)       = 500_000           // spread profit since last collect
  adminSpreadFeeE6              = 100_000 (10%)
  adminNotionalFeeE8            = 500_000 (0.5%)

Step 1 — pool admin calls:
  factory.setPoolAdminFeeDestination(pool, attackerAddress)
  → poolAdminFeeDestination[pool] = attackerAddress
  → NO collectFees called; accrued balances untouched

Step 2 — anyone calls (permissionless):
  factory.collectPoolFees(pool)
  → collectFees(..., attackerAddress)
  → adminSpread0 = 500_000 * 100_000 / (protocolSpread + 100_000) → sent to attackerAddress
  → adminNotional0 = 1_000_000 * 500_000 / notionalSumE8           → sent to attackerAddress
  → notionalFeeToken0Scaled = 0

Result: treasury receives nothing; attackerAddress receives all accrued admin fees.
``` [2](#0-1) [3](#0-2) [5](#0-4)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L382-433)
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
    }
```
