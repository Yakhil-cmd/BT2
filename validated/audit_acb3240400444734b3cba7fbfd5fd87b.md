### Title
Admin Fee Destination Change Without Prior Collection Redirects Accrued Fees to New Recipient — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first flushing accrued fees to the old destination. All spread-fee surplus and notional-fee accumulator balances that were earned under the old destination are silently redirected to the new one on the next `collectPoolFees` call.

---

### Finding Description

Every other fee-configuration mutator in `MetricOmmPoolFactory` calls `collectFees` on the pool before modifying state, so that fees accrued at the old configuration are settled before the new one takes effect:

- `setPoolAdminFees` (lines 418–425): calls `collectFees(…, poolAdminFeeDestination[pool])` first.
- `setPoolProtocolFee` (lines 328–335): calls `collectFees(…, poolAdminFeeDestination[pool])` first.

`setPoolAdminFeeDestination` (lines 438–447) is the sole exception:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;   // ← no collectFees first
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

After this call, the next invocation of `collectPoolFees` (or any fee-rate change) passes `newAdminFeeDestination` to `collectFees`. Inside `collectFees`, the admin's share of both fee streams is computed and transferred to that address:

1. **Spread-fee surplus** — `surplus{0,1}Scaled = balance * SCALE - binTotals - notionalAccumulator` — all of it is split between admin and protocol at the stored rates and sent to `adminFeeDestination_`.
2. **Notional-fee accumulator** — `notionalFeeToken{0,1}Scaled` — split and sent to `adminFeeDestination_`, then zeroed.

Because the destination was already overwritten, the old destination receives nothing; the new destination receives fees it did not earn. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

The old admin fee destination — which may be a treasury contract entirely separate from the pool admin — permanently loses all fees that accrued between the last collection and the destination change. Those tokens are transferred to the new destination instead. The loss is bounded only by the volume of swaps since the last `collectPoolFees` call and the configured admin fee rates, and can be arbitrarily large on a high-volume pool.

---

### Likelihood Explanation

The pool admin is a semi-trusted role that legitimately calls `setPoolAdminFeeDestination` during normal treasury rotation. No attacker capability is required beyond being the pool admin. The bug fires on every such call when uncollected fees exist, which is the common case (fees accumulate continuously between periodic keeper runs of `collectPoolFees`).

---

### Recommendation

Mirror the pattern used by `setPoolAdminFees` and `setPoolProtocolFee`: flush accrued fees to the **current** destination before overwriting it.

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Settle fees owed to the current destination before changing it.
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

1. Pool is deployed with `adminFeeDestination = TREASURY_A` and `adminSpreadFeeE6 = 5_000` (0.5 %).
2. Swaps occur; spread-fee surplus accumulates in the pool balance and notional fees accumulate in `notionalFeeToken{0,1}Scaled`.
3. Pool admin calls `setPoolAdminFeeDestination(pool, TREASURY_B)` — no `collectFees` is triggered.
4. Anyone calls `collectPoolFees(pool)`.
5. Inside `collectFees`, `adminFeeDestination_` is `TREASURY_B`; the admin share of all accrued spread and notional fees is transferred to `TREASURY_B`.
6. `TREASURY_A` receives zero despite having earned those fees. `notionalFeeToken{0,1}Scaled` is zeroed and the surplus is consumed — the loss is permanent. [1](#0-0) [4](#0-3) [5](#0-4)

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L418-425)
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
