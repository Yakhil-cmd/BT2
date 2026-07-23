### Title
`setPoolAdminFeeDestination` redirects accumulated fees without first settling them to the original destination — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` immediately without first collecting accumulated fees to the old destination. This is the direct analog of the MIMO `updateBoost` bug: a state variable that governs fee distribution is changed retroactively, causing already-accrued fees to flow to the wrong recipient.

---

### Finding Description

The protocol maintains two types of accumulated admin fees on each pool:

1. **Spread fees** — held as a surplus in the pool's token balance (`balance - binTotals - notionalFees`), split at collection time by the ratio `adminSpreadFeeE6 / spreadSumE6`.
2. **Notional fees** — tracked explicitly in `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`, split at collection time by the ratio `adminNotionalFeeE8 / notionalSumE8`.

Both are disbursed to `adminFeeDestination_` only when `collectFees` is called on the pool.

`setPoolAdminFees` correctly collects all accumulated fees at the old rates before updating the fee config: [1](#0-0) 

`setPoolAdminFeeDestination` performs no such settlement — it overwrites `poolAdminFeeDestination[pool]` in a single storage write: [2](#0-1) 

After the destination is changed, the next call to `collectPoolFees` (which is **permissionless** — callable by any address) will send all previously accumulated admin fees to the new destination: [3](#0-2) 

The pool's `collectFees` uses the `adminFeeDestination_` argument passed in at collection time, not any value stored on the pool itself: [4](#0-3) 

---

### Impact Explanation

The original `adminFeeDestination` (e.g., a DAO treasury, a separate multisig, or an LP revenue contract) loses all fees that accrued before the destination was changed. The pool admin can redirect those fees to any non-zero address they control. Both spread-fee surplus and notional-fee accumulators are affected.

This is a direct loss of protocol fees / owed admin assets. The magnitude scales with how long the pool has been active and how much trading volume has occurred since the last `collectPoolFees` call.

---

### Likelihood Explanation

The pool admin is semi-trusted. The task scope explicitly calls out "fee collection destinations" as an admin-boundary area to audit. The admin has no cap, timelock, or on-chain constraint preventing an immediate destination change. Because `collectPoolFees` is permissionless, the admin does not even need to call it themselves — they can change the destination and wait for a keeper or bot to trigger collection.

---

### Recommendation

Mirror the pattern used in `setPoolAdminFees`: collect all accumulated fees to the **current** destination before updating `poolAdminFeeDestination[pool]`.

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Settle fees to the old destination before rotating
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

1. Pool accumulates 1000 USDC in admin spread fees and 500 USDC in admin notional fees over several weeks of trading. `poolAdminFeeDestination[pool]` = `treasury`.
2. Pool admin calls `setPoolAdminFeeDestination(pool, attacker)`. No fees are collected; `poolAdminFeeDestination[pool]` is now `attacker`.
3. Anyone (or the admin) calls `collectPoolFees(pool)`. The factory reads `poolAdminFeeDestination[pool]` = `attacker` and passes it to `collectFees`.
4. `collectFees` transfers the full 1500 USDC admin share to `attacker`. `treasury` receives nothing.

The invariant broken: fees accrued under `treasury` as the designated destination are disbursed to `attacker` instead, with no on-chain mechanism to prevent or detect this before collection occurs. [5](#0-4) [2](#0-1) [6](#0-5)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L382-421)
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
```
