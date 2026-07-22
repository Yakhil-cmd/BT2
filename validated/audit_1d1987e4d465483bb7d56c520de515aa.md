### Title
`setPoolAdminFeeDestination` Fails to Collect Accrued Fees Before Redirecting Admin Fee Destination — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first flushing accrued fees to the old destination. All fees that accrued under the old destination are silently redirected to the new one on the next `collectFees` call.

### Finding Description

Every other fee-mutating function in `MetricOmmPoolFactory` — `setPoolAdminFees` and `setPoolProtocolFee` — calls `collectFees` on the pool **before** writing new configuration, so that fees earned under the old parameters are settled to the correct recipients first.

`setPoolAdminFeeDestination` breaks this invariant:

```solidity
// MetricOmmPoolFactory.sol L438-447
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;   // ← no collectFees first
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

Compare with `setPoolAdminFees` (lines 408-435), which always flushes first:

```solidity
IMetricOmmPoolCollectFees(pool).collectFees(
    c.protocolSpreadFeeE6, c.adminSpreadFeeE6,
    c.protocolNotionalFeeE8, c.adminNotionalFeeE8,
    poolAdminFeeDestination[pool]   // ← old destination, before the update
);
```

`collectFees` in `MetricOmmPool` distributes two categories of accrued value to whichever `adminFeeDestination_` is passed at call time:

1. **Notional fees** — stored in `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` (lines 382-383, 429-430).
2. **Spread fee surplus** — the live token balance minus LP bin totals minus notional fees (lines 385-388).

Because `setPoolAdminFeeDestination` writes the new address before any flush, the next `collectFees` call (whether via `collectPoolFees`, `setPoolAdminFees`, or `setPoolProtocolFee`) passes the **new** destination and transfers all previously accrued admin fees there instead of to the old one.

### Impact Explanation

The old `adminFeeDestination` — which may be a treasury contract, DAO, or any address distinct from the pool admin — permanently loses all admin fees (both spread and notional) that accrued before the destination was changed. Those tokens are transferred to the new destination, which did not earn them. This is a direct, irreversible loss of owed protocol/admin fee revenue.

### Likelihood Explanation

The pool admin is semi-trusted and has a legitimate reason to call `setPoolAdminFeeDestination` (e.g., rotating a treasury address). The bug fires every time this function is called while any fees have accrued — a routine operational scenario. No special attacker setup is required; the pool admin simply calls the function in the normal course of administration.

### Recommendation

Mirror the pattern used by `setPoolAdminFees` and `setPoolProtocolFee`: flush accrued fees to the **current** destination before overwriting it.

```diff
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
+   PoolFeeConfig memory c = poolFeeConfig[pool];
+   IMetricOmmPoolCollectFees(pool).collectFees(
+       c.protocolSpreadFeeE6,
+       c.adminSpreadFeeE6,
+       c.protocolNotionalFeeE8,
+       c.adminNotionalFeeE8,
+       poolAdminFeeDestination[pool]
+   );
    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

### Proof of Concept

1. Pool is deployed with `adminFeeDestination = OLD_TREASURY`.
2. Swaps occur; `notionalFeeToken0Scaled` and `notionalFeeToken1Scaled` accumulate on the pool, and spread surplus builds up in the pool balance.
3. Pool admin calls `setPoolAdminFeeDestination(pool, NEW_TREASURY)`. No `collectFees` is triggered; `poolAdminFeeDestination[pool]` is overwritten.
4. Anyone calls `collectPoolFees(pool)`. Inside `collectFees`, `adminFeeDestination_` is now `NEW_TREASURY`. All accrued notional fees and spread surplus are transferred to `NEW_TREASURY`.
5. `OLD_TREASURY` receives nothing despite having earned those fees. The loss equals the full admin share of all fees accrued between the last collection and the destination change.

---

**Relevant code locations:**

`setPoolAdminFeeDestination` (missing flush): [1](#0-0) 

`setPoolAdminFees` (correct pattern — flushes before update): [2](#0-1) 

`collectFees` — uses the passed `adminFeeDestination_` to route all accrued admin fees: [3](#0-2)

### Citations

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
