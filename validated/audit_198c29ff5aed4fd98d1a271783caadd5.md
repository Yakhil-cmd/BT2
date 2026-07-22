### Title
`setPoolAdminFeeDestination` Does Not Collect Pending Fees Before Updating Destination, Causing Loss of Accrued Admin Fees for the Prior Recipient — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first flushing accrued fees at the old destination. Every other fee-config mutator (`setPoolAdminFees`, `setPoolProtocolFee`) calls `collectFees` before writing new state. The missing flush means all spread-surplus and notional fees that accrued under the old destination are silently redirected to the new destination on the next `collectPoolFees` call, permanently depriving the prior recipient of funds they are owed.

---

### Finding Description

`MetricOmmPool.collectFees` distributes two categories of admin fees:

1. **Spread fees** — the token surplus above LP positions, split pro-rata by `adminSpreadFeeE6 / spreadSumE6`.
2. **Notional fees** — explicitly tracked in `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`, split pro-rata by `adminNotionalFeeE8 / notionalSumE8`.

Both are sent to whichever `adminFeeDestination_` is passed in at collection time. [1](#0-0) 

`collectPoolFees` (permissionless) reads `poolAdminFeeDestination[pool]` at call time and forwards it to `collectFees`: [2](#0-1) 

`setPoolAdminFees` and `setPoolProtocolFee` both call `collectFees` with the **current** destination before writing any new state, preserving the invariant that fees earned under a given configuration go to the correct recipient: [3](#0-2) [4](#0-3) 

`setPoolAdminFeeDestination` does **not** follow this pattern — it overwrites the destination with no prior flush:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;   // ← no collectFees first
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
``` [5](#0-4) 

After this call, the next `collectPoolFees` invocation passes `newAdminFeeDestination` to `collectFees`, which transfers **all** previously accrued spread surplus and notional fees — including those earned before the destination change — to the new address. The old destination receives nothing.

---

### Impact Explanation

**Direct loss of admin fees for the prior fee destination.** `admin` and `adminFeeDestination` are independent parameters at pool creation: [6](#0-5) 

When the fee destination is a separate treasury, DAO, or LP-revenue contract, the pool admin can redirect all uncollected fees — both spread surplus and explicitly tracked notional fees — to any new address by calling `setPoolAdminFeeDestination` before `collectPoolFees` is triggered. The old destination permanently loses those funds with no recourse.

---

### Likelihood Explanation

The pool admin is semi-trusted and has a direct, single-transaction path to trigger this: call `setPoolAdminFeeDestination` at any time when fees have accrued but not yet been collected. No timelock, no cap, and no guard prevents it. Because `collectPoolFees` is permissionless and can be called by anyone (keepers, bots), the window between fee accrual and collection is always open, making the precondition easy to satisfy.

---

### Recommendation

Mirror the pattern used by `setPoolAdminFees` and `setPoolProtocolFee`: collect accrued fees at the **current** destination before updating `poolAdminFeeDestination`:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Flush fees to the current destination before rotating
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

1. Pool is created with `admin = Alice`, `adminFeeDestination = TreasuryA`.
2. Swaps occur; spread surplus and notional fees accumulate in the pool.
3. Alice calls `setPoolAdminFeeDestination(pool, TreasuryB)`. No fees are collected.
4. Anyone calls `collectPoolFees(pool)`. The factory reads `poolAdminFeeDestination[pool] == TreasuryB` and passes it to `collectFees`.
5. All fees — including those earned while `TreasuryA` was the destination — are transferred to `TreasuryB`.
6. `TreasuryA` receives zero; its accrued share is permanently lost.

### Citations

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
