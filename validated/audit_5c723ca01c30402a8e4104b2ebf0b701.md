### Title
`setPoolAdminFeeDestination` Does Not Flush Accrued Fees to the Old Destination Before Updating — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` immediately without first collecting accrued fees to the old destination. Any admin fees that accrued under the old destination will subsequently be transferred to the new destination on the next `collectPoolFees` call, sending funds to the wrong recipient.

---

### Finding Description

`setPoolAdminFees` and `setPoolProtocolFee` both call `pool.collectFees(…, poolAdminFeeDestination[pool])` **before** updating any fee-related state, ensuring that all fees accrued under the old configuration are flushed to the correct (old) destination first.

`setPoolAdminFeeDestination` does not follow this pattern:

```solidity
// metric-core/contracts/MetricOmmPoolFactory.sol
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;   // ← no prior collect
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

After this call, `poolAdminFeeDestination[pool]` points to the new address. The next invocation of `collectPoolFees` (permissionless) or any fee-triggering admin action reads the **new** destination and transfers all previously accrued fees — both spread surplus and `notionalFeeToken0/1Scaled` — to the new address instead of the old one.

The pool's `collectFees` function transfers admin fees directly to the `adminFeeDestination_` argument supplied by the factory:

```solidity
// metric-core/contracts/MetricOmmPool.sol
if (totalFee0ToAdmin > 0) {
    transferToken0(adminFeeDestination_, totalFee0ToAdmin);
}
if (totalFee1ToAdmin > 0) {
    transferToken1(adminFeeDestination_, totalFee1ToAdmin);
}
```

There is no on-pool record of which destination earned which portion of the surplus; the entire accrued amount is sent to whichever address the factory supplies at collection time.

---

### Impact Explanation

The old `adminFeeDestination` (e.g., a DAO treasury or revenue-sharing contract with independent beneficiaries) permanently loses all fees that accrued before the destination change. Those fees are instead transferred to the new destination. The magnitude equals the full admin-fee share of the spread surplus plus any outstanding `notionalFeeToken0/1Scaled` at the time of the change. For an active pool with non-trivial volume, this can be a material token loss for the old destination's beneficiaries.

---

### Likelihood Explanation

The trigger is the pool admin calling `setPoolAdminFeeDestination`, which is a routine operational action (treasury migration, multisig rotation). No external precondition or underlying bug is required. The pool admin is semi-trusted and acts within documented caps; this is a normal lifecycle event. Any time the admin changes the fee destination without manually calling `collectPoolFees` first, the loss occurs. The permissionless nature of `collectPoolFees` means a third party can also race to collect immediately after the destination change, locking in the misdirection.

---

### Recommendation

Add a `collectFees` call at the start of `setPoolAdminFeeDestination`, mirroring the pattern used in `setPoolAdminFees` and `setPoolProtocolFee`:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Flush accrued fees to the OLD destination before updating
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

1. Pool is deployed with `adminFeeDestination = treasuryA` and non-zero admin spread/notional fees.
2. Swaps occur; spread surplus and `notionalFeeToken0Scaled` accumulate on the pool.
3. Pool admin calls `setPoolAdminFeeDestination(pool, treasuryB)`. No fees are collected; `poolAdminFeeDestination[pool]` is now `treasuryB`.
4. Anyone calls `collectPoolFees(pool)`. The factory reads `poolAdminFeeDestination[pool] == treasuryB` and passes it to `pool.collectFees(…, treasuryB)`.
5. All admin fees — including those accrued while `treasuryA` was the destination — are transferred to `treasuryB`. `treasuryA` receives nothing. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-425)
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

**File:** metric-core/contracts/MetricOmmPool.sol (L416-421)
```text
      if (totalFee0ToAdmin > 0) {
        transferToken0(adminFeeDestination_, totalFee0ToAdmin);
      }
      if (totalFee1ToAdmin > 0) {
        transferToken1(adminFeeDestination_, totalFee1ToAdmin);
      }
```
