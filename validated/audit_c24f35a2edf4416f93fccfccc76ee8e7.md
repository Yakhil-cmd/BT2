### Title
Accrued Admin Fees Are Misdirected When `setPoolAdminFeeDestination` Is Called Without Prior Fee Collection — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first flushing accrued fees at the old destination. Every other fee-mutating path in the factory (`setPoolAdminFees`, `setPoolProtocolFee`) calls `collectFees` before making its change. The missing settlement step means all fees that accrued under the previous destination are silently redirected to the new one on the next collection.

---

### Finding Description

The factory maintains two independent fee-state variables per pool:

- `poolAdminFeeDestination[pool]` — the address that receives the admin share on every `collectFees` call.
- `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` on the pool — running accumulators for notional fees earned since the last collection.
- Spread fees — the token surplus sitting in the pool balance above `binTotals` (also cleared only on `collectFees`).

Both `setPoolAdminFees` and `setPoolProtocolFee` guard against stale-destination misdirection by calling `collectFees` with the **current** `poolAdminFeeDestination` before writing any new configuration: [1](#0-0) [2](#0-1) 

`setPoolAdminFeeDestination` performs no such settlement: [3](#0-2) 

After the write, `poolAdminFeeDestination[pool]` points to the new address. The next call to `collectPoolFees` (or any fee-changing function that internally calls `collectFees`) passes the **new** destination to the pool: [4](#0-3) 

Inside `collectFees`, all accrued admin fees — both the spread surplus and the notional accumulator — are transferred to whatever `adminFeeDestination_` is supplied at that moment: [5](#0-4) [6](#0-5) 

Fees that accrued while the old destination was active are therefore sent to the new destination, with no on-chain mechanism to recover them for the original recipient.

---

### Impact Explanation

The previous `adminFeeDestination` (e.g., a DAO treasury or LP-fee multisig) permanently loses all admin fees that had accrued since the last collection. Those tokens are transferred to the new destination instead. The loss is bounded only by the volume of swaps since the last `collectPoolFees` call and the configured admin fee rates, but can be material in high-volume pools with infrequent collection.

---

### Likelihood Explanation

The pool admin is a semi-trusted role that legitimately calls `setPoolAdminFeeDestination` during treasury rotations, multisig migrations, or operational changes. No special timing or adversarial setup is required — the misdirection occurs automatically on the next collection after any destination change while fees are outstanding. Because `collectPoolFees` is permissionless and can be called by anyone (including bots or keepers), the window between the destination change and the next collection may be very short, but the misdirection is guaranteed whenever fees have accrued.

---

### Recommendation

Add a `collectFees` call inside `setPoolAdminFeeDestination` before updating the storage variable, mirroring the pattern used in `setPoolAdminFees` and `setPoolProtocolFee`:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Settle accrued fees to the current destination before rotating.
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

1. Pool is live; swaps have accrued `notionalFeeToken0Scaled = X` and a spread surplus of `Y` tokens in the pool balance. `poolAdminFeeDestination[pool] = Alice`.
2. Pool admin calls `setPoolAdminFeeDestination(pool, Bob)`. No fees are collected; `poolAdminFeeDestination[pool]` is now `Bob`.
3. Anyone calls `collectPoolFees(pool)`. The factory reads `poolAdminFeeDestination[pool] == Bob` and passes it to `collectFees`.
4. Inside `collectFees`, the admin share of `X` (notional) and `Y` (spread surplus) is transferred to `Bob`.
5. Alice receives nothing despite the fees having accrued entirely during her tenure as fee destination.

The corrupted value is `totalFee{0,1}ToAdmin` — computed correctly from the accrued pool state but dispatched to the wrong address because `adminFeeDestination_` reflects the post-change value rather than the address that was active when the fees were earned. [7](#0-6) [3](#0-2)

### Citations

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

**File:** metric-core/contracts/MetricOmmPool.sol (L382-388)
```text
    uint256 notionalFee0AmountScaled = notionalFeeToken0Scaled;
    uint256 notionalFee1AmountScaled = notionalFeeToken1Scaled;

    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;
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

**File:** metric-core/contracts/MetricOmmPool.sol (L429-430)
```text
      notionalFeeToken0Scaled = 0;
      notionalFeeToken1Scaled = 0;
```
