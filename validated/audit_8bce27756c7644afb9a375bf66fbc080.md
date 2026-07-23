### Title
USDC-Blacklisted `adminFeeDestination` Permanently Locks Protocol Fees and Blocks Factory Owner Fee-Change Authority — (`MetricOmmPool.sol` / `MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPool.collectFees()` atomically pushes admin fees and protocol fees in a single call. If the `adminFeeDestination` address is USDC-blacklisted, the `safeTransfer` to that address reverts, causing the entire `collectFees` call to revert. Because `setPoolProtocolFee` (factory owner) and `setPoolAdminFees` (pool admin) both call `collectFees` as a mandatory prerequisite, a blacklisted `adminFeeDestination` permanently locks all accrued protocol fees inside the pool and strips the factory owner of the ability to update protocol fees for that pool — without any independent recovery path available to the factory owner.

---

### Finding Description

`MetricOmmPool.collectFees()` performs four sequential `safeTransfer` calls:

```
transferToken0(adminFeeDestination_, totalFee0ToAdmin);   // line 417
transferToken1(adminFeeDestination_, totalFee1ToAdmin);   // line 420
transferToken0(FACTORY, totalFee0ToProtocol);             // line 423
transferToken1(FACTORY, totalFee1ToProtocol);             // line 426
``` [1](#0-0) 

All four transfers are inside a single atomic call. If `adminFeeDestination_` is USDC-blacklisted, the first `safeTransfer` reverts and the entire function reverts — including the protocol-fee transfers to `FACTORY` and the zeroing of `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`.

Three callers in the factory all route through `collectFees`:

1. **`collectPoolFees(pool)`** — permissionless, callable by anyone: [2](#0-1) 

2. **`setPoolAdminFees(pool, ...)`** — pool admin path, calls `collectFees` before updating fee config: [3](#0-2) 

3. **`setPoolProtocolFee(pool, ...)`** — factory owner path, calls `collectFees` before updating protocol fee config: [4](#0-3) 

The factory owner has **no independent path** to change `poolAdminFeeDestination` — only the pool admin can call `setPoolAdminFeeDestination`. If the pool admin is uncooperative or unaware, the factory owner is permanently blocked from exercising their authority over protocol fees for that pool.

---

### Impact Explanation

- **Protocol fee loss**: All accrued spread surplus and notional fees (`notionalFeeToken0Scaled`, `notionalFeeToken1Scaled`) remain locked inside the pool. They cannot be collected until the `adminFeeDestination` is changed by the pool admin.
- **Admin-boundary break**: The factory owner (`onlyOwner`) cannot call `setPoolProtocolFee` for the affected pool. A semi-trusted pool admin effectively vetoes the factory owner's fee-governance authority over that pool.
- **Broken admin flow**: The pool admin also cannot call `setPoolAdminFees` to adjust their own fees, since that path also calls `collectFees` first.

---

### Likelihood Explanation

USDC (and USDT) maintain active blacklists. Any address set as `adminFeeDestination` — including multisigs, DAOs, or treasury contracts — can be blacklisted post-deployment for compliance reasons. The pool admin sets this address at creation or via `setPoolAdminFeeDestination`; neither the factory nor the factory owner can override it. The condition is reachable without any malicious intent: a routine USDC compliance action against the fee destination address is sufficient.

---

### Recommendation

Decouple admin and protocol fee transfers so that a failed admin transfer does not block protocol fee collection. Two options:

1. **Pull pattern**: Instead of pushing to `adminFeeDestination_`, credit a claimable balance mapping inside the pool or factory. The admin destination claims separately.
2. **Try/catch isolation**: Wrap the admin-fee `safeTransfer` calls in a `try/catch`. On failure, record the owed amount in a claimable mapping and continue with the protocol-fee transfers and state zeroing.

The protocol-fee transfers to `FACTORY` and the `notionalFeeToken0Scaled = 0` / `notionalFeeToken1Scaled = 0` resets must always execute regardless of admin-fee transfer success.

---

### Proof of Concept

1. Pool is created with `token0 = USDC`, `adminFeeDestination = 0xAdminTreasury`.
2. Swaps accrue spread surplus and notional fees over time.
3. USDC blacklists `0xAdminTreasury` (e.g., for compliance).
4. Anyone calls `collectPoolFees(pool)`:
   - `collectFees` is called with `adminFeeDestination_ = 0xAdminTreasury`.
   - `transferToken0(0xAdminTreasury, totalFee0ToAdmin)` → `safeTransfer` reverts (USDC blacklist).
   - Entire `collectFees` reverts. Protocol fees remain locked.
5. Factory owner calls `setPoolProtocolFee(pool, newFee, newFee)`:
   - Same `collectFees` call → same revert.
   - Factory owner cannot update protocol fees for this pool.
6. Pool admin calls `setPoolAdminFees(pool, newFee, newFee)`:
   - Same `collectFees` call → same revert.
   - Pool admin cannot change their own fees either.
7. Recovery requires the pool admin to call `setPoolAdminFeeDestination(pool, nonBlacklistedAddress)` first — an action the factory owner cannot force.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L416-427)
```text
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
