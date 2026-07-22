### Title
USDC-Blacklisted `adminFeeDestination` Permanently Blocks Fee Collection and Protocol Fee Updates — (File: `metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

`MetricOmmPool.collectFees` pushes accrued fees directly to `adminFeeDestination_` via `safeTransfer`. Because `collectFees` is called atomically inside `collectPoolFees`, `setPoolAdminFees`, and `setPoolProtocolFee`, a USDC-blacklisted `adminFeeDestination` causes all three entry points to revert. The factory owner has no unilateral bypass; protocol fees accumulate in the pool and cannot be extracted until the pool admin cooperates.

---

### Finding Description

`MetricOmmPool.collectFees` (lines 416–427) pushes token amounts to `adminFeeDestination_` unconditionally before returning:

```solidity
if (totalFee0ToAdmin > 0) {
    transferToken0(adminFeeDestination_, totalFee0ToAdmin);   // safeTransfer
}
if (totalFee1ToAdmin > 0) {
    transferToken1(adminFeeDestination_, totalFee1ToAdmin);   // safeTransfer
}
``` [1](#0-0) 

`transferToken0`/`transferToken1` call OpenZeppelin `safeTransfer`, which reverts on any ERC-20 failure — including a USDC blacklist revert. [2](#0-1) 

Three factory-level entry points call `collectFees` atomically before doing anything else:

**1. `collectPoolFees` (permissionless):**
```solidity
function collectPoolFees(address pool) external override nonReentrant {
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool).collectFees(
        c.protocolSpreadFeeE6, c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8, c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]          // ← blacklisted → revert
    );
}
``` [3](#0-2) 

**2. `setPoolAdminFees` (pool admin):**
```solidity
IMetricOmmPoolCollectFees(pool).collectFees(
    c.protocolSpreadFeeE6, c.adminSpreadFeeE6,
    c.protocolNotionalFeeE8, c.adminNotionalFeeE8,
    poolAdminFeeDestination[pool]              // ← blacklisted → revert
);
// fee config update never reached
``` [4](#0-3) 

**3. `setPoolProtocolFee` (factory owner / `onlyOwner`):**
```solidity
IMetricOmmPoolCollectFees(pool).collectFees(
    c.protocolSpreadFeeE6, c.adminSpreadFeeE6,
    c.protocolNotionalFeeE8, c.adminNotionalFeeE8,
    poolAdminFeeDestination[pool]              // ← blacklisted → revert
);
// protocol fee update never reached
``` [5](#0-4) 

The only escape hatch is `setPoolAdminFeeDestination`, which does **not** call `collectFees` and can update the destination without triggering a transfer:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    ...
}
``` [6](#0-5) 

However, this function is `onlyPoolAdmin`. The factory owner has **no unilateral path** to unblock fee collection or update protocol fees — they are entirely dependent on the pool admin acting.

---

### Impact Explanation

- **Protocol fees are frozen in the pool.** `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` continue to accumulate but `collectFees` always reverts before zeroing them or transferring anything. Protocol revenue is inaccessible for the affected pool.
- **Factory owner cannot update protocol fee rates** for the pool (`setPoolProtocolFee` reverts). This breaks the factory owner's ability to manage fee policy across pools.
- **Pool admin cannot update their own fee rates** (`setPoolAdminFees` reverts).

This constitutes direct loss of protocol fee revenue and broken core admin functionality — both within the allowed impact gate.

---

### Likelihood Explanation

USDC (and USDT) maintain on-chain blacklists. The contest scope explicitly includes USDC/USDT non-standard behavior. An `adminFeeDestination` address being blacklisted is a realistic operational event (e.g., regulatory action, compromised key). Likelihood is **Low** but the trigger is unprivileged (USDC's blacklist authority, not the protocol).

---

### Recommendation

Decouple fee collection from fee configuration updates. Options:

1. **Pull pattern:** Credit admin fees to a claimable mapping (`pendingAdminFees[pool]`) instead of pushing during `collectFees`. Let the admin pull separately.
2. **Skip-on-failure:** Catch the transfer failure and emit an event, allowing configuration updates to proceed even if the push fails (fees remain in pool for later collection after destination is fixed).
3. **Separate `collectFees` from `setPoolAdminFees` / `setPoolProtocolFee`:** Remove the mandatory pre-collection from fee-update functions; let keepers call `collectPoolFees` independently.

---

### Proof of Concept

1. Pool is deployed with `adminFeeDestination = 0xABC` (a USDC-capable address).
2. Swaps occur; `notionalFeeToken0Scaled` and spread surplus accumulate.
3. USDC blacklists `0xABC`.
4. Any caller invokes `collectPoolFees(pool)` → `collectFees` calls `transferToken1(0xABC, amount)` → USDC reverts → entire tx reverts. Protocol fees remain stuck.
5. Factory owner calls `setPoolProtocolFee(pool, newFee, 0)` → same revert at the mandatory `collectFees` call → protocol fee rate cannot be updated.
6. Pool admin calls `setPoolAdminFees(pool, newFee, 0)` → same revert → admin fee rate cannot be updated.
7. Resolution requires pool admin to call `setPoolAdminFeeDestination(pool, newAddress)` — the factory owner cannot force this.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L565-570)
```text
  function transferToken0(address to, uint256 amount) internal {
    IERC20(TOKEN0).safeTransfer(to, amount);
  }

  function transferToken1(address to, uint256 amount) internal {
    IERC20(TOKEN1).safeTransfer(to, amount);
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
