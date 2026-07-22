### Title
`poolAdminFeeDestination` Not Cleared on Pool Admin Transfer Causes New Admin to Lose Accrued Admin Fees — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

When pool admin ownership is transferred via `acceptPoolAdmin`, the factory's `poolAdminFeeDestination[pool]` mapping is not updated. Because `collectPoolFees` is explicitly permissionless, anyone — including the outgoing admin — can call it in the window between `acceptPoolAdmin` and the new admin's `setPoolAdminFeeDestination` call, draining all accrued admin fees to the old admin's address.

---

### Finding Description

`acceptPoolAdmin` performs a two-step admin handover: [1](#0-0) 

It updates `poolAdmin[pool]` and clears `pendingPoolAdmin[pool]`, but it does **not** touch `poolAdminFeeDestination[pool]`. That mapping was set at pool creation: [2](#0-1) 

and is the sole recipient of the admin share whenever fees are collected: [3](#0-2) 

The pool's `collectFees` implementation transfers tokens directly to `adminFeeDestination_`: [4](#0-3) 

Critically, `collectPoolFees` is documented and designed as **permissionless** — "any address may call (keepers, pool admin, or bots)": [5](#0-4) 

After `acceptPoolAdmin` completes:

| Storage slot | Value |
|---|---|
| `poolAdmin[pool]` | new admin ✓ |
| `poolAdminFeeDestination[pool]` | **old admin's address** ✗ |

Any `collectPoolFees` call before the new admin executes `setPoolAdminFeeDestination` sends the entire accrued admin share to the old admin's address. The new admin cannot atomically accept the role and update the destination in a single transaction through the factory's public API.

---

### Impact Explanation

Direct loss of admin fees owed to the new pool admin. The old admin retains economic benefit (admin fee revenue) from a role they no longer hold. The loss is proportional to all fees accrued since the last collection. For active pools with non-zero `adminSpreadFeeE6` or `adminNotionalFeeE8`, this can be material.

---

### Likelihood Explanation

Every pool admin transfer where fees have accrued is affected. The outgoing admin is economically incentivized to call `collectPoolFees` immediately after `acceptPoolAdmin` is mined (or to front-run the new admin's `setPoolAdminFeeDestination` call). No special privilege is required — `collectPoolFees` is permissionless.

---

### Recommendation

In `acceptPoolAdmin`, collect outstanding fees at the old destination before the role switches, then require the new admin to set a fresh destination:

```solidity
function acceptPoolAdmin(address pool) external override nonReentrant {
    address pending = pendingPoolAdmin[pool];
    if (pending == address(0)) revert NoPendingPoolAdminTransfer();
    if (msg.sender != pending) revert NotPendingPoolAdmin(pool, msg.sender, pending);

    // Flush accrued fees to the outgoing admin's destination before handover
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool).collectFees(
        c.protocolSpreadFeeE6, c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8, c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
    );

    address previousAdmin = poolAdmin[pool];
    poolAdmin[pool] = pending;
    delete pendingPoolAdmin[pool];
    // Force new admin to explicitly set their own destination
    delete poolAdminFeeDestination[pool];
    emit PoolAdminTransferred(pool, previousAdmin, pending);
}
```

Alternatively, require the proposer to supply a `newAdminFeeDestination` in `proposePoolAdminTransfer` and apply it atomically in `acceptPoolAdmin`.

---

### Proof of Concept

1. Pool has been active; admin fees have accrued (non-zero spread surplus or `notionalFeeToken0/1Scaled`).
2. Old admin calls `proposePoolAdminTransfer(pool, newAdmin)`.
3. New admin calls `acceptPoolAdmin(pool)`:
   - `poolAdmin[pool]` → `newAdmin`
   - `poolAdminFeeDestination[pool]` → **unchanged** (still old admin's address)
4. Old admin (or any keeper) calls `collectPoolFees(pool)`:
   - All accrued admin fees are transferred to `poolAdminFeeDestination[pool]` = old admin's address.
5. New admin calls `setPoolAdminFeeDestination(pool, newAdminDest)` — but all previously accrued fees are already gone.

The new admin has no way to prevent step 4 without front-running it, mirroring exactly the NFV-savior scenario where the new owner cannot prevent the old owner's configuration from being triggered before they can clear it.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L220-220)
```text
    poolAdminFeeDestination[pool] = params.adminFeeDestination;
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L518-526)
```text
  function acceptPoolAdmin(address pool) external override nonReentrant {
    address pending = pendingPoolAdmin[pool];
    if (pending == address(0)) revert NoPendingPoolAdminTransfer();
    if (msg.sender != pending) revert NotPendingPoolAdmin(pool, msg.sender, pending);
    address previousAdmin = poolAdmin[pool];
    poolAdmin[pool] = pending;
    delete pendingPoolAdmin[pool];
    emit PoolAdminTransferred(pool, previousAdmin, pending);
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

**File:** metric-core/docs/POOL_CONFIGURATION_AND_MANAGEMENT.md (L193-193)
```markdown
| **`collectPoolFees(pool)`**        | Uses **`poolFeeConfig`** to split accrued fees on the pool: **admin** share goes to **`poolAdminFeeDestination`**; **protocol** share is transferred to the **`FACTORY`** address (the pool’s `transferToken0/1(FACTORY, …)`). | **Permissionless** — any address may call (keepers, pool admin, or bots). Does not change fee configuration. Run on an operational schedule; sweep protocol balances from the factory with **`collectTokens`** / **`collectEth`** when moving to treasury. |
```
