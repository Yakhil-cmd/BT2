### Title
Admin Fee Destination Not Reset on Pool Admin Transfer — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`acceptPoolAdmin` transfers the `poolAdmin[pool]` role to a new address but does not reset `poolAdminFeeDestination[pool]`. Because `collectPoolFees` is permissionless, the previous admin's fee destination continues to receive all accrued admin fees until the new admin explicitly calls `setPoolAdminFeeDestination`. The previous admin (or any third party) can front-run that update to drain all accrued admin fees to the old destination.

### Finding Description

`acceptPoolAdmin` performs a two-step admin handover. Its entire state mutation is:

```solidity
// MetricOmmPoolFactory.sol L518-526
function acceptPoolAdmin(address pool) external override nonReentrant {
    address pending = pendingPoolAdmin[pool];
    if (pending == address(0)) revert NoPendingPoolAdminTransfer();
    if (msg.sender != pending) revert NotPendingPoolAdmin(pool, msg.sender, pending);
    address previousAdmin = poolAdmin[pool];
    poolAdmin[pool] = pending;          // ← role updated
    delete pendingPoolAdmin[pool];      // ← pending cleared
    emit PoolAdminTransferred(pool, previousAdmin, pending);
    // poolAdminFeeDestination[pool] is NEVER touched
}
``` [1](#0-0) 

`poolAdminFeeDestination[pool]` is set at pool creation and can be updated only by the current pool admin via `setPoolAdminFeeDestination`. It is never cleared or reset during admin transfer. [2](#0-1) 

`collectPoolFees` is explicitly permissionless — the NatSpec says "Callable by any address (keepers, admins, or bots)" — and it routes the entire admin fee share to `poolAdminFeeDestination[pool]`:

```solidity
// MetricOmmPoolFactory.sol L379-389
function collectPoolFees(address pool) external override nonReentrant {
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool).collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]   // ← still old admin's address
    );
}
``` [3](#0-2) 

Inside `MetricOmmPool.collectFees`, the admin share (both spread surplus and accrued notional) is transferred directly to `adminFeeDestination_`: [4](#0-3) 

### Impact Explanation

After `acceptPoolAdmin` completes, all admin fees accrued in the pool — spread surplus and `notionalFeeToken0Scaled`/`notionalFeeToken1Scaled` — are still routed to the previous admin's fee destination. The new admin receives nothing until they call `setPoolAdminFeeDestination`. Because `collectPoolFees` is permissionless, the previous admin (or any MEV bot) can call it in the same block as `acceptPoolAdmin` (or front-run the new admin's destination update), permanently diverting all accrued admin fees. This is a direct loss of protocol fees owed to the new admin.

### Likelihood Explanation

Every pool admin transfer triggers this condition automatically. The window exists from the moment `acceptPoolAdmin` is mined until the new admin's `setPoolAdminFeeDestination` is confirmed. On any active pool with meaningful fee accrual, the previous admin has a direct financial incentive to call `collectPoolFees` immediately after the transfer. No special permissions or malicious setup are required — the previous admin acted legitimately throughout.

### Recommendation

In `acceptPoolAdmin`, reset `poolAdminFeeDestination[pool]` to the incoming admin's address, or require the new admin to supply a new fee destination as part of `acceptPoolAdmin`. A minimal fix:

```solidity
function acceptPoolAdmin(address pool, address newFeeDestination) external override nonReentrant {
    // ... existing checks ...
    poolAdmin[pool] = pending;
    delete pendingPoolAdmin[pool];
    if (newFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newFeeDestination);
    emit PoolAdminTransferred(pool, previousAdmin, pending);
}
```

Alternatively, collect all accrued fees to the old destination atomically inside `acceptPoolAdmin` before the role switches, so the new admin starts with a clean slate.

### Proof of Concept

1. Pool is deployed; `poolAdmin[pool] = oldAdmin`, `poolAdminFeeDestination[pool] = oldAdmin` (or any address oldAdmin controls).
2. Significant swap volume accrues admin fees in the pool (`notionalFeeToken0Scaled > 0`, spread surplus > 0).
3. `oldAdmin` calls `proposePoolAdminTransfer(pool, newAdmin)`.
4. `newAdmin` calls `acceptPoolAdmin(pool)`. State after: `poolAdmin[pool] = newAdmin`, but `poolAdminFeeDestination[pool]` is still `oldAdmin`.
5. `oldAdmin` (or any address) calls `collectPoolFees(pool)`. All accrued admin fees are transferred to `oldAdmin`'s address.
6. `newAdmin` calls `setPoolAdminFeeDestination(pool, newAdmin)` — but the fees are already gone.

The new admin loses 100% of admin fees accrued up to the point of transfer. [5](#0-4) [3](#0-2) [4](#0-3)

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L510-526)
```text
  function proposePoolAdminTransfer(address pool, address newAdmin) external override nonReentrant onlyPoolAdmin(pool) {
    if (newAdmin == address(0)) revert InvalidAdmin();
    if (newAdmin == poolAdmin[pool]) revert InvalidAdmin();
    pendingPoolAdmin[pool] = newAdmin;
    emit PoolAdminTransferProposed(pool, poolAdmin[pool], newAdmin);
  }

  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
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
