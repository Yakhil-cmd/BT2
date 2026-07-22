### Title
Admin Fee Destination Not Reset on Pool Admin Transfer Allows Old Admin to Drain Accumulated Fees - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

When pool admin ownership is transferred via `proposePoolAdminTransfer` / `acceptPoolAdmin`, the `poolAdminFeeDestination[pool]` mapping is never cleared or updated. Because `collectPoolFees` is permissionless, the outgoing admin (or any actor) can immediately call it after the transfer completes, routing all accumulated admin-share fees to the old admin's address rather than the new admin's.

### Finding Description

`acceptPoolAdmin` transfers the `poolAdmin[pool]` role to the new admin but leaves `poolAdminFeeDestination[pool]` pointing to the address the old admin originally set: [1](#0-0) 

No reset of `poolAdminFeeDestination` occurs anywhere in that function. The permissionless `collectPoolFees` then uses the stale destination: [2](#0-1) 

`collectFees` on the pool transfers the admin fee share directly to `poolAdminFeeDestination[pool]`: [3](#0-2) 

The new admin must separately call `setPoolAdminFeeDestination` to update the destination, but there is a race window — and no atomicity guarantee — between `acceptPoolAdmin` and that update. [4](#0-3) 

### Impact Explanation

All admin-share fees accrued in the pool up to the moment of transfer (spread surplus and notional fee balances) can be extracted to the old admin's address by anyone calling `collectPoolFees` in the block(s) after `acceptPoolAdmin`. The new admin receives nothing for that accrued period. This is a direct, quantifiable loss of owed admin fee assets.

### Likelihood Explanation

Pool admin transfers are an explicitly supported, documented flow (`proposePoolAdminTransfer` / `acceptPoolAdmin`). The old admin is the natural actor with both motive and knowledge to front-run the new admin's `setPoolAdminFeeDestination` call. No special permissions are required to trigger `collectPoolFees`; any EOA can call it.

### Recommendation

In `acceptPoolAdmin`, atomically reset `poolAdminFeeDestination[pool]` to the incoming admin's address (or to `address(0)` with a require that the new admin sets it before fees can be collected). Alternatively, collect and settle all outstanding fees to the old destination inside `acceptPoolAdmin` before transferring the role, mirroring the pattern used in `setPoolAdminFees` and `setPoolProtocolFee`.

### Proof of Concept

1. Pool has accrued admin fees (non-zero spread surplus and/or `notionalFeeToken{0,1}Scaled`).
2. Old admin calls `proposePoolAdminTransfer(pool, newAdmin)`.
3. New admin calls `acceptPoolAdmin(pool)` — `poolAdmin[pool]` is now `newAdmin`, but `poolAdminFeeDestination[pool]` still equals `oldAdminFeeDestination`.
4. Old admin (or any bot) calls `collectPoolFees(pool)` in the same or next block.
5. `collectFees` inside the pool transfers the full admin fee share to `oldAdminFeeDestination`.
6. New admin calls `setPoolAdminFeeDestination(pool, newAdminFeeDestination)` — too late; fees are gone.
7. New admin has lost all fees that accrued before the transfer.

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
