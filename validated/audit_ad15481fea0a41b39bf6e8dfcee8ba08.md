### Title
One-step `setPoolAdminFeeDestination` allows permanent misdirection of accrued admin fees — (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary
`MetricOmmPoolFactory.setPoolAdminFeeDestination` overwrites `poolAdminFeeDestination[pool]` in a single call with no confirmation step. Because `collectPoolFees` is permissionless, any caller can immediately flush all accrued admin-share fees to the wrong address before the pool admin can correct the mistake, causing permanent, irrecoverable loss of those fees.

### Finding Description

`setPoolAdminFeeDestination` (lines 438–447) immediately commits the new address with only a zero-address guard:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;   // ← instant, no confirmation
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
``` [1](#0-0) 

The protocol already applies a two-step pattern for the pool admin role itself (`proposePoolAdminTransfer` + `acceptPoolAdmin`) and a timelock for oracle rotation (`proposePoolPriceProvider` + `executePoolPriceProviderUpdate`), demonstrating explicit awareness of this class of risk. The fee destination setter is the only critical address mutation that lacks any such safeguard. [2](#0-1) 

`collectPoolFees` carries **no access control** — any address may call it at any time:

```solidity
function collectPoolFees(address pool) external override nonReentrant {
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool).collectFees(
        c.protocolSpreadFeeE6, c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8, c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]   // ← uses the just-corrupted value
    );
}
``` [3](#0-2) 

Inside `MetricOmmPool.collectFees`, the admin share is transferred directly to `adminFeeDestination_`:

```solidity
if (totalFee0ToAdmin > 0) { transferToken0(adminFeeDestination_, totalFee0ToAdmin); }
if (totalFee1ToAdmin > 0) { transferToken1(adminFeeDestination_, totalFee1ToAdmin); }
``` [4](#0-3) 

A second amplification path exists: both `setPoolAdminFees` and `setPoolProtocolFee` internally call `collectFees` **before** updating fee parameters, using the current (now corrupted) `poolAdminFeeDestination[pool]`. If the admin attempts to update fees after accidentally setting a wrong destination, the collection is triggered to the wrong address as a side effect. [5](#0-4) 

### Impact Explanation

All admin-share fees accrued in the pool since the last collection are permanently transferred to the wrong address on the next `collectPoolFees` call. The admin can correct the destination for future collections, but fees already sent are irrecoverable — `safeTransfer` to the wrong address succeeds and there is no pull-back mechanism. In a high-volume pool the accrued admin fees between the wrong setting and the correction can be substantial.

### Likelihood Explanation

The pool admin is a semi-trusted role that may be operated by a human (EOA or multisig). Address typos are a realistic operational hazard, especially when managing multiple pools across chains. The permissionless nature of `collectPoolFees` means the exposure window is zero blocks — any keeper, bot, or front-runner can trigger collection the moment the wrong destination is set, before the admin can issue a corrective transaction.

### Recommendation

Apply the same two-step pattern already used for pool admin transfers:

1. `proposePoolAdminFeeDestination(pool, newDestination)` — records the pending destination in a `pendingPoolAdminFeeDestination[pool]` mapping.
2. `acceptPoolAdminFeeDestination(pool)` — callable only by `msg.sender == pendingPoolAdminFeeDestination[pool]`, confirming the new address can receive tokens and is under the admin's control.

Alternatively, add a short timelock (matching `priceProviderTimelock`) before the new destination takes effect, giving the admin a window to cancel a mistaken proposal.

### Proof of Concept

1. Pool admin calls `setPoolAdminFeeDestination(pool, 0xWRONG)` with a typo.
2. `poolAdminFeeDestination[pool]` is immediately overwritten to `0xWRONG`.
3. Any address (bot, keeper, or MEV searcher) calls `collectPoolFees(pool)` in the same or next block.
4. `MetricOmmPool.collectFees` executes `transferToken0(0xWRONG, totalFee0ToAdmin)` and `transferToken1(0xWRONG, totalFee1ToAdmin)` — all accrued admin fees are sent to `0xWRONG` and permanently lost.
5. Pool admin calls `setPoolAdminFeeDestination(pool, 0xCORRECT)` to fix it.
6. Future fees go to `0xCORRECT`, but the fees already sent to `0xWRONG` are irrecoverable.

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
