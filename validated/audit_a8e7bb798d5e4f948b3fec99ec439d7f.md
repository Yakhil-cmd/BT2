### Title
`setPoolAdminFeeDestination` Redirects Already-Accrued Admin Fees to New Destination Without Prior Collection - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` without first flushing accrued fees to the old destination. Every other fee-mutating function in the factory (`setPoolAdminFees`, `setPoolProtocolFee`) calls `collectFees` before changing configuration. The missing flush means all fees accrued under the old destination are silently redirected to the new one on the next `collectPoolFees` call.

### Finding Description

`setPoolAdminFees` and `setPoolProtocolFee` both follow the same pattern: collect accrued fees at the current rates/destination, then update configuration. [1](#0-0) 

`setPoolAdminFeeDestination` does not follow this pattern. It overwrites `poolAdminFeeDestination[pool]` immediately, with no prior flush: [2](#0-1) 

`collectPoolFees` (permissionless) reads `poolAdminFeeDestination[pool]` at call time and passes it directly into `pool.collectFees`: [3](#0-2) 

The pool's `collectFees` then transfers the entire admin share — spread surplus and notional accumulator — to whatever address is stored at that moment: [4](#0-3) 

There is no on-pool record of which destination earned which portion of the surplus. Once `poolAdminFeeDestination[pool]` is overwritten, the old destination's claim is permanently lost.

### Impact Explanation

The old admin fee destination (e.g., a DAO treasury or a multisig with independent signers) loses all fees that accrued before the destination change. Those tokens are transferred to the new destination on the next `collectPoolFees` call. The loss is bounded by the total admin-share of spread surplus plus notional accumulator at the time of the change — real token amounts proportional to pool trading volume.

### Likelihood Explanation

The pool admin is a semi-trusted role that legitimately rotates treasury addresses during operational transitions (multisig key rotation, DAO governance handover). The trigger is a single call to `setPoolAdminFeeDestination` while any fees have accrued — a routine scenario for any active pool. `collectPoolFees` is permissionless, so a watcher can front-run the destination change to force collection before the update, but the pool admin can equally front-run in the opposite direction. No special conditions are required beyond normal pool operation.

### Recommendation

Mirror the pattern used by `setPoolAdminFees` and `setPoolProtocolFee`: collect accrued fees at the current destination before updating `poolAdminFeeDestination[pool]`.

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();

    // Flush accrued fees to the current destination before rotating.
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

### Proof of Concept

1. Pool is deployed with `adminFeeDestination = oldTreasury`.
2. Swaps execute; spread surplus and notional accumulators grow, giving `oldTreasury` a proportional claim.
3. Pool admin calls `setPoolAdminFeeDestination(pool, newTreasury)`. No collection occurs; `poolAdminFeeDestination[pool]` is now `newTreasury`.
4. Anyone calls `collectPoolFees(pool)`. The factory reads `poolAdminFeeDestination[pool] == newTreasury` and passes it to `pool.collectFees`.
5. The pool transfers the entire admin share — including all fees earned before step 3 — to `newTreasury`.
6. `oldTreasury` receives zero tokens despite having earned fees during steps 1–2.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L416-421)
```text
      if (totalFee0ToAdmin > 0) {
        transferToken0(adminFeeDestination_, totalFee0ToAdmin);
      }
      if (totalFee1ToAdmin > 0) {
        transferToken1(adminFeeDestination_, totalFee1ToAdmin);
      }
```
