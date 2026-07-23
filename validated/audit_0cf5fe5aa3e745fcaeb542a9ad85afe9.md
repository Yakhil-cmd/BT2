### Title
Blocklisted `adminFeeDestination` permanently locks protocol fees and breaks fee management — (`metric-core/contracts/MetricOmmPool.sol`, `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPool.collectFees` pushes tokens directly to `adminFeeDestination_` via `safeTransfer`. When a pool's token is USDC or USDT and `adminFeeDestination` is a blocklisted address, every call to `collectFees` reverts. Because `setPoolAdminFees` and `setPoolProtocolFee` both call `collectFees` as a mandatory first step before updating fee state, a blocklisted destination permanently freezes protocol fee collection and blocks the protocol owner from updating protocol fees for that pool. The protocol owner has no path to override `adminFeeDestination`—only the pool admin can change it.

---

### Finding Description

`MetricOmmPool.collectFees` distributes accrued fees by pushing tokens to two addresses in sequence: [1](#0-0) 

```solidity
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

The admin transfer is attempted **before** the protocol transfer. `transferToken0`/`transferToken1` use OpenZeppelin `SafeERC20.safeTransfer`, which reverts on failure. If `adminFeeDestination_` is on the USDC or USDT blocklist, the entire `collectFees` call reverts—including the protocol leg.

`collectFees` is called as a mandatory prerequisite inside three factory functions:

**`collectPoolFees`** (callable by anyone): [2](#0-1) 

**`setPoolAdminFees`** (pool admin): [3](#0-2) 

**`setPoolProtocolFee`** (protocol owner): [4](#0-3) 

All three revert atomically when `adminFeeDestination` is blocklisted.

`adminFeeDestination` is stored in factory-side mapping `poolAdminFeeDestination[pool]` and is updated exclusively by the pool admin via `setPoolAdminFeeDestination`: [5](#0-4) 

The only validation is `newAdminFeeDestination != address(0)`. There is no check against token blocklists. The protocol owner has **no function** to override `poolAdminFeeDestination[pool]`—it is exclusively pool-admin-controlled.

---

### Impact Explanation

When `adminFeeDestination` is a USDC/USDT-blocklisted address for a pool denominated in those tokens:

1. **Protocol fees permanently locked**: All accrued spread and notional fees (both admin and protocol shares) remain trapped in the pool contract indefinitely. `collectPoolFees` reverts for anyone.
2. **Protocol owner cannot update protocol fees**: `setPoolProtocolFee` reverts before it can write new fee config or call `setPoolFees` on the pool. The protocol owner loses the ability to adjust protocol fee rates for that pool.
3. **Pool admin cannot update admin fees**: `setPoolAdminFees` reverts before it can update `poolFeeConfig` or call `setPoolFees`. Fee rate management is frozen.

The notional fee accumulators (`notionalFeeToken0Scaled`, `notionalFeeToken1Scaled`) are only cleared inside `collectFees` after the transfers succeed: [6](#0-5) 

Since the function reverts before reaching those lines, the accumulators grow unboundedly, and the surplus calculation in future `collectFees` attempts will also be affected.

---

### Likelihood Explanation

Two conditions must hold simultaneously:
1. The pool's token0 or token1 is USDC or USDT (explicitly in scope per the allowed impact gate).
2. `adminFeeDestination` is or becomes a blocklisted address.

Condition 2 can arise in two ways:
- **Accidental**: The pool admin sets `adminFeeDestination` to a multisig or smart contract that is later added to the USDC/USDT blocklist (e.g., a sanctioned entity). The admin may not notice until fee collection fails.
- **Deliberate**: A semi-trusted pool admin deliberately sets `adminFeeDestination` to a known blocklisted address to grief the protocol. The pool admin also loses their own admin fees, so the incentive is low, but the capability exists within the semi-trusted boundary.

The protocol owner has no recovery path without pool admin cooperation.

---

### Recommendation

Separate the admin and protocol fee transfers so that a failure on the admin leg does not block the protocol leg. Two options:

1. **Pull pattern**: Do not push fees to `adminFeeDestination` inside `collectFees`. Instead, credit an internal balance mapping and let the admin pull their share separately. The protocol leg transfers to `FACTORY` unconditionally.

2. **Try/catch isolation**: Wrap the admin transfer in a `try/catch` so that a revert on the admin leg is recorded (e.g., credited to a claimable balance) without reverting the protocol transfer or the fee-config update.

Additionally, decouple fee-config updates from fee collection: `setPoolAdminFees` and `setPoolProtocolFee` should be able to update fee rates even if the current collection fails, or should call collection in a non-reverting wrapper.

---

### Proof of Concept

```
Setup:
  - Pool with token0 = USDC, token1 = WETH
  - adminFeeDestination = 0xBLOCKLISTED (a USDC-blocklisted address)
  - adminSpreadFeeE6 > 0, so totalFee0ToAdmin > 0 after swaps

Attack:
  1. Pool admin calls setPoolAdminFeeDestination(pool, 0xBLOCKLISTED)
     → poolAdminFeeDestination[pool] = 0xBLOCKLISTED (no revert, only non-zero check)

  2. Swaps occur; spread surplus and notional accumulators grow.

  3. Anyone calls collectPoolFees(pool):
     → factory calls pool.collectFees(..., 0xBLOCKLISTED)
     → pool computes totalFee0ToAdmin > 0
     → transferToken0(0xBLOCKLISTED, amount) → USDC.safeTransfer reverts (blocklisted)
     → entire collectFees reverts
     → protocol fees remain in pool; notional accumulators not cleared

  4. Protocol owner calls setPoolProtocolFee(pool, newFee, newNotional):
     → factory calls pool.collectFees(..., 0xBLOCKLISTED) first
     → same revert → protocol owner cannot update protocol fees

  5. Pool admin calls setPoolAdminFees(pool, 0, 0):
     → factory calls pool.collectFees(..., 0xBLOCKLISTED) first
     → same revert → admin cannot change fees either

Result: Protocol fees permanently locked; fee management frozen for this pool.
        Only the pool admin can unblock by calling setPoolAdminFeeDestination to a valid address.
        Protocol owner has no override.
```

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

**File:** metric-core/contracts/MetricOmmPool.sol (L429-430)
```text
      notionalFeeToken0Scaled = 0;
      notionalFeeToken1Scaled = 0;
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
