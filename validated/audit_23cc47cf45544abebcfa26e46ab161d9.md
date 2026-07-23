### Title
Blocklisted `adminFeeDestination` in USDC/USDT pool permanently DoS-es fee collection and blocks protocol fee updates — (`metric-core/contracts/MetricOmmPool.sol`, `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPool.collectFees` transfers the admin fee share to `adminFeeDestination_` using `safeTransfer`. If that address is blocklisted by a USDC/USDT pool token, every call to `collectFees` reverts. Because `setPoolProtocolFee` and `setPoolAdminFees` in the factory both call `collectFees` atomically before writing new fee config, a blocklisted `adminFeeDestination` permanently prevents the factory owner from updating protocol fees and the pool admin from updating admin fees for that pool, while all accrued protocol fees remain permanently locked inside the pool.

---

### Finding Description

`MetricOmmPool.collectFees` performs four `safeTransfer` calls in sequence:

```
transferToken0(adminFeeDestination_, totalFee0ToAdmin);   // line 417
transferToken1(adminFeeDestination_, totalFee1ToAdmin);   // line 420
transferToken0(FACTORY, totalFee0ToProtocol);             // line 423
transferToken1(FACTORY, totalFee1ToProtocol);             // line 426
notionalFeeToken0Scaled = 0;                              // line 429
notionalFeeToken1Scaled = 0;                              // line 430
``` [1](#0-0) 

`transferToken0` and `transferToken1` are thin wrappers around `IERC20.safeTransfer`: [2](#0-1) 

If `adminFeeDestination_` is blocklisted by the pool's token0 or token1 (e.g., USDC or USDT), the first `safeTransfer` to it reverts, unwinding the entire transaction. The notional fee accumulators are never zeroed, and no fees are distributed.

Three factory entry-points are broken by this:

**1. `collectPoolFees` (permissionless)** — calls `collectFees` directly; reverts on every invocation, permanently locking all accrued spread and notional fees inside the pool. [3](#0-2) 

**2. `setPoolProtocolFee` (factory owner only)** — calls `collectFees` at old rates *before* writing the new `poolFeeConfig`. A revert here means the factory owner can never update the protocol fee for this pool. [4](#0-3) 

**3. `setPoolAdminFees` (pool admin only)** — same pattern; the pool admin cannot update their own fee components. [5](#0-4) 

The `adminFeeDestination` is set by the pool admin via `setPoolAdminFeeDestination`, which performs no `collectFees` call and accepts any non-zero address without restriction: [6](#0-5) 

The factory owner has no independent path to override `poolAdminFeeDestination[pool]`; only the pool admin can call `setPoolAdminFeeDestination`. If the pool admin is unresponsive or malicious, the factory owner has no recourse.

---

### Impact Explanation

- **Protocol fee revenue permanently locked**: All spread and notional fees accrued in the pool cannot be extracted. `collectPoolFees` reverts on every call; the `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` accumulators are never cleared.
- **Factory owner fee governance broken**: `setPoolProtocolFee` is permanently blocked for the affected pool. The factory owner cannot raise or lower the protocol fee component, cannot clamp admin fees to new caps, and cannot call `setPoolFees` on the pool through this path.
- **Pool admin fee governance broken**: `setPoolAdminFees` is also permanently blocked, preventing the pool admin from adjusting their own fee components.

---

### Likelihood Explanation

USDC and USDT both implement blocklisting. The `adminFeeDestination` is a mutable address controlled by the semi-trusted pool admin with no timelock or cap. Two realistic paths exist:

- **External event**: A previously valid `adminFeeDestination` (e.g., a multisig or treasury) is blocklisted by USDC/USDT due to regulatory action after pool creation.
- **Semi-trusted actor griefing**: The pool admin deliberately calls `setPoolAdminFeeDestination` with a known-blocklisted address, permanently blocking the factory owner's `setPoolProtocolFee` for that pool at zero cost beyond gas.

The second path requires only a single transaction from the pool admin and has no on-chain defense.

---

### Recommendation

Decouple fee distribution from fee configuration updates. Two options:

1. **Non-reverting transfer helper**: Replace `safeTransfer` in `collectFees` with a try/catch or a non-reverting transfer. On failure, leave the fee amount credited to a per-address claimable balance rather than reverting the entire call. This mirrors the "pull over push" pattern.

2. **Separate collection from configuration**: Remove the embedded `collectFees` call from `setPoolProtocolFee` and `setPoolAdminFees`. Let fee configuration updates proceed independently of whether the current `adminFeeDestination` is reachable. Fees already accrued at old rates can be collected separately (or written off to a claimable balance).

---

### Proof of Concept

1. Deploy a pool with USDC as `token0`.
2. Pool admin calls `setPoolAdminFeeDestination(pool, blocklisted_address)` where `blocklisted_address` is USDC-blocklisted.
3. Swaps occur; `notionalFeeToken0Scaled` and spread surplus accumulate.
4. Any caller invokes `factory.collectPoolFees(pool)` → reverts because `USDC.safeTransfer(blocklisted_address, amount)` reverts.
5. Factory owner calls `factory.setPoolProtocolFee(pool, newFee, 0)` → reverts for the same reason; protocol fee config is frozen.
6. Pool admin calls `factory.setPoolAdminFees(pool, newFee, 0)` → reverts; admin fee config is also frozen.
7. All accrued fees remain locked in the pool indefinitely. The factory owner has no path to override `poolAdminFeeDestination[pool]`.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L416-430)
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

      notionalFeeToken0Scaled = 0;
      notionalFeeToken1Scaled = 0;
```

**File:** metric-core/contracts/MetricOmmPool.sol (L565-571)
```text
  function transferToken0(address to, uint256 amount) internal {
    IERC20(TOKEN0).safeTransfer(to, amount);
  }

  function transferToken1(address to, uint256 amount) internal {
    IERC20(TOKEN1).safeTransfer(to, amount);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L327-360)
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

    uint24 aSpread = c.adminSpreadFeeE6;
    uint24 aNotional = c.adminNotionalFeeE8;
    if (aSpread > maxAdminSpreadFeeE6) {
      aSpread = maxAdminSpreadFeeE6;
      emit PoolAdminSpreadFeeUpdated(pool, aSpread);
    }
    if (aNotional > maxAdminNotionalFeeE8) {
      aNotional = maxAdminNotionalFeeE8;
      emit PoolAdminNotionalFeeUpdated(pool, aNotional);
    }

    c = PoolFeeConfig({
      protocolSpreadFeeE6: newProtocolSpreadFeeE6,
      adminSpreadFeeE6: aSpread,
      protocolNotionalFeeE8: newProtocolNotionalFeeE8,
      adminNotionalFeeE8: aNotional
    });
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolProtocolSpreadFeeUpdated(pool, newProtocolSpreadFeeE6);
    emit PoolProtocolNotionalFeeUpdated(pool, newProtocolNotionalFeeE8);
  }
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L417-435)
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

    c.adminSpreadFeeE6 = newAdminSpreadFeeE6;
    c.adminNotionalFeeE8 = newAdminNotionalFeeE8;
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
    emit PoolAdminSpreadFeeUpdated(pool, newAdminSpreadFeeE6);
    emit PoolAdminNotionalFeeUpdated(pool, newAdminNotionalFeeE8);
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
