### Title
Unhandled revert in `collectFees` when `adminFeeDestination` reverts on token receipt permanently blocks `setPoolProtocolFee`, `setPoolAdminFees`, and `collectPoolFees` — (File: metric-core/contracts/MetricOmmPoolFactory.sol)

---

### Summary

`setPoolProtocolFee` (factory owner) and `setPoolAdminFees` (pool admin) both call `collectFees` on the pool **before** updating fee state. Inside `collectFees`, tokens are transferred to `adminFeeDestination_` via `safeTransfer`. If `adminFeeDestination_` is a contract that reverts on ERC20 receipt, the transfer reverts with no try/catch, propagating up through `collectFees` and blocking all downstream state updates. The pool admin can set any non-zero address as `adminFeeDestination` with no validation of token receivability, making this a reachable semi-trusted trigger.

---

### Finding Description

**Root cause — `MetricOmmPool.collectFees`:** [1](#0-0) 

The admin fee transfer (lines 416–421) executes **before** the protocol fee transfer (lines 422–427) and **before** the state reset `notionalFeeToken0Scaled = 0` / `notionalFeeToken1Scaled = 0` (lines 429–430). `transferToken0` / `transferToken1` use `safeTransfer`, which reverts if the recipient contract reverts. There is no try/catch around either transfer. A revert at line 417 or 420 unwinds the entire call, leaving `notionalFeeToken0Scaled` and `notionalFeeToken1Scaled` non-zero and all surplus balance untouched.

**Propagation — `setPoolProtocolFee`:** [2](#0-1) 

`collectFees` is called at line 328 with no error handling. If it reverts, the factory never reaches `poolFeeConfig[pool] = c` (line 354) or `setPoolFees(...)` (line 356). The factory owner's protocol-fee update is permanently blocked for that pool.

**Same propagation — `setPoolAdminFees`:** [3](#0-2) 

`collectFees` at line 418 blocks `poolFeeConfig[pool] = c` (line 429) and `setPoolFees(...)` (line 431).

**Same propagation — `collectPoolFees` (permissionless):** [4](#0-3) 

Any caller's attempt to collect fees reverts, so accumulated fees can never leave the pool.

**Trigger — `setPoolAdminFeeDestination`:** [5](#0-4) 

The only validation is `!= address(0)`. A contract that reverts on ERC20 receipt (e.g., a broken multisig, a contract with a reverting `fallback`, or any contract that does not implement token receipt) is accepted without restriction. The same gap exists at pool creation: [6](#0-5) 

---

### Impact Explanation

1. **Protocol fees permanently stuck in pool.** `collectPoolFees` is permissionless but reverts. Both spread-fee surplus (held as pool token balance above `binTotals`) and notional fees (`notionalFeeToken0Scaled` / `notionalFeeToken1Scaled`) accumulate indefinitely with no extraction path. This is a direct loss of protocol and admin fee revenue.

2. **Factory owner cannot update protocol fees for the affected pool.** `setPoolProtocolFee` reverts before writing `poolFeeConfig[pool]` or calling `setPoolFees` on the pool. The pool continues operating at stale fee rates regardless of factory owner intent — an admin-boundary break where a semi-trusted pool admin neutralises a factory-owner control.

3. **Pool admin cannot update their own admin fees.** `setPoolAdminFees` reverts before writing the new config. The pool admin is also self-locked, but the factory-owner blockage is the contest-relevant impact.

---

### Likelihood Explanation

The pool admin is semi-trusted and can call `setPoolAdminFeeDestination` at any time post-deployment with any non-zero address. Realistic triggers include:

- A multisig fee destination that is later upgraded to a contract that reverts on token receipt.
- A pool admin who intentionally sets a reverting contract to block the factory owner from adjusting protocol fees.
- An accidental misconfiguration (e.g., setting a contract address that only accepts ETH, not ERC-20).

The pool admin can self-recover by calling `setPoolAdminFeeDestination` with a valid address — but only if they retain control of the admin key. If the admin key is lost or the action is intentional, the block is permanent.

---

### Recommendation

1. **Decouple fee collection from fee-rate updates.** In `setPoolProtocolFee` and `setPoolAdminFees`, update `poolFeeConfig` and call `setPoolFees` unconditionally; make fee collection a separate, optional step (or use try/catch to collect best-effort and continue regardless).

2. **Validate `adminFeeDestination` receivability.** In `setPoolAdminFeeDestination` (and at `createPool`), perform a zero-value `safeTransfer` probe or require the destination to pass a token-receipt check before accepting it.

3. **Reorder transfers in `collectFees`.** Transfer protocol fees to `FACTORY` before admin fees to `adminFeeDestination_`, and reset `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` before any external transfer, so protocol accounting is preserved even if the admin transfer fails.

---

### Proof of Concept

```
1. Deploy a pool with a valid adminFeeDestination (e.g., EOA).
2. Pool admin calls setPoolAdminFeeDestination(pool, address(revertOnReceive))
   where revertOnReceive is a contract whose fallback/receive reverts on ERC20 safeTransfer.
3. Swaps occur; notionalFeeToken0Scaled and surplus balance accumulate.
4. Anyone calls collectPoolFees(pool) → collectFees reverts at transferToken0(revertOnReceive, ...) → fees stuck.
5. Factory owner calls setPoolProtocolFee(pool, newFee, 0) → same revert → poolFeeConfig never updated, pool's spreadFeeE6/notionalFeeE8 unchanged.
6. Pool admin calls setPoolAdminFees(pool, 0, 0) → same revert → admin fee config frozen.
7. All three entry points are permanently bricked for this pool until the pool admin (if they still hold the key) calls setPoolAdminFeeDestination with a valid address.
```

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L327-357)
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L417-432)
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L553-554)
```text
    _validatePriceProvider(params.token0, params.token1, params.priceProvider);
    if (params.adminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
```
