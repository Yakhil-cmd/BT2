### Title
Push-payment griefing in `collectFees` permanently blocks protocol fee collection and fee-rate updates — (`metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

`MetricOmmPool.collectFees` unconditionally pushes tokens to `adminFeeDestination_` with `safeTransfer`. If that address is USDC/USDT-blacklisted (or is a reverting contract), every call to `collectFees` reverts. Because `collectPoolFees`, `setPoolProtocolFee`, and `setPoolAdminFees` all invoke `collectFees` as a mandatory first step, all three entry-points become permanently bricked for the affected pool, and all accrued protocol fees are permanently stranded inside the pool.

---

### Finding Description

`MetricOmmPool.collectFees` distributes fees with four sequential `safeTransfer` calls:

```
if (totalFee0ToAdmin > 0) transferToken0(adminFeeDestination_, totalFee0ToAdmin);   // ← reverts here
if (totalFee1ToAdmin > 0) transferToken1(adminFeeDestination_, totalFee1ToAdmin);
if (totalFee0ToProtocol > 0) transferToken0(FACTORY, totalFee0ToProtocol);
if (totalFee1ToProtocol > 0) transferToken1(FACTORY, totalFee1ToProtocol);
notionalFeeToken0Scaled = 0;   // ← never reached
notionalFeeToken1Scaled = 0;
``` [1](#0-0) 

`adminFeeDestination_` is the value stored in `poolAdminFeeDestination[pool]`, which the pool admin sets via `setPoolAdminFeeDestination`. If that address is later blacklisted by USDC (token0 or token1), `safeTransfer` reverts and the entire `collectFees` call fails.

Every factory path that needs to collect or update fees calls `collectFees` as a mandatory, non-skippable first step:

**`collectPoolFees`** (callable by anyone): [2](#0-1) 

**`setPoolProtocolFee`** (factory owner only): [3](#0-2) 

**`setPoolAdminFees`** (pool admin only): [4](#0-3) 

Because `collectFees` is the only mechanism that zeroes `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` and transfers the spread surplus, a permanent revert means:

1. All notional fees already accrued in `notionalFeeToken0Scaled` / `notionalFeeToken1Scaled` are frozen in the pool forever.
2. All spread-fee surplus (pool balance above `binTotals`) is frozen forever.
3. The factory owner cannot call `setPoolProtocolFee` to adjust the protocol fee rate for that pool.
4. The pool admin cannot call `setPoolAdminFees` to adjust their own fee rate.

---

### Impact Explanation

- **Direct loss of protocol fees**: All spread and notional fees accrued in the pool are permanently unrecoverable. The factory (protocol) and the pool admin both lose their owed fee revenue.
- **Broken core admin functionality**: `setPoolProtocolFee` and `setPoolAdminFees` are permanently DoS'd for the affected pool. The factory owner cannot correct fee rates even in an emergency.
- **No recovery path**: The factory owner has no function to override `poolAdminFeeDestination`; only the pool admin can call `setPoolAdminFeeDestination`. If the pool admin is uncooperative or their keys are lost, the pool is permanently bricked for fee collection.

---

### Likelihood Explanation

- USDC and USDT both implement address-level blacklists. Any pool whose token0 or token1 is USDC/USDT is exposed.
- `adminFeeDestination` is commonly set to a multisig or DAO treasury. Such addresses can be blacklisted by USDC (e.g., due to regulatory action or a compromised key).
- No malicious intent is required: a legitimately-set destination that is later blacklisted triggers the bug automatically.
- The contest scope explicitly includes USDC/USDT non-standard behavior as in-scope.

---

### Recommendation

Replace the push-payment pattern in `collectFees` with a pull-payment (claimable balance) pattern, or wrap each `safeTransfer` in a `try/catch` that credits an internal claimable balance on failure:

```solidity
// Instead of:
transferToken0(adminFeeDestination_, totalFee0ToAdmin);

// Use:
try IERC20(TOKEN0).transfer(adminFeeDestination_, totalFee0ToAdmin) returns (bool ok) {
    if (!ok) claimable0[adminFeeDestination_] += totalFee0ToAdmin;
} catch {
    claimable0[adminFeeDestination_] += totalFee0ToAdmin;
}
```

Alternatively, separate fee accounting from fee distribution: let `collectFees` only update internal claimable balances, and expose a separate `withdrawFees(address destination)` function that the destination calls itself (pull pattern).

---

### Proof of Concept

1. Pool is created with token0 = USDC, token1 = WETH. Pool admin sets `adminFeeDestination` to address `D`.
2. Swaps occur; `notionalFeeToken0Scaled` accumulates USDC fees; spread surplus accumulates in the pool balance.
3. USDC blacklists address `D` (e.g., regulatory action).
4. Anyone calls `collectPoolFees(pool)`:
   - `collectFees` is called with `adminFeeDestination_ = D`.
   - `transferToken0(D, totalFee0ToAdmin)` → `IERC20(USDC).safeTransfer(D, ...)` → USDC reverts (blacklisted).
   - Entire transaction reverts. Protocol fees are not transferred. `notionalFeeToken0Scaled` is not zeroed.
5. Factory owner calls `setPoolProtocolFee(pool, newFee, newFee)`:
   - Same `collectFees` call → same revert. Protocol fee rate cannot be updated.
6. Pool admin calls `setPoolAdminFees(pool, newFee, newFee)`:
   - Same `collectFees` call → same revert. Admin fee rate cannot be updated.
7. All accrued fees remain permanently locked in the pool. The factory owner has no override to change `poolAdminFeeDestination[pool]`.

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L318-360)
```text
  function setPoolProtocolFee(address pool, uint24 newProtocolSpreadFeeE6, uint24 newProtocolNotionalFeeE8)
    external
    override
    onlyOwner
    nonReentrant
  {
    if (newProtocolSpreadFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (newProtocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L408-435)
```text
  function setPoolAdminFees(address pool, uint24 newAdminSpreadFeeE6, uint24 newAdminNotionalFeeE8)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();

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
