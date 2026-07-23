### Title
Unbounded timelock in `OracleValueStopLossExtension.proposeOracleStopLossTimelock` permanently freezes all stop-loss configuration — (`File: metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol`)

---

### Summary

`OracleValueStopLossExtension.proposeOracleStopLossTimelock` accepts any `uint32 newTimelock` with no upper-bound validation. Because every subsequent proposal (drawdown, decay, watermarks, and the timelock itself) computes its `executeAfter` from the **current** stored timelock via `_afterTimelock`, a pool admin who executes a very large timelock value permanently freezes all stop-loss configuration changes for up to ~136 years. This is the direct analog of the GovernanceProxy DOS: changing the timelock to a lower value requires waiting out the very large timelock that was just set.

---

### Finding Description

`_afterTimelock` reads the live `oracleStopLossConfig[pool_].timelock` and adds it to `block.timestamp`:

```solidity
// OracleValueStopLossExtension.sol L297-299
function _afterTimelock(address pool_) private view returns (uint32) {
    return uint32(block.timestamp + oracleStopLossConfig[pool_].timelock);
}
``` [1](#0-0) 

Every propose function — `proposeOracleStopLossTimelock`, `proposeOracleStopLossDrawdown`, `proposeOracleStopLossDecay`, and `proposeOracleStopLossHighWatermarks` — calls `_afterTimelock` to stamp the pending proposal's `executeAfter`:

```solidity
// L78-84
function proposeOracleStopLossTimelock(address pool_, uint32 newTimelock) external onlyPoolAdmin(pool_) {
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);   // uses CURRENT timelock
    sched.pendingTimelock = newTimelock;
    sched.pendingTimelockExecuteAfter = executeAfter;
    ...
}
``` [2](#0-1) 

There is **no cap** on `newTimelock`. The only validations in the contract are for `drawdownE6` (≤ 1e6) and `decayPerSecondE8` (≤ 1e8); the timelock field is accepted as-is:

```solidity
// L56-61 (initialize) — no timelock validation
(uint32 drawdownE6, uint32 decayPerSecondE8, uint32 timelock) = abi.decode(data, (uint32, uint32, uint32));
_validateDrawdown(drawdownE6);
_validateDecay(decayPerSecondE8);
// timelock stored without any bound check
``` [3](#0-2) 

**Attack path:**

1. Pool starts with `timelock = 1 day` (reasonable).
2. Pool admin calls `proposeOracleStopLossTimelock(pool, 2_541_967_294)` — ≈ 80 years in seconds, chosen so `block.timestamp + value` stays within `uint32` range.
3. After 1 day, admin calls `executeOracleStopLossTimelock(pool)`. The stored timelock is now 80 years.
4. Admin realizes the drawdown is misconfigured (e.g., too tight, causing false stop-loss triggers that block all swaps). Admin calls `proposeOracleStopLossDrawdown(pool, newValue)`.
5. `_afterTimelock` stamps `executeAfter = block.timestamp + 80 years`. The drawdown fix cannot be applied for 80 years.
6. To reduce the timelock itself, admin calls `proposeOracleStopLossTimelock(pool, 1 day)` — but `executeAfter` is again `block.timestamp + 80 years`. The timelock cannot be reduced for 80 years.

All four proposal types are frozen simultaneously. [4](#0-3) [5](#0-4) [6](#0-5) 

---

### Impact Explanation

The `OracleValueStopLossExtension` is an `afterSwap` hook. When `drawdownE6 > 0`, every swap through the pool calls `_afterSwapOracleStopLoss`, which reverts with `OracleStopLossTriggered` if the per-bin value per share falls below the drawdown floor:

```solidity
// L271-277
if (breach0 && zeroForOne) {
    revert OracleStopLossTriggered(binIdx, true, metricT0, (hwm0 * floorMultiplier) / E6);
}
...
if (breach1 && !zeroForOne) {
    revert OracleStopLossTriggered(binIdx, false, metricT1, (hwm1 * floorMultiplier) / E6);
}
``` [7](#0-6) 

If the drawdown is set too tightly (e.g., 0.1% — a value that normal oracle mid-price fluctuations can breach), every swap reverts. With the timelock frozen at 80 years, the admin cannot loosen the drawdown, reset watermarks, or disable decay. The pool's swap functionality is permanently broken for the duration of the large timelock. LPs can still remove liquidity, but the pool is commercially dead.

---

### Likelihood Explanation

The pool admin is semi-trusted and is explicitly permitted to call `proposeOracleStopLossTimelock`. No on-chain guard prevents passing `type(uint32).max` or any other large value. A single mistaken or malicious call followed by `executeOracleStopLossTimelock` (after the old, short timelock elapses) is sufficient to trigger the freeze. The scenario requires only two transactions from the pool admin — a realistic operational mistake.

---

### Recommendation

Add a hard cap on `newTimelock` in `proposeOracleStopLossTimelock` and in `initialize`. A reasonable maximum (e.g., 30 days) prevents indefinite lockout while still providing meaningful LP protection windows:

```solidity
uint32 private constant MAX_TIMELOCK = 30 days;

function proposeOracleStopLossTimelock(address pool_, uint32 newTimelock) external onlyPoolAdmin(pool_) {
    if (newTimelock > MAX_TIMELOCK) revert OracleStopLossTimelockTooLarge(newTimelock);
    ...
}
```

Apply the same check inside `initialize` for the initial timelock value.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

// Foundry test sketch (pseudo-code, uses existing test helpers)
function test_timelockDOS() public {
    // 1. Pool initialized with drawdown=5% and timelock=1 day
    uint32 LARGE_TIMELOCK = uint32(type(uint32).max - block.timestamp - 1); // ~80 years

    vm.prank(address(factoryStub));
    extension.initialize(address(pool), abi.encode(
        uint32(50_000),   // 5% drawdown
        uint32(58),       // normal decay
        uint32(1 days)    // initial timelock
    ));

    // 2. Admin proposes a very large timelock
    vm.prank(admin);
    extension.proposeOracleStopLossTimelock(address(pool), LARGE_TIMELOCK);

    // 3. After 1 day, admin executes — now timelock = ~80 years
    vm.warp(block.timestamp + 1 days);
    vm.prank(admin);
    extension.executeOracleStopLossTimelock(address(pool));

    // 4. Drawdown is too tight; admin tries to fix it — locked for 80 years
    vm.prank(admin);
    extension.proposeOracleStopLossDrawdown(address(pool), 100_000); // loosen to 10%

    // executeAfter = block.timestamp + 80 years
    vm.expectRevert(); // OracleStopLossTimelockNotElapsed
    vm.prank(admin);
    extension.executeOracleStopLossDrawdown(address(pool));

    // 5. Admin tries to reduce the timelock itself — also locked for 80 years
    vm.prank(admin);
    extension.proposeOracleStopLossTimelock(address(pool), uint32(1 days));

    vm.expectRevert(); // OracleStopLossTimelockNotElapsed
    vm.prank(admin);
    extension.executeOracleStopLossTimelock(address(pool));

    // Pool swaps revert with OracleStopLossTriggered for ~80 years.
}
``` [8](#0-7) [9](#0-8)

### Citations

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L56-61)
```text
    (uint32 drawdownE6, uint32 decayPerSecondE8, uint32 timelock) = abi.decode(data, (uint32, uint32, uint32));
    _validateDrawdown(drawdownE6);
    _validateDecay(decayPerSecondE8);

    oracleStopLossConfig[pool] = PoolStopLossConfig({
      drawdownE6: drawdownE6, decayPerSecondE8: decayPerSecondE8, timelock: timelock, initialized: true
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L78-94)
```text
  function proposeOracleStopLossTimelock(address pool_, uint32 newTimelock) external onlyPoolAdmin(pool_) {
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    sched.pendingTimelock = newTimelock;
    sched.pendingTimelockExecuteAfter = executeAfter;
    emit OracleStopLossTimelockProposed(pool_, newTimelock, executeAfter);
  }

  function executeOracleStopLossTimelock(address pool_) external onlyPoolAdmin(pool_) {
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    if (sched.pendingTimelockExecuteAfter == 0) revert OracleStopLossNoPendingTimelock(pool_);
    _requireElapsed(sched.pendingTimelockExecuteAfter);
    uint32 timelock = sched.pendingTimelock;
    oracleStopLossConfig[pool_].timelock = timelock;
    (sched.pendingTimelock, sched.pendingTimelockExecuteAfter) = (0, 0);
    emit OracleStopLossTimelockSet(pool_, timelock);
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L103-110)
```text
  function proposeOracleStopLossDrawdown(address pool_, uint256 newMaxDrawdownE6) external onlyPoolAdmin(pool_) {
    _validateDrawdown(newMaxDrawdownE6);
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    sched.pendingDrawdownE6 = uint32(newMaxDrawdownE6);
    sched.pendingDrawdownExecuteAfter = executeAfter;
    emit OracleStopLossDrawdownProposed(pool_, newMaxDrawdownE6, executeAfter);
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L130-136)
```text
  function proposeOracleStopLossDecay(address pool_, uint256 newDecayPerSecondE8) external onlyPoolAdmin(pool_) {
    _validateDecay(newDecayPerSecondE8);
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    sched.pendingDecayPerSecondE8 = uint32(newDecayPerSecondE8);
    sched.pendingDecayExecuteAfter = executeAfter;
    emit OracleStopLossDecayProposed(pool_, newDecayPerSecondE8, executeAfter);
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L157-165)
```text
  function proposeOracleStopLossHighWatermarks(address pool_, int8 binIdx, uint104 newHwmToken0, uint104 newHwmToken1)
    external
    onlyPoolAdmin(pool_)
  {
    _requireInitialized(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    pendingHighWatermark[pool_] =
      PendingHighWatermarks({token0: newHwmToken0, token1: newHwmToken1, binIdx: binIdx, executeAfter: executeAfter});
    emit OracleStopLossHighWatermarkProposed(pool_, binIdx, newHwmToken0, newHwmToken1, executeAfter);
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L271-277)
```text
    if (breach0 && zeroForOne) {
      revert OracleStopLossTriggered(binIdx, true, metricT0, (hwm0 * floorMultiplier) / E6);
    }

    (uint256 hwm1, bool breach1) = _applyWatermark(metricT1, _decayed(hwmS.token1, decayRate, dt), floorMultiplier);
    if (breach1 && !zeroForOne) {
      revert OracleStopLossTriggered(binIdx, false, metricT1, (hwm1 * floorMultiplier) / E6);
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L297-303)
```text
  function _afterTimelock(address pool_) private view returns (uint32) {
    return uint32(block.timestamp + oracleStopLossConfig[pool_].timelock);
  }

  function _requireElapsed(uint32 executeAfter) private view {
    if (block.timestamp < executeAfter) revert OracleStopLossTimelockNotElapsed(executeAfter, block.timestamp);
  }
```
