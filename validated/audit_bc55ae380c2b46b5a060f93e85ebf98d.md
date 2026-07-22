### Title
`uint32` Overflow in `_afterTimelock` Allows Pool Admin to Instantly Bypass LP-Protective Stop-Loss Timelock — (`metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol`)

---

### Summary

`OracleValueStopLossExtension._afterTimelock` casts the sum `block.timestamp + timelock` to `uint32`. When the stored `timelock` is large enough to push that sum past `type(uint32).max`, the result silently wraps to a value in the past, making every subsequent `_requireElapsed` check pass immediately. A pool admin can exploit this to atomically propose **and** execute any stop-loss parameter change — drawdown, decay, or per-bin watermarks — with zero LP reaction window, defeating the only LP-protective guard the extension provides.

---

### Finding Description

`_afterTimelock` is the single function that computes the `executeAfter` timestamp stored in every pending schedule slot:

```solidity
// OracleValueStopLossExtension.sol line 297-299
function _afterTimelock(address pool_) private view returns (uint32) {
    return uint32(block.timestamp + oracleStopLossConfig[pool_].timelock);
}
```

`oracleStopLossConfig[pool_].timelock` is a `uint32` field (max ≈ 4.29 × 10⁹ s ≈ 136 years). The addition is performed in `uint256` space, then **truncated** to `uint32`. No overflow guard exists.

The guard that enforces the delay is:

```solidity
// OracleValueStopLossExtension.sol line 301-303
function _requireElapsed(uint32 executeAfter) private view {
    if (block.timestamp < executeAfter) revert OracleStopLossTimelockNotElapsed(executeAfter, block.timestamp);
}
```

`block.timestamp` (a `uint256`) is compared against `executeAfter` (a `uint32` implicitly widened to `uint256`). If `executeAfter` has wrapped to a value smaller than the current `block.timestamp`, the comparison is `false` and the revert is never reached.

**Concrete arithmetic (July 2026, `block.timestamp ≈ 1 753 000 000`):**

| `timelock` value | `block.timestamp + timelock` | `uint32(…)` | `block.timestamp < executeAfter`? |
|---|---|---|---|
| `type(uint32).max` = 4 294 967 295 | 6 047 967 295 | **1 752 999 999** | `1 753 000 000 < 1 752 999 999` → **false** ✓ bypass |

Any `timelock ≥ type(uint32).max − block.timestamp + 1` (currently ≈ 2.54 × 10⁹ s, ≈ 80 years) triggers the wrap.

**Attack path:**

1. Admin initialises the pool with `timelock = 0` (no validation exists on the timelock value in `initialize`).
2. Admin calls `proposeOracleStopLossTimelock(pool, type(uint32).max)`. Because the current timelock is 0, `_afterTimelock` returns `uint32(block.timestamp)` — the check passes immediately.
3. Admin calls `executeOracleStopLossTimelock(pool)` in the same block. `timelock` is now `type(uint32).max`.
4. LPs observe a timelock of ~136 years and deposit, believing they have ample reaction time.
5. Admin calls `proposeOracleStopLossDrawdown(pool, 0)` (disable stop-loss) or `proposeOracleStopLossHighWatermarks(pool, bin, MAX, MAX)` (force immediate breach). `_afterTimelock` wraps to `≈ block.timestamp − 1`.
6. Admin calls the matching `execute…` function in the same transaction. `_requireElapsed(block.timestamp − 1)` passes. The change is live with **zero LP reaction window**.

No validation on `newTimelock` exists in `proposeOracleStopLossTimelock` either:

```solidity
// OracleValueStopLossExtension.sol line 78-84
function proposeOracleStopLossTimelock(address pool_, uint32 newTimelock) external onlyPoolAdmin(pool_) {
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    sched.pendingTimelock = newTimelock;
    sched.pendingTimelockExecuteAfter = executeAfter;
    emit OracleStopLossTimelockProposed(pool_, newTimelock, executeAfter);
}
```

The same overflow affects `pendingDrawdownExecuteAfter`, `pendingDecayExecuteAfter`, and `PendingHighWatermarks.executeAfter` — all computed through the same `_afterTimelock` call.

---

### Impact Explanation

The `OracleValueStopLossExtension` is explicitly documented as the mechanism that gives LPs time to exit before the admin can change stop-loss parameters:

> *"Drawdown and decay changes are timelocked so LPs can react."*

Once the overflow is triggered:

- **Drawdown set to 0**: stop-loss is disabled (`if (drawdown == 0) return`), removing the only on-chain value-loss guard for LPs.
- **Watermarks set to `type(uint104).max`**: every subsequent swap immediately breaches the floor, blocking all swaps and trapping LP funds.
- **Decay set to `type(uint32).max`**: watermarks decay to zero in one second, permanently disabling the guard.

All three outcomes represent broken core pool functionality or direct LP principal loss, satisfying the allowed impact gate.

---

### Likelihood Explanation

The admin is semi-trusted and controls the `timelock` parameter with no cap. The two-step sequence (set timelock to overflow value, then immediately execute any parameter change) requires only two transactions from the pool admin. No external conditions, oracle state, or third-party cooperation are needed. The only prerequisite is that the pool was initialised with `timelock = 0` (or the admin waited through whatever initial timelock was set to first change it to the overflow value).

---

### Recommendation

1. **Use `uint256` for `executeAfter` throughout.** Change `_afterTimelock` to return `uint256` and store all schedule timestamps as `uint256` (or at minimum `uint48`, which is safe until year 8 million):

```solidity
function _afterTimelock(address pool_) private view returns (uint256) {
    return block.timestamp + oracleStopLossConfig[pool_].timelock;
}
```

2. **Cap the maximum timelock** in both `initialize` and `proposeOracleStopLossTimelock` to a safe upper bound (e.g., 365 days) so that `block.timestamp + timelock` can never overflow even `uint256`.

3. **Update `_requireElapsed`** to accept and compare `uint256`:

```solidity
function _requireElapsed(uint256 executeAfter) private view {
    if (block.timestamp < executeAfter) revert ...;
}
```

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

// Assume: extension deployed, pool initialised with timelock=0, drawdown=500_000

function test_timelockOverflowBypass() public {
    vm.startPrank(admin);

    // Step 1: set timelock to type(uint32).max
    // Current timelock = 0 → executeAfter = block.timestamp → passes immediately
    extension.proposeOracleStopLossTimelock(pool, type(uint32).max);
    extension.executeOracleStopLossTimelock(pool);

    // Confirm timelock is now type(uint32).max
    (,, uint32 tl,) = extension.oracleStopLossConfig(pool);
    assertEq(tl, type(uint32).max);

    // Step 2: propose drawdown = 0 (disable stop-loss)
    // _afterTimelock = uint32(block.timestamp + type(uint32).max) wraps to block.timestamp - 1
    extension.proposeOracleStopLossDrawdown(pool, 0);

    // Step 3: execute immediately — no warp needed
    extension.executeOracleStopLossDrawdown(pool);

    // Stop-loss is now disabled despite the "136-year" timelock
    (uint32 dd,,,) = extension.oracleStopLossConfig(pool);
    assertEq(dd, 0); // passes
    vm.stopPrank();
}
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L44-68)
```text
  /// @notice Called once by the factory at pool creation.
  ///         `data` = `abi.encode(uint32 drawdownE6, uint32 decayPerSecondE8, uint32 timelockSeconds)`.
  function initialize(address pool, bytes calldata data)
    external
    override(BaseMetricExtension, IOracleValueStopLossExtension)
    onlyFactory
    returns (bytes4)
  {
    if (oracleStopLossConfig[pool].initialized) {
      revert OracleStopLossAlreadyInitialized(pool);
    }

    (uint32 drawdownE6, uint32 decayPerSecondE8, uint32 timelock) = abi.decode(data, (uint32, uint32, uint32));
    _validateDrawdown(drawdownE6);
    _validateDecay(decayPerSecondE8);

    oracleStopLossConfig[pool] = PoolStopLossConfig({
      drawdownE6: drawdownE6, decayPerSecondE8: decayPerSecondE8, timelock: timelock, initialized: true
    });

    emit OracleStopLossDrawdownSet(pool, drawdownE6);
    emit OracleStopLossDecaySet(pool, decayPerSecondE8);
    emit OracleStopLossTimelockSet(pool, timelock);
    return IMetricOmmExtensions.initialize.selector;
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L78-84)
```text
  function proposeOracleStopLossTimelock(address pool_, uint32 newTimelock) external onlyPoolAdmin(pool_) {
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    sched.pendingTimelock = newTimelock;
    sched.pendingTimelockExecuteAfter = executeAfter;
    emit OracleStopLossTimelockProposed(pool_, newTimelock, executeAfter);
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L103-120)
```text
  function proposeOracleStopLossDrawdown(address pool_, uint256 newMaxDrawdownE6) external onlyPoolAdmin(pool_) {
    _validateDrawdown(newMaxDrawdownE6);
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    sched.pendingDrawdownE6 = uint32(newMaxDrawdownE6);
    sched.pendingDrawdownExecuteAfter = executeAfter;
    emit OracleStopLossDrawdownProposed(pool_, newMaxDrawdownE6, executeAfter);
  }

  function executeOracleStopLossDrawdown(address pool_) external onlyPoolAdmin(pool_) {
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    if (sched.pendingDrawdownExecuteAfter == 0) revert OracleStopLossNoPendingDrawdown(pool_);
    _requireElapsed(sched.pendingDrawdownExecuteAfter);
    uint32 drawdown = sched.pendingDrawdownE6;
    oracleStopLossConfig[pool_].drawdownE6 = drawdown;
    (sched.pendingDrawdownE6, sched.pendingDrawdownExecuteAfter) = (0, 0);
    emit OracleStopLossDrawdownSet(pool_, drawdown);
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L156-166)
```text
  /// @notice Propose per-bin high watermarks; applied after the pool timelock via execute.
  function proposeOracleStopLossHighWatermarks(address pool_, int8 binIdx, uint104 newHwmToken0, uint104 newHwmToken1)
    external
    onlyPoolAdmin(pool_)
  {
    _requireInitialized(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    pendingHighWatermark[pool_] =
      PendingHighWatermarks({token0: newHwmToken0, token1: newHwmToken1, binIdx: binIdx, executeAfter: executeAfter});
    emit OracleStopLossHighWatermarkProposed(pool_, binIdx, newHwmToken0, newHwmToken1, executeAfter);
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L297-299)
```text
  function _afterTimelock(address pool_) private view returns (uint32) {
    return uint32(block.timestamp + oracleStopLossConfig[pool_].timelock);
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L301-303)
```text
  function _requireElapsed(uint32 executeAfter) private view {
    if (block.timestamp < executeAfter) revert OracleStopLossTimelockNotElapsed(executeAfter, block.timestamp);
  }
```

**File:** metric-periphery/contracts/interfaces/extensions/IOracleValueStopLossExtension.sol (L13-27)
```text
  struct PoolStopLossConfig {
    uint32 drawdownE6;
    uint32 decayPerSecondE8;
    uint32 timelock;
    bool initialized;
  }

  struct PoolStopLossSchedule {
    uint32 pendingTimelock;
    uint32 pendingTimelockExecuteAfter;
    uint32 pendingDrawdownE6;
    uint32 pendingDrawdownExecuteAfter;
    uint32 pendingDecayPerSecondE8;
    uint32 pendingDecayExecuteAfter;
  }
```
