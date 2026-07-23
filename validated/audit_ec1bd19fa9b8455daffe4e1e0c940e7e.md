### Title
`uint32` Overflow in `_afterTimelock` Bypasses LP-Protection Timelock — (`metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol`)

---

### Summary

`OracleValueStopLossExtension._afterTimelock()` casts `block.timestamp + timelock` to `uint32` without overflow protection. A pool admin can set `timelock = type(uint32).max`, causing the sum to wrap to a past timestamp, which makes every subsequent `_requireElapsed` check pass immediately. This nullifies the LP-protection timelock on all timelocked parameter changes (drawdown, decay rate, high watermarks).

---

### Finding Description

`_afterTimelock` computes the deadline for every pending admin change:

```solidity
function _afterTimelock(address pool_) private view returns (uint32) {
    return uint32(block.timestamp + oracleStopLossConfig[pool_].timelock);
}
``` [1](#0-0) 

`timelock` is stored as `uint32` (max ≈ 4.295 × 10⁹ seconds ≈ 136 years). With `block.timestamp` currently ≈ 1.753 × 10⁹ (July 2026), any `timelock ≥ 2^32 − block.timestamp ≈ 2.542 × 10⁹` (≈ 80.6 years) causes the addition to exceed `2^32`, wrapping the result to approximately `block.timestamp − 1` — a timestamp already in the past.

`_requireElapsed` then trivially passes:

```solidity
function _requireElapsed(uint32 executeAfter) private view {
    if (block.timestamp < executeAfter) revert OracleStopLossTimelockNotElapsed(...);
}
``` [2](#0-1) 

There is no cap on the `newTimelock` argument. `_validateDrawdown` and `_validateDecay` both enforce upper bounds, but no `_validateTimelock` equivalent exists: [3](#0-2) 

Every propose function — `proposeOracleStopLossDrawdown`, `proposeOracleStopLossDecay`, `proposeOracleStopLossHighWatermarks`, and `proposeOracleStopLossTimelock` itself — calls `_afterTimelock` to compute `executeAfter`: [4](#0-3) [5](#0-4) [6](#0-5) 

All pending-change structs store `executeAfter` as `uint32`: [7](#0-6) 

---

### Impact Explanation

`OracleValueStopLossExtension` is the sole on-chain mechanism protecting LPs from value extraction: it blocks swaps that push per-bin value below a drawdown floor. The timelock is explicitly the LP-reaction window — the NatSpec states *"monitor at least as often as the timelock or trust the pool admin"*. [8](#0-7) 

Once the timelock overflows, the admin can atomically:

1. Set `drawdownE6 = 1_000_000` (100% — disables stop-loss entirely).
2. Set `decayPerSecondE8 = 1e8` (maximum — watermarks decay to zero in one second).
3. Set arbitrary high watermarks to reset the stop-loss baseline.

With stop-loss disabled, the admin (or a colluding MEV actor) can drain LP bins via swaps that would otherwise be blocked, causing direct loss of LP principal. This is an admin-boundary break: the timelock is the cap on admin power, and it is bypassed without any privileged factory-owner action.

---

### Likelihood Explanation

The trigger is a single `proposeOracleStopLossTimelock(pool, type(uint32).max)` call by the pool admin, followed by `executeOracleStopLossTimelock` after the *current* timelock elapses (or immediately if the initial timelock is 0). After that, all subsequent proposals bypass the timelock in the same block. The pool admin role is semi-trusted and reachable by any address that was assigned admin at pool creation or accepted an admin transfer.

---

### Recommendation

1. Add a `_validateTimelock` function that caps `newTimelock` at a safe maximum (e.g., 365 days = 31,536,000 seconds, well below the overflow threshold of ~2.54 × 10⁹):

```solidity
uint32 private constant MAX_TIMELOCK = 365 days; // 31_536_000 — safe from uint32 overflow

function _validateTimelock(uint256 timelock) private pure {
    if (timelock > MAX_TIMELOCK) revert OracleStopLossTimelockTooLarge(timelock);
}
```

2. Call `_validateTimelock` in both `initialize` and `proposeOracleStopLossTimelock`.

3. Alternatively, widen `executeAfter` storage fields to `uint64` and perform the addition in `uint256` before downcasting, with an explicit overflow check.

---

### Proof of Concept

```solidity
// Assume pool was created with timelock = 0 (or admin waits for current timelock to elapse)

// Step 1: Set timelock to type(uint32).max
vm.prank(admin);
extension.proposeOracleStopLossTimelock(pool, type(uint32).max);
// executeAfter = uint32(block.timestamp + 0) = block.timestamp → already elapsed
vm.prank(admin);
extension.executeOracleStopLossTimelock(pool);
// oracleStopLossConfig[pool].timelock == type(uint32).max

// Step 2: Propose 100% drawdown (disables stop-loss)
vm.prank(admin);
extension.proposeOracleStopLossDrawdown(pool, 1_000_000);
// _afterTimelock: uint32(1_753_000_000 + 4_294_967_295) = uint32(6_047_967_295)
//              = 6_047_967_295 mod 4_294_967_296 = 1_752_999_999  ← past timestamp

// Step 3: Execute immediately — no waiting
vm.prank(admin);
extension.executeOracleStopLossDrawdown(pool);
// drawdownE6 == 1_000_000 → stop-loss disabled; LPs unprotected
```

### Citations

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L13-28)
```text
/// @title OracleValueStopLossExtension
/// @notice Tracks per-bin value per share in token0 and token1 terms at the oracle mid,
///         against decaying high watermarks. Drawdown and decay changes are timelocked so LPs
///         can react; monitor at least as often as the timelock or trust the pool admin.
/// @dev Value formulas (Q64.64 mid = token1 per token0), per-share in bin scaled units:
///
///      metricToken0 = t0*SCALE/shares + (t1 * 2^64 / mid) * SCALE / shares
///      metricToken1 = (t0 * mid / 2^64) * SCALE / shares + t1*SCALE/shares
///
///      A pure mid move pushes the metrics in opposite directions; a value leak pushes both down.
///        - metricToken0 breach (mid suspect-high) blocks zeroForOne == true  (token1 outflow)
///        - metricToken1 breach (mid suspect-low)  blocks zeroForOne == false (token0 outflow)
///        - both breached blocks both directions
///
///      Watermarks decay linearly at decayPerSecondE8 (lazy, per bin). Guarantee: value per
///      share at oracle marks cannot fall faster than drawdown (one-time) + decay * t (ongoing).
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

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L157-166)
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

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L305-311)
```text
  function _validateDrawdown(uint256 drawdownE6) private pure {
    if (drawdownE6 > E6) revert OracleStopLossDrawdownTooLarge(drawdownE6);
  }

  function _validateDecay(uint256 decayPerSecondE8) private pure {
    if (decayPerSecondE8 > E8) revert OracleStopLossDecayTooLarge(decayPerSecondE8);
  }
```

**File:** metric-periphery/contracts/interfaces/extensions/IOracleValueStopLossExtension.sol (L20-34)
```text
  struct PoolStopLossSchedule {
    uint32 pendingTimelock;
    uint32 pendingTimelockExecuteAfter;
    uint32 pendingDrawdownE6;
    uint32 pendingDrawdownExecuteAfter;
    uint32 pendingDecayPerSecondE8;
    uint32 pendingDecayExecuteAfter;
  }

  struct PendingHighWatermarks {
    uint104 token0;
    uint104 token1;
    int8 binIdx;
    uint32 executeAfter;
  }
```
