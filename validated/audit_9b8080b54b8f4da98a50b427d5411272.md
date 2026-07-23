### Title
`OracleValueStopLossExtension` Watermark Decay Accrues During Pool Pause, Allowing Pool Admin to Bypass Stop-Loss Timelock — (`metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol`)

---

### Summary

`BinHighWatermarks.lastDecayTs` is only updated inside `_checkAndUpdateWatermarks`, which is called exclusively from `afterSwap`. When the pool is paused, swaps are blocked and `afterSwap` never fires, so `lastDecayTs` is never refreshed. On unpause, the first swap computes `dt = block.timestamp - lastDecayTs` spanning the entire pause window, causing the watermark to decay as if trading continued uninterrupted. With a sufficiently long pause (or a high decay rate), the watermark collapses to zero, silently resetting the stop-loss protection that LPs explicitly configured and that the timelock mechanism was designed to guard.

---

### Finding Description

`_checkAndUpdateWatermarks` computes elapsed time as:

```solidity
uint256 dt = block.timestamp - hwmS.lastDecayTs;
```

and then applies linear decay:

```solidity
uint256 factor = ratePerSecondE8 * dt;
if (factor >= E8) return 0;
return hwm - (hwm * factor) / E8;
``` [1](#0-0) 

`lastDecayTs` is written only at the end of `_checkAndUpdateWatermarks`:

```solidity
hwmS.lastDecayTs = uint32(block.timestamp);
``` [2](#0-1) 

`_checkAndUpdateWatermarks` is only reachable through `afterSwap`, which is only called by the pool during a swap. Swaps are blocked when `pauseLevel >= 1`: [3](#0-2) 

The pool admin can pause (level 1) and the protocol owner can pause (level 2): [4](#0-3) 

During the pause window, `lastDecayTs` is frozen at the timestamp of the last pre-pause swap. When the pool is unpaused and the first swap arrives, `dt` equals the full pause duration. With `decayPerSecondE8` at its maximum allowed value of `E8 = 1e8`, a single second of pause is enough to satisfy `factor = 1e8 * 1 = E8 >= E8`, returning 0 and wiping the watermark entirely. [5](#0-4) 

The stop-loss extension deliberately timelocks watermark resets via `proposeOracleStopLossHighWatermarks` / `executeOracleStopLossHighWatermarks` so LPs have time to react before their protection is changed: [6](#0-5) 

The pause path bypasses this timelock entirely: the pool admin pauses, waits for decay to zero, then unpauses. The watermark resets on the first post-unpause swap with no proposal, no timelock, and no LP notification.

---

### Impact Explanation

LPs who deploy a pool with `OracleValueStopLossExtension` rely on the drawdown threshold to block swaps that would drain bin value below their configured floor. The timelock on watermark changes is the mechanism that gives LPs time to exit before that floor is lowered. By pausing the pool long enough for the watermark to decay to zero, the pool admin resets the effective floor to the current (potentially depressed) metric value without going through the timelocked proposal flow. Subsequent swaps at an unfavorable oracle price are no longer blocked by the stop-loss, and LP principal is drained without the protection triggering. This is a direct bypass of the admin-boundary timelock that the extension was designed to enforce.

---

### Likelihood Explanation

The pool admin is a semi-trusted role that already holds the `pausePool` capability. No external oracle manipulation is required — natural market price movement during a pause period is sufficient to cause LP value loss once the watermark has been reset. The time required to decay the watermark to zero depends on `decayPerSecondE8`; at the maximum rate (`1e8`), a single second suffices. At a realistic rate (e.g., 58 E8/s ≈ 5%/day), approximately 20 days of pause resets the watermark. The pool admin controls both the pause and the decay rate (via the timelocked decay proposal), so they can configure conditions that make the attack fast.

---

### Recommendation

Snapshot and freeze the decay clock on pause entry, and resume it on unpause. The simplest approach is to record a `pauseStartTs` when `setPause` transitions to a non-zero level, and on unpause add `(block.timestamp - pauseStartTs)` to `lastDecayTs` for every affected bin — or, equivalently, store a per-pool cumulative "paused seconds" offset and subtract it from `dt` in `_checkAndUpdateWatermarks` and `currentHighWatermarks`. This mirrors the fix applied in the referenced Cozy PR 133: update the inactive-period tracking variable at every state transition so that elapsed-time calculations remain correct across pause/unpause cycles.

---

### Proof of Concept

1. Pool is created with `OracleValueStopLossExtension`, `drawdownE6 = 50_000` (5%), `decayPerSecondE8 = 58` (~5%/day), `timelock = 3 days`.
2. LP deposits into bin 0. A swap occurs, setting `lastDecayTs = T0` and `hwm.token0 = V`.
3. Pool admin calls `factory.pausePool(pool)` at time `T0`.
4. 20 days pass (`dt = 1_728_000 s`). `factor = 58 * 1_728_000 = 100_224_000 > E8`, so `_decayed` returns 0.
5. Pool admin calls `factory.unpausePool(pool)`.
6. Oracle price has dropped 30% during the pause (natural market movement).
7. A swap arrives. `_checkAndUpdateWatermarks` computes `dt = 1_728_000`, decays `hwm.token0` to 0, then calls `_applyWatermark(currentMetric, 0, floorMultiplier)`. Since `currentMetric >= 0`, the watermark ratchets up to `currentMetric` (the depressed value) and `breached = false`.
8. The stop-loss does not trigger. The swap executes at the 30%-lower oracle price, draining LP value. The timelocked watermark-reset mechanism was bypassed entirely — no proposal, no 3-day wait, no LP notification. [7](#0-6) [5](#0-4) [8](#0-7)

### Citations

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L156-177)
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

  /// @notice Apply the pending watermarks. Also resets the decay clock for the bin.
  function executeOracleStopLossHighWatermarks(address pool_) external onlyPoolAdmin(pool_) {
    PendingHighWatermarks memory pending = pendingHighWatermark[pool_];
    if (pending.executeAfter == 0) revert OracleStopLossNoPendingHighWatermark(pool_);
    _requireElapsed(pending.executeAfter);
    highWatermarks[pool_][pending.binIdx] =
      BinHighWatermarks({token0: pending.token0, token1: pending.token1, lastDecayTs: uint32(block.timestamp)});
    delete pendingHighWatermark[pool_];
    emit OracleStopLossHighWatermarkUpdated(pool_, pending.binIdx, pending.token0, pending.token1);
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L258-285)
```text
  function _checkAndUpdateWatermarks(
    address pool_,
    int8 binIdx,
    uint256 metricT0,
    uint256 metricT1,
    uint256 floorMultiplier,
    uint256 decayRate,
    bool zeroForOne
  ) private {
    BinHighWatermarks storage hwmS = highWatermarks[pool_][binIdx];
    uint256 dt = block.timestamp - hwmS.lastDecayTs;

    (uint256 hwm0, bool breach0) = _applyWatermark(metricT0, _decayed(hwmS.token0, decayRate, dt), floorMultiplier);
    if (breach0 && zeroForOne) {
      revert OracleStopLossTriggered(binIdx, true, metricT0, (hwm0 * floorMultiplier) / E6);
    }

    (uint256 hwm1, bool breach1) = _applyWatermark(metricT1, _decayed(hwmS.token1, decayRate, dt), floorMultiplier);
    if (breach1 && !zeroForOne) {
      revert OracleStopLossTriggered(binIdx, false, metricT1, (hwm1 * floorMultiplier) / E6);
    }

    // forge-lint: disable-next-line(unsafe-typecast)
    hwmS.token0 = uint104(hwm0);
    // forge-lint: disable-next-line(unsafe-typecast)
    hwmS.token1 = uint104(hwm1);
    hwmS.lastDecayTs = uint32(block.timestamp);
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L319-324)
```text
  function _decayed(uint256 hwm, uint256 ratePerSecondE8, uint256 dt) private pure returns (uint256) {
    if (ratePerSecondE8 == 0 || dt == 0 || hwm == 0) return hwm;
    uint256 factor = ratePerSecondE8 * dt;
    if (factor >= E8) return 0;
    return hwm - (hwm * factor) / E8;
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L326-336)
```text
  /// @dev Ratchet up on new highs; report breach below the drawdown floor. Direction-aware
  ///      blocking is decided by the caller.
  function _applyWatermark(uint256 metric, uint256 hwm, uint256 floorMultiplier)
    private
    pure
    returns (uint256 newHwm, bool breached)
  {
    if (metric >= hwm) return (metric, false);
    breached = metric < (hwm * floorMultiplier) / E6;
    return (hwm, breached);
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L455-461)
```text
  function setPause(uint8 newLevel) external onlyFactory {
    if (newLevel > 2) revert InvalidPauseLevel();
    if (newLevel == pauseLevel) return;
    uint8 prev = pauseLevel;
    pauseLevel = newLevel;
    emit PauseLevelUpdated(prev, newLevel);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L460-471)
```text
  function pausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);
  }

  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
  function unpausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 1) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0);
  }
```
