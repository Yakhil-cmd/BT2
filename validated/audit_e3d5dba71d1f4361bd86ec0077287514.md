### Title
Pool Admin Can Reduce `OracleValueStopLossExtension` Timelock to Zero, Then Immediately Disable LP Stop-Loss Protection — (`File: metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol`)

---

### Summary

The `OracleValueStopLossExtension` uses a per-pool `timelock` to delay drawdown, decay, and watermark changes so LPs can react. However, there is no minimum value enforced on the timelock itself — neither at initialization nor when the pool admin proposes a new timelock value. A pool admin can reduce the timelock to `0`, after which all subsequent parameter changes (including setting `drawdownE6 = 0` to fully disable the stop-loss) can be proposed and executed atomically in the same block, with zero LP reaction window.

---

### Finding Description

`OracleValueStopLossExtension.initialize()` accepts a `uint32 timelock` from the caller-supplied `data` with no lower-bound validation: [1](#0-0) 

`proposeOracleStopLossTimelock()` computes `executeAfter` using the **current** timelock: [2](#0-1) 

`_afterTimelock()` returns `block.timestamp + currentTimelock`. When `currentTimelock == 0`, `executeAfter == block.timestamp`: [3](#0-2) 

`_requireElapsed()` checks `block.timestamp < executeAfter`. When `executeAfter == block.timestamp`, the condition is `false` and the call succeeds immediately: [4](#0-3) 

`executeOracleStopLossTimelock()` applies the pending timelock with no minimum validation on the new value: [5](#0-4) 

Once the timelock is 0, the same same-block atomicity applies to `proposeOracleStopLossDrawdown` + `executeOracleStopLossDrawdown`. Setting `drawdownE6 = 0` triggers the early-return guard in `_afterSwapOracleStopLoss`, fully disabling the stop-loss: [6](#0-5) 

The same zero-timelock path applies to `proposeOracleStopLossDecay` / `executeOracleStopLossDecay` and `proposeOracleStopLossHighWatermarks` / `executeOracleStopLossHighWatermarks`. [7](#0-6) 

---

### Impact Explanation

The NatDoc for `OracleValueStopLossExtension` states: *"Drawdown and decay changes are timelocked so LPs can react; monitor at least as often as the timelock or trust the pool admin."* The timelock is the sole LP protection boundary. Once the pool admin reduces it to 0:

1. The stop-loss can be disabled (`drawdownE6 = 0`) in the same block, with no LP reaction window.
2. With the stop-loss disabled, adversarial swaps that drain per-share value from LP bins are no longer blocked by `afterSwap`, causing direct LP principal loss.
3. Alternatively, the decay rate can be set to `1e8` (100%/second) in the same block, causing watermarks to floor at 0 within one second, making the stop-loss permanently ineffective without disabling it outright.

This is an **admin-boundary break**: the pool admin is semi-trusted only *inside* timelocks. Reducing the timelock to 0 collapses that boundary entirely.

---

### Likelihood Explanation

- The pool admin is a named, semi-trusted role — not an arbitrary attacker.
- The attack requires waiting the **current** timelock before reducing it to 0 (e.g., 3 days). LPs have that window to observe the `OracleStopLossTimelockProposed` event and exit.
- However, many LPs do not monitor extension-level events. The NatDoc's "monitor at least as often as the timelock" is an operational assumption that is routinely violated in practice.
- After the timelock reaches 0, the disable step is atomic and unobservable in advance — no second proposal event is emitted before the drawdown is zeroed.

---

### Recommendation

1. **Enforce a minimum timelock** in both `initialize()` and `executeOracleStopLossTimelock()`. A reasonable floor (e.g., `1 days`) prevents the timelock from being reduced to a value that gives LPs no reaction window.
2. **Validate the new timelock is ≥ the current timelock** (or at least ≥ a protocol-defined minimum) when executing a timelock reduction, analogous to how the external bug was fixed by separating the two-step unstake into distinct instructions.
3. Alternatively, store the timelock as an immutable set at initialization (like `priceProviderTimelock` on the factory for immutable-oracle pools), preventing any post-deployment reduction.

---

### Proof of Concept

```
1. Pool created with OracleValueStopLossExtension, drawdownE6=50_000, timelock=3 days.
2. LPs add liquidity trusting the 3-day reaction window.
3. Admin calls proposeOracleStopLossTimelock(pool, 0).
   → executeAfter = block.timestamp + 3 days  (current timelock enforced here)
4. Admin waits 3 days. LPs may not notice the OracleStopLossTimelockProposed event.
5. Admin calls executeOracleStopLossTimelock(pool).
   → oracleStopLossConfig[pool].timelock = 0
6. In the same block (or next block):
   Admin calls proposeOracleStopLossDrawdown(pool, 0).
   → executeAfter = block.timestamp + 0 = block.timestamp
   Admin calls executeOracleStopLossDrawdown(pool).
   → _requireElapsed(block.timestamp): block.timestamp < block.timestamp == false → passes
   → oracleStopLossConfig[pool].drawdownE6 = 0
7. _afterSwapOracleStopLoss now returns immediately (drawdown == 0 guard).
8. Adversarial swaps drain LP bins with no stop-loss blocking them.
```

### Citations

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L56-62)
```text
    (uint32 drawdownE6, uint32 decayPerSecondE8, uint32 timelock) = abi.decode(data, (uint32, uint32, uint32));
    _validateDrawdown(drawdownE6);
    _validateDecay(decayPerSecondE8);

    oracleStopLossConfig[pool] = PoolStopLossConfig({
      drawdownE6: drawdownE6, decayPerSecondE8: decayPerSecondE8, timelock: timelock, initialized: true
    });
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

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L86-94)
```text
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

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L130-147)
```text
  function proposeOracleStopLossDecay(address pool_, uint256 newDecayPerSecondE8) external onlyPoolAdmin(pool_) {
    _validateDecay(newDecayPerSecondE8);
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    sched.pendingDecayPerSecondE8 = uint32(newDecayPerSecondE8);
    sched.pendingDecayExecuteAfter = executeAfter;
    emit OracleStopLossDecayProposed(pool_, newDecayPerSecondE8, executeAfter);
  }

  function executeOracleStopLossDecay(address pool_) external onlyPoolAdmin(pool_) {
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    if (sched.pendingDecayExecuteAfter == 0) revert OracleStopLossNoPendingDecay(pool_);
    _requireElapsed(sched.pendingDecayExecuteAfter);
    uint32 decay = sched.pendingDecayPerSecondE8;
    oracleStopLossConfig[pool_].decayPerSecondE8 = decay;
    (sched.pendingDecayPerSecondE8, sched.pendingDecayExecuteAfter) = (0, 0);
    emit OracleStopLossDecaySet(pool_, decay);
  }
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L215-217)
```text
    PoolStopLossConfig memory cfg = oracleStopLossConfig[pool_];
    uint256 drawdown = cfg.drawdownE6;
    if (drawdown == 0) return;
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
