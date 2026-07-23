### Title
Unbounded `newTimelock` in `proposeOracleStopLossTimelock` allows pool admin to permanently freeze stop-loss recovery, breaking swap functionality — (`metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol`)

---

### Summary

`OracleValueStopLossExtension.proposeOracleStopLossTimelock` accepts any `uint32 newTimelock` value with no upper-bound validation. Once a large timelock is executed, every subsequent parameter-change proposal (drawdown, decay, watermarks) inherits that delay via `_afterTimelock`. If the stop-loss triggers before those parameters can be updated, all swaps in the affected direction revert permanently.

---

### Finding Description

`proposeOracleStopLossTimelock` stores `newTimelock` directly without any cap:

```solidity
// OracleValueStopLossExtension.sol:78-84
function proposeOracleStopLossTimelock(address pool_, uint32 newTimelock) external onlyPoolAdmin(pool_) {
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);   // uses CURRENT timelock
    sched.pendingTimelock = newTimelock;            // no validation on newTimelock
    sched.pendingTimelockExecuteAfter = executeAfter;
    emit OracleStopLossTimelockProposed(pool_, newTimelock, executeAfter);
}
``` [1](#0-0) 

After `executeOracleStopLossTimelock` applies the change, `oracleStopLossConfig[pool_].timelock` is set to the new value. Every future proposal then calls `_afterTimelock`:

```solidity
// OracleValueStopLossExtension.sol:297-299
function _afterTimelock(address pool_) private view returns (uint32) {
    return uint32(block.timestamp + oracleStopLossConfig[pool_].timelock);
}
``` [2](#0-1) 

If `newTimelock` is set to, for example, `315_360_000` (10 years in seconds — well within `uint32` range, no overflow), then `executeAfter` for every subsequent drawdown, decay, or watermark proposal is 10 years in the future. `_requireElapsed` enforces this strictly:

```solidity
// OracleValueStopLossExtension.sol:301-303
function _requireElapsed(uint32 executeAfter) private view {
    if (block.timestamp < executeAfter) revert OracleStopLossTimelockNotElapsed(executeAfter, block.timestamp);
}
``` [3](#0-2) 

By contrast, `drawdownE6` and `decayPerSecondE8` are both validated against hard ceilings (`E6` and `E8` respectively), but `timelock` receives no analogous check at either `initialize` or `proposeOracleStopLossTimelock`:

```solidity
// OracleValueStopLossExtension.sol:56-62
(uint32 drawdownE6, uint32 decayPerSecondE8, uint32 timelock) = abi.decode(data, (uint32, uint32, uint32));
_validateDrawdown(drawdownE6);   // validated
_validateDecay(decayPerSecondE8); // validated
// timelock: no validation
``` [4](#0-3) 

When the stop-loss triggers, `afterSwap` reverts with `OracleStopLossTriggered`:

```solidity
// OracleValueStopLossExtension.sol:271-273
if (breach0 && zeroForOne) {
    revert OracleStopLossTriggered(binIdx, true, metricT0, (hwm0 * floorMultiplier) / E6);
}
``` [5](#0-4) 

The only recovery path is updating the high watermarks via `proposeOracleStopLossHighWatermarks` + `executeOracleStopLossHighWatermarks`, both of which are gated behind the same frozen timelock.

---

### Impact Explanation

Once the oversized timelock is executed, the pool admin cannot update drawdown, decay, or watermarks for the duration of the timelock. If the stop-loss triggers during that window, every swap in the affected direction reverts permanently. LPs retain the ability to call `removeLiquidity` directly (the stop-loss only fires in `afterSwap`), but the pool's swap functionality — its core purpose — is completely unusable. This matches the allowed impact gate: **broken core pool functionality causing unusable swap flows**.

---

### Likelihood Explanation

The pool admin is semi-trusted and is expected to operate within reasonable bounds. The absence of any cap means a misconfiguration (e.g., entering seconds instead of days, or a fat-finger of `type(uint32).max`) permanently locks the recovery mechanism. The stop-loss extension is a production periphery extension designed to be attached to live pools, so the combination of a misconfigured timelock and a subsequent market drawdown is a realistic operational scenario.

---

### Recommendation

Add a maximum cap on `newTimelock` in `proposeOracleStopLossTimelock`, mirroring the pattern used for `drawdownE6` and `decayPerSecondE8`. A reasonable ceiling (e.g., 4 weeks, consistent with the fix applied to the analogous EmergencyProposer bug) prevents the timelock from being set to an operationally unreachable value:

```solidity
uint32 private constant MAX_TIMELOCK = 4 weeks;

function proposeOracleStopLossTimelock(address pool_, uint32 newTimelock) external onlyPoolAdmin(pool_) {
    if (newTimelock > MAX_TIMELOCK) revert OracleStopLossTimelockTooLarge(newTimelock);
    // ... rest unchanged
}
```

Apply the same cap inside `initialize` so the constraint holds from pool creation.

---

### Proof of Concept

```solidity
// 1. Pool is created with OracleValueStopLossExtension, timelock = 0, drawdownE6 = 50_000 (5%).
// 2. Pool admin calls:
extension.proposeOracleStopLossTimelock(pool, 315_360_000); // 10 years, fits uint32
// (current timelock = 0, so executeAfter = block.timestamp; executable immediately)
extension.executeOracleStopLossTimelock(pool);
// oracleStopLossConfig[pool].timelock is now 315_360_000

// 3. Market moves; afterSwap fires OracleStopLossTriggered — all zeroForOne swaps revert.

// 4. Admin tries to raise watermarks to recover:
extension.proposeOracleStopLossHighWatermarks(pool, 0, newHwm0, newHwm1);
// executeAfter = block.timestamp + 315_360_000 (10 years from now)
extension.executeOracleStopLossHighWatermarks(pool);
// REVERTS: OracleStopLossTimelockNotElapsed

// 5. Pool swaps remain permanently broken for 10 years.
//    removeLiquidity still works, but no swap can execute in the triggered direction.
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

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L271-278)
```text
    if (breach0 && zeroForOne) {
      revert OracleStopLossTriggered(binIdx, true, metricT0, (hwm0 * floorMultiplier) / E6);
    }

    (uint256 hwm1, bool breach1) = _applyWatermark(metricT1, _decayed(hwmS.token1, decayRate, dt), floorMultiplier);
    if (breach1 && !zeroForOne) {
      revert OracleStopLossTriggered(binIdx, false, metricT1, (hwm1 * floorMultiplier) / E6);
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
