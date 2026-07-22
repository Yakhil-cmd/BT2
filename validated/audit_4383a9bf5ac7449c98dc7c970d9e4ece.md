### Title
`uint32` Overflow in `_afterTimelock` Allows Pool Admin to Bypass LP-Protection Timelock Immediately — (`metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol`)

---

### Summary

`_afterTimelock` casts `block.timestamp + timelock` to `uint32`. When `timelock` is set to `type(uint32).max`, the addition overflows the `uint32` range and produces an `executeAfter` value that is one second in the past. Every subsequent `execute*` call passes `_requireElapsed` immediately, silently nullifying the LP-protection timelock for all parameter changes (drawdown, decay, high watermarks).

---

### Finding Description

`_afterTimelock` computes the execution deadline as:

```solidity
function _afterTimelock(address pool_) private view returns (uint32) {
    return uint32(block.timestamp + oracleStopLossConfig[pool_].timelock);
}
```

`block.timestamp` is `uint256`; `timelock` is `uint32`. The addition is performed in `uint256` and then **silently truncated** to `uint32`. When `timelock = type(uint32).max` (4,294,967,295):

```
block.timestamp (≈ 1,753,000,000)  +  4,294,967,295
= 6,047,967,295
uint32(6,047,967,295) = 6,047,967,295 mod 4,294,967,296 = 1,752,999,999
```

The result is `block.timestamp − 1`. The guard:

```solidity
function _requireElapsed(uint32 executeAfter) private view {
    if (block.timestamp < executeAfter) revert ...;
}
```

evaluates `block.timestamp < block.timestamp − 1`, which is `false`, so it never reverts. Every `execute*` call succeeds in the same transaction as the matching `propose*` call.

**Attack path (no malicious initial setup required):**

1. Pool is legitimately initialized with `timelock = 0`.
2. Admin calls `proposeOracleStopLossTimelock(pool, type(uint32).max)` → `executeAfter = uint32(block.timestamp + 0) = block.timestamp` → immediately executable.
3. Admin calls `executeOracleStopLossTimelock(pool)` → `oracleStopLossConfig[pool].timelock = type(uint32).max`.
4. Admin calls `proposeOracleStopLossDrawdown(pool, 0)` → `executeAfter = block.timestamp − 1`.
5. Admin calls `executeOracleStopLossDrawdown(pool)` in the same block → succeeds; drawdown is now `0`.

Steps 4–5 can be repeated for decay and high watermarks in the same transaction. No waiting period is enforced.

The `initialize` function also accepts `uint32 timelock` with no upper-bound validation, so a pool can be deployed with `timelock = type(uint32).max` from day one, making every timelocked operation immediately executable without any admin escalation step.

---

### Impact Explanation

The `OracleValueStopLossExtension` timelock is the sole mechanism giving LPs advance notice before the pool admin changes stop-loss parameters. With the timelock bypassed:

- **Drawdown set to 0** disables the stop-loss entirely (`if (drawdown == 0) return;` in `_afterSwapOracleStopLoss`), removing LP protection against value extraction.
- **Decay set to `type(uint32).max`** causes watermarks to decay to zero instantly on the next swap, making the stop-loss permanently inactive.
- **High watermarks raised arbitrarily** can trigger the stop-loss on the next swap, blocking all swaps and freezing LP liquidity.

LPs who monitor the timelock queue to decide whether to exit cannot react because the change is applied in the same block it is proposed. This breaks the core LP-protection invariant of the extension and can result in direct loss of LP principal.

---

### Likelihood Explanation

The pool admin is semi-trusted (not fully trusted). The timelock exists precisely because the admin is not assumed to be fully benign. The attack requires only two admin transactions (steps 2–3 to set the timelock, then steps 4–5 to exploit it) and no external conditions. Any pool using `OracleValueStopLossExtension` with an initial `timelock = 0` is immediately vulnerable to this escalation. Pools initialized with `timelock = type(uint32).max` are vulnerable from deployment.

---

### Recommendation

Add an upper-bound check on `timelock` in both `initialize` and `executeOracleStopLossTimelock` to prevent values that would cause `uint32` overflow:

```solidity
uint32 constant MAX_TIMELOCK = 365 days; // or another safe ceiling

function _validateTimelock(uint32 timelock) private pure {
    if (timelock > MAX_TIMELOCK) revert OracleStopLossTimelockTooLarge(timelock);
}
```

Apply `_validateTimelock` in `initialize` (alongside `_validateDrawdown` / `_validateDecay`) and in `executeOracleStopLossTimelock` before writing the new value. Alternatively, compute `executeAfter` in `uint256` and revert if it exceeds `type(uint32).max`.

---

### Proof of Concept

```solidity
// Pool initialized with timelock = 0
extension.initialize(pool, abi.encode(uint32(50_000), uint32(58), uint32(0)));

vm.startPrank(admin);

// Step 1: escalate timelock to type(uint32).max (immediately executable since current timelock = 0)
extension.proposeOracleStopLossTimelock(pool, type(uint32).max);
extension.executeOracleStopLossTimelock(pool);

// Verify timelock is now type(uint32).max
(,, uint32 tl,) = extension.oracleStopLossConfig(pool);
assertEq(tl, type(uint32).max);

// Step 2: propose and immediately execute drawdown = 0 (bypasses timelock via uint32 overflow)
extension.proposeOracleStopLossDrawdown(pool, 0);
// executeAfter = uint32(block.timestamp + type(uint32).max) = block.timestamp - 1 (overflow)
extension.executeOracleStopLossDrawdown(pool); // succeeds in same block

// Stop-loss is now disabled
(uint32 dd,,,) = extension.oracleStopLossConfig(pool);
assertEq(dd, 0, "drawdown bypassed without waiting");

vm.stopPrank();
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** metric-periphery/contracts/interfaces/extensions/IOracleValueStopLossExtension.sol (L13-18)
```text
  struct PoolStopLossConfig {
    uint32 drawdownE6;
    uint32 decayPerSecondE8;
    uint32 timelock;
    bool initialized;
  }
```
