### Title
`uint32` Overflow in `_afterTimelock` Silently Bypasses Stop-Loss Timelock — (`File: metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol`)

---

### Summary

`OracleValueStopLossExtension._afterTimelock` casts `block.timestamp + timelock` directly to `uint32` with no overflow guard and no cap on the `timelock` value. When the sum exceeds `type(uint32).max`, the result silently wraps to a past timestamp, making `_requireElapsed` pass immediately and allowing the pool admin to execute any timelocked stop-loss parameter change (drawdown, decay, watermarks, timelock itself) without waiting.

---

### Finding Description

`_afterTimelock` is the single function that computes the `executeAfter` deadline for every timelocked mutation in the extension:

```solidity
// OracleValueStopLossExtension.sol line 297-299
function _afterTimelock(address pool_) private view returns (uint32) {
    return uint32(block.timestamp + oracleStopLossConfig[pool_].timelock);
}
``` [1](#0-0) 

The stored `timelock` field is a `uint32` (max ≈ 4.29 × 10⁹ seconds ≈ 136 years). At current mainnet timestamps (~1.75 × 10⁹), any `timelock` value greater than `type(uint32).max − block.timestamp` (≈ 2.54 × 10⁹ s ≈ 80 years) causes the addition to overflow `uint32`, wrapping the result to a value **already in the past**.

`_requireElapsed` then trivially passes:

```solidity
// line 301-303
function _requireElapsed(uint32 executeAfter) private view {
    if (block.timestamp < executeAfter) revert OracleStopLossTimelockNotElapsed(...);
}
``` [2](#0-1) 

`_afterTimelock` is called by every propose function:

- `proposeOracleStopLossTimelock` (line 80)
- `proposeOracleStopLossDrawdown` (line 106)
- `proposeOracleStopLossDecay` (line 133)
- `proposeOracleStopLossHighWatermarks` (line 162) [3](#0-2) [4](#0-3) 

The `initialize` function validates `drawdownE6` and `decayPerSecondE8` but applies **no cap or validation on `timelock`**:

```solidity
// line 56-62
(uint32 drawdownE6, uint32 decayPerSecondE8, uint32 timelock) = abi.decode(data, (uint32, uint32, uint32));
_validateDrawdown(drawdownE6);
_validateDecay(decayPerSecondE8);
// ← no _validateTimelock
``` [5](#0-4) 

Likewise, `proposeOracleStopLossTimelock` accepts any `uint32 newTimelock` without bounds checking. [6](#0-5) 

**Concrete overflow example (July 2025, `block.timestamp` ≈ 1,750,000,000):**

| Variable | Value |
|---|---|
| `block.timestamp` | 1,750,000,000 |
| `timelock` | `type(uint32).max` = 4,294,967,295 |
| Sum (uint256) | 6,044,967,295 |
| `uint32(sum)` | 1,749,999,999 ← **1 second in the past** |
| `_requireElapsed` result | **passes immediately** |

---

### Impact Explanation

The stop-loss timelock is the only mechanism that gives LPs advance notice before the pool admin changes drawdown thresholds, decay rates, or high watermarks. With the timelock bypassed, the admin can:

1. Immediately set `drawdownE6 = 0`, disabling the stop-loss entirely, then drain value from the pool through a manipulated swap before LPs can react.
2. Immediately lower watermarks to trigger or suppress stop-loss blocks at will.
3. Immediately change the decay rate to accelerate watermark erosion.

This breaks the admin-boundary invariant: the pool admin is semi-trusted only within the timelock constraint. Bypassing the timelock allows the admin to make sudden, LP-adverse parameter changes that the timelock was designed to prevent.

---

### Likelihood Explanation

The pool admin controls the `timelock` value at initialization (passed as `abi.encode` data through the factory) and can also change it later via `proposeOracleStopLossTimelock` / `executeOracleStopLossTimelock`. A malicious or compromised admin can set `timelock = type(uint32).max` at any point. No factory-level cap exists on this value. The overflow threshold (~80 years at current timestamps) is reachable with a single `uint32` value and requires no special privileges beyond being the pool admin.

---

### Recommendation

Add a maximum timelock cap and validate it in both `initialize` and `proposeOracleStopLossTimelock`:

```solidity
uint32 private constant MAX_TIMELOCK = 365 days; // or another protocol-chosen bound

function _validateTimelock(uint256 timelock) private pure {
    if (timelock > MAX_TIMELOCK) revert OracleStopLossTimelockTooLarge(timelock);
}
```

Apply this in `initialize` alongside the existing `_validateDrawdown` / `_validateDecay` calls, and in `proposeOracleStopLossTimelock` before storing `newTimelock`. This ensures `block.timestamp + timelock` never overflows `uint32` and the `executeAfter` deadline is always in the future.

---

### Proof of Concept

Place in the existing `OracleValueStopLossSubExtension.t.sol` test suite:

```solidity
function test_timelockOverflowBypassesTimelock() public {
    // Deploy a fresh extension with timelock = type(uint32).max
    OracleValueStopLossExtension freshExtension =
        new OracleValueStopLossExtension(address(factoryStub));
    MockExtensionExtsloadPool freshPool =
        new MockExtensionExtsloadPool(address(factoryStub), MIN_SHARES);
    factoryStub.setPoolAdmin(address(freshPool), admin);

    // Initialize with max uint32 timelock — no revert, no cap
    vm.prank(address(factoryStub));
    freshExtension.initialize(
        address(freshPool),
        abi.encode(uint32(500_000), uint32(58), type(uint32).max)
    );

    // Propose a drawdown change — _afterTimelock overflows to a past timestamp
    vm.startPrank(admin);
    freshExtension.proposeOracleStopLossDrawdown(address(freshPool), 100_000);

    // Execute immediately — should revert if timelock worked, but it doesn't
    freshExtension.executeOracleStopLossDrawdown(address(freshPool));
    vm.stopPrank();

    // Drawdown changed without waiting any time
    (uint32 dd,,,) = freshExtension.oracleStopLossConfig(address(freshPool));
    assertEq(dd, 100_000, "drawdown changed instantly despite max timelock");
}
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

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L103-109)
```text
  function proposeOracleStopLossDrawdown(address pool_, uint256 newMaxDrawdownE6) external onlyPoolAdmin(pool_) {
    _validateDrawdown(newMaxDrawdownE6);
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    sched.pendingDrawdownE6 = uint32(newMaxDrawdownE6);
    sched.pendingDrawdownExecuteAfter = executeAfter;
    emit OracleStopLossDrawdownProposed(pool_, newMaxDrawdownE6, executeAfter);
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
