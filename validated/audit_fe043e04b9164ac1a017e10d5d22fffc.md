### Title
Pool Admin Can Reduce `OracleValueStopLossExtension` Timelock to Zero, Enabling Instant Drawdown/Decay Bypass — (`metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol`)

### Summary

`OracleValueStopLossExtension` enforces no minimum on the `timelock` parameter. When `timelock == 0`, `_afterTimelock` returns `block.timestamp`, and `_requireElapsed` passes immediately (`block.timestamp < block.timestamp` is false). A pool admin can reduce the timelock to zero in one timelocked step, then propose and execute any drawdown or decay change in the same block, completely defeating the LP-protection invariant the extension was designed to enforce.

### Finding Description

The extension's stated invariant is:

> "Drawdown and decay changes are timelocked so LPs can react."

The `_afterTimelock` helper computes the execution deadline:

```solidity
function _afterTimelock(address pool_) private view returns (uint32) {
    return uint32(block.timestamp + oracleStopLossConfig[pool_].timelock);
}
``` [1](#0-0) 

And `_requireElapsed` enforces the delay:

```solidity
function _requireElapsed(uint32 executeAfter) private view {
    if (block.timestamp < executeAfter) revert OracleStopLossTimelockNotElapsed(executeAfter, block.timestamp);
}
``` [2](#0-1) 

When `timelock == 0`, `executeAfter == block.timestamp`. The condition `block.timestamp < block.timestamp` is always false, so `_requireElapsed` never reverts. Propose and execute can be called in the same block.

Neither `initialize` nor `proposeOracleStopLossTimelock` validates a minimum timelock value. `initialize` only validates `drawdownE6` and `decayPerSecondE8`:

```solidity
(uint32 drawdownE6, uint32 decayPerSecondE8, uint32 timelock) = abi.decode(data, (uint32, uint32, uint32));
_validateDrawdown(drawdownE6);
_validateDecay(decayPerSecondE8);
// timelock is stored without any minimum check
``` [3](#0-2) 

`proposeOracleStopLossTimelock` similarly accepts any `uint32` value including zero:

```solidity
function proposeOracleStopLossTimelock(address pool_, uint32 newTimelock) external onlyPoolAdmin(pool_) {
    PoolStopLossSchedule storage sched = _initializedSchedule(pool_);
    uint32 executeAfter = _afterTimelock(pool_);
    sched.pendingTimelock = newTimelock;
    sched.pendingTimelockExecuteAfter = executeAfter;
``` [4](#0-3) 

The `PoolStopLossConfig` struct stores `timelock` as a plain `uint32` with no floor: [5](#0-4) 

The existing test `test_decayTimelockZeroExecutesImmediately` explicitly confirms that when `timelock == 0`, propose and execute succeed in the same block: [6](#0-5) 

### Impact Explanation

Once the timelock is zero, the pool admin can:

1. Call `proposeOracleStopLossDrawdown(pool, 1_000_000)` (drawdown = 100% = `E6`) — stop-loss floor becomes 0, the guard never triggers.
2. Call `executeOracleStopLossDrawdown(pool)` in the same transaction — applied immediately.

Or equivalently raise `decayPerSecondE8` to `E8` (100%/second), collapsing all watermarks to zero on the next swap, permanently disabling the stop-loss.

LPs who deposited trusting the stop-loss extension to cap their downside have no reaction window. The extension's `afterSwap` hook will no longer revert on value loss, allowing the pool to drain LP principal through adverse swaps without triggering the guard. [7](#0-6) 

### Likelihood Explanation

The attack requires the pool admin to first reduce the timelock to zero. That step itself is gated by the current timelock (e.g., 7 days). However:

- A pool can be **initialized with `timelock = 0`** from day one — no waiting required.
- After the initial timelock elapses, the admin can reduce it to zero in one step, then act instantly on all future parameter changes.
- The pool admin is explicitly described as "semi-trusted only inside caps and timelocks." The timelock is the cap; bypassing it is an admin-boundary break. [8](#0-7) 

### Recommendation

Enforce a minimum timelock in both `initialize` and `proposeOracleStopLossTimelock`. A reasonable floor (e.g., 1 day) ensures LPs always have a reaction window:

```solidity
uint32 private constant MIN_TIMELOCK = 1 days;

// in initialize:
if (timelock < MIN_TIMELOCK) revert OracleStopLossTimelockTooShort(timelock);

// in proposeOracleStopLossTimelock:
if (newTimelock < MIN_TIMELOCK) revert OracleStopLossTimelockTooShort(newTimelock);
```

### Proof of Concept

```solidity
// Pool initialized with timelock = 0 (no minimum enforced)
vm.prank(address(factory));
extension.initialize(pool, abi.encode(uint32(50_000), uint32(0), uint32(0)));
// drawdown = 5%, decay = 0, timelock = 0

// Admin disables stop-loss in a single block — no LP reaction window
vm.startPrank(admin);
extension.proposeOracleStopLossDrawdown(pool, 1_000_000); // 100% drawdown = no floor
extension.executeOracleStopLossDrawdown(pool);            // executes immediately
vm.stopPrank();

// Confirm drawdown is now 100% — stop-loss permanently disabled
(uint32 dd,,,) = extension.oracleStopLossConfig(pool);
assertEq(dd, 1_000_000); // guard never triggers
``` [9](#0-8) [10](#0-9)

### Citations

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L46-68)
```text
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

**File:** metric-periphery/test/extensions/OracleValueStopLossSubExtension.t.sol (L249-255)
```text
  function test_decayTimelockZeroExecutesImmediately() public {
    vm.startPrank(admin);
    extension.proposeOracleStopLossDecay(address(mockPool), 58);
    extension.executeOracleStopLossDecay(address(mockPool));
    vm.stopPrank();
    assertEq(_decay(), 58);
  }
```

**File:** metric-core/docs/POOL_CONFIGURATION_AND_MANAGEMENT.md (L122-128)
```markdown
| Role           | On-chain identity                                 | Primary contract                                  |
| -------------- | ------------------------------------------------- | ------------------------------------------------- |
| **Protocol**   | `MetricOmmPoolFactory` **owner** (`Ownable2Step`) | Factory                                           |
| **Pool admin** | **`poolAdmin[pool]`**                             | Factory-gated entrypoints that call into the pool |

The **pool contract** only accepts privileged calls from **`FACTORY`** (`onlyFactory`); admins and protocol act **through the factory** for fee collection, pausing, oracle updates, and per-bin fee tweaks.

```
