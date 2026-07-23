The code is clear. Let me trace the exact path:

The path is confirmed by the code. Here is the analysis:

---

### Title
Off-by-one in `_validateDecay` allows pool admin to set 100%/second decay, zeroing all watermarks in 1 second and resetting LP stop-loss baseline — (`metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol`)

---

### Summary

`_validateDecay` uses a strict `>` comparison, so `decayPerSecondE8 = 1e8` (exactly `E8`) passes validation. `_decayed` then floors any watermark to 0 after a single second, silently resetting the stop-loss protection baseline for all LP positions.

---

### Finding Description

**Step 1 — Validation off-by-one.**
`_validateDecay` rejects only values strictly greater than `E8`:

```solidity
if (decayPerSecondE8 > E8) revert OracleStopLossDecayTooLarge(decayPerSecondE8);
``` [1](#0-0) 

`E8 = 1e8` is the scale denominator representing 100 %/second. The check should be `>= E8`; as written, `1e8` is accepted.

**Step 2 — `_decayed` floors to 0 after 1 second.**

```solidity
uint256 factor = ratePerSecondE8 * dt;   // 1e8 * 1 = 1e8
if (factor >= E8) return 0;              // 1e8 >= 1e8 → true → returns 0
``` [2](#0-1) 

Any established `BinHighWatermarks.token0` / `token1` value is reduced to 0 after exactly one elapsed second.

**Step 3 — `_applyWatermark` silently ratchets up from 0.**

When `hwm = 0`, the condition `metric >= hwm` is always true, so `_applyWatermark` returns `(metric, false)` — no breach is reported and the new watermark is set to the current (potentially much lower) live metric:

```solidity
if (metric >= hwm) return (metric, false);
``` [3](#0-2) 

**Step 4 — Persisted state is corrupted.**

`_checkAndUpdateWatermarks` writes the new (reset) watermarks back to storage:

```solidity
hwmS.token0 = uint104(hwm0);
hwmS.token1 = uint104(hwm1);
hwmS.lastDecayTs = uint32(block.timestamp);
``` [4](#0-3) 

The previously established high watermarks — which encoded the LP value baseline at the time of last touch — are permanently overwritten with the current (lower) metric. All prior drawdown history is erased.

---

### Impact Explanation

The stop-loss extension is the primary on-chain mechanism protecting LPs from value extraction via manipulated swaps. Resetting watermarks to the current (depressed) metric means:

- Any value already lost by LPs is no longer tracked; the drawdown floor is recalculated from the new, lower baseline.
- A subsequent swap that would have triggered `OracleStopLossTriggered` (and reverted) now passes silently.
- LPs suffer the loss that the extension was designed to prevent, with no on-chain recourse.

This is a broken core protective functionality causing loss of LP principal above Sherlock thresholds, and an admin-boundary break where the pool admin exceeds the intended decay cap due to the off-by-one.

---

### Likelihood Explanation

- The pool admin role is semi-trusted and this action is gated by the pool's timelock. However, if the pool was initialized with `timelock = 0` (no validation prevents this), the admin can execute immediately.
- Even with a non-zero timelock, the admin can first reduce the timelock to 0 (propose → wait → execute), then set decay to `1e8` with zero delay.
- The `_validateDecay` off-by-one is a single-character fix (`>` → `>=`), confirming it is an unintentional boundary error rather than a deliberate design choice.

---

### Recommendation

Change the strict inequality to `>=` in `_validateDecay`:

```solidity
// Before
if (decayPerSecondE8 > E8) revert OracleStopLossDecayTooLarge(decayPerSecondE8);

// After
if (decayPerSecondE8 >= E8) revert OracleStopLossDecayTooLarge(decayPerSecondE8);
``` [1](#0-0) 

This ensures 100 %/second (instant full decay) is never a valid configuration, consistent with the intent expressed in the NatSpec ("58 ~= 5%/day").

---

### Proof of Concept

```solidity
// Foundry unit test sketch
function test_decayE8_resetsWatermarks() public {
    // 1. Initialize pool with timelock=0, decay=0, drawdown=500_000 (50%)
    // 2. Establish watermarks: hwm0 = 1000, hwm1 = 1000 via executeOracleStopLossHighWatermarks
    // 3. Pool admin proposes + immediately executes decay = 1e8
    extension.proposeOracleStopLossDecay(pool, 1e8);
    extension.executeOracleStopLossDecay(pool);   // timelock=0, executes immediately
    // 4. Warp 1 second
    vm.warp(block.timestamp + 1);
    // 5. Trigger afterSwap (any swap through the pool)
    // 6. Assert: highWatermarks[pool][binIdx].token0 == currentMetricT0 (not 1000)
    //            highWatermarks[pool][binIdx].token1 == currentMetricT1 (not 1000)
    // 7. Assert: a subsequent swap that drops value by 40% does NOT revert
    //    (it would have reverted before the reset with 50% drawdown protection)
}
```

The `_decayed(1000, 1e8, 1)` call computes `factor = 1e8 * 1 = 1e8 >= E8` and returns `0`. `_applyWatermark(currentMetric, 0, floorMultiplier)` returns `(currentMetric, false)`, silently resetting the baseline. [2](#0-1)

### Citations

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L281-284)
```text
    hwmS.token0 = uint104(hwm0);
    // forge-lint: disable-next-line(unsafe-typecast)
    hwmS.token1 = uint104(hwm1);
    hwmS.lastDecayTs = uint32(block.timestamp);
```

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L309-311)
```text
  function _validateDecay(uint256 decayPerSecondE8) private pure {
    if (decayPerSecondE8 > E8) revert OracleStopLossDecayTooLarge(decayPerSecondE8);
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

**File:** metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol (L333-333)
```text
    if (metric >= hwm) return (metric, false);
```
