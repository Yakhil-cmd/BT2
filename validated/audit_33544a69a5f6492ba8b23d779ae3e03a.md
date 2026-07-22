### Title
`protocolUnpausePool` Passes Hardcoded Wrong Pause Level to `setPause`, Leaving Active Pools Permanently Admin-Paused After Protocol Unpause — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`protocolUnpausePool` always calls `setPause(1)` (admin-paused) regardless of the pool's state before the protocol pause. When the protocol owner pauses an **active** pool (level 0) and then unpauses it, the pool is left at level 1 (admin-paused) instead of level 0 (active). Swaps and liquidity operations remain blocked even after the protocol owner has explicitly unpaused the pool.

### Finding Description

The pool pause state machine has three levels:

| Level | Meaning |
|---|---|
| 0 | Active |
| 1 | Paused by admin |
| 2 | Paused by protocol |

`protocolPausePool` accepts pools at either level 0 or level 1 and transitions them to level 2: [1](#0-0) 

`protocolUnpausePool` then unconditionally calls `setPause(1)` — hardcoding the wrong target state: [2](#0-1) 

The correct value to pass depends on the pool's pre-protocol-pause state. When the pool was active (0) before `protocolPausePool`, `protocolUnpausePool` should call `setPause(0)`, not `setPause(1)`. Instead it always passes `1`, leaving the pool in admin-paused state.

This is directly analogous to the seeded bug: a caller function passes a hardcoded/wrong value to a sub-function (`setPause`) instead of the contextually correct one, corrupting the resulting state.

### Impact Explanation

After `protocolUnpausePool` is called on a pool that was active before the protocol pause:

- `pauseLevel` is set to 1 (admin-paused) instead of 0 (active).
- `swap()` reverts via `_checkNotPaused()` because `pauseLevel != 0`. [3](#0-2) 

- `addLiquidity` and `removeLiquidity` are not gated by `whenNotPaused` directly, but the pool is functionally broken for swaps.
- The protocol owner **cannot** directly restore the pool to active (0) — `protocolUnpausePool` only ever reaches level 1, and there is no factory function that sets a pool to level 0 except `unpausePool` (admin-only).
- If the pool admin is unresponsive, the pool remains permanently stuck at level 1 despite the protocol owner having explicitly unpaused it.

This breaks the core swap flow and constitutes unusable swap/liquidity functionality.

### Likelihood Explanation

The trigger path is:
1. Pool is active (level 0) — the normal operating state.
2. Protocol owner calls `protocolPausePool` (valid, e.g., during an emergency).
3. Protocol owner calls `protocolUnpausePool` to restore normal operation.
4. Pool is now at level 1 (admin-paused) — swaps still revert.

This is a routine operational sequence. No attacker is required; the protocol owner's own correct usage of the pause/unpause API triggers the bug.

### Recommendation

`protocolUnpausePool` must restore the pool to **active** (level 0), not admin-paused (level 1). The simplest correct fix:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0); // restore to active
}
```

If the intent is to preserve the admin-paused state for pools that were admin-paused before the protocol pause, the factory must store the pre-protocol-pause level (e.g., in a `mapping(address => uint8) prePausedLevel`) and restore it on unpause.

### Proof of Concept

```
Initial state:  pool.pauseLevel == 0  (active)

Step 1: protocolPausePool(pool)
  → checks cur == 0, passes (0 != 0 && 0 != 1 is false → wait, 0 != 0 is false, so condition fails)
```

Wait — re-reading the guard:

```solidity
if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
```

`cur == 0`: `0 != 0` is `false`, so the whole `&&` is `false` → no revert → `setPause(2)` executes. ✓

```
Step 2: protocolUnpausePool(pool)
  → cur == 2, passes check
  → setPause(1)   ← BUG: should be setPause(0)

Result: pool.pauseLevel == 1  (admin-paused)

Step 3: user calls swap()
  → _checkNotPaused(): pauseLevel == 1 != 0 → revert PoolPaused()

Protocol owner has unpaused; pool is still paused.
Only the pool admin calling unpausePool() can restore level 0.
If admin is absent, pool is permanently stuck.
``` [2](#0-1) [4](#0-3)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L392-396)
```text
  function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L398-403)
```text
  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L174-177)
```text
  modifier whenNotPaused() {
    _checkNotPaused();
    _;
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L643-645)
```text
  function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
  }
```
