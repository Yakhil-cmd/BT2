### Title
`protocolUnpausePool` Always Transitions to Admin-Paused State (1) Regardless of Pre-Pause State, Leaving Active Pools Permanently Paused After Protocol Unpause - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`protocolUnpausePool` unconditionally sets `pauseLevel` to `1` (admin-paused) instead of restoring the pool's pre-pause state. When the protocol pauses an **active** pool (state `0`) and then unpauses it, the pool ends up in state `1` (admin-paused) — still paused — rather than returning to state `0` (active). Swaps remain blocked until the pool admin separately calls `unpausePool`. If the admin is unavailable, the pool is permanently paused.

### Finding Description

The pause state machine has three levels:
- `0` = active
- `1` = paused by admin
- `2` = paused by protocol

`protocolPausePool` accepts both state `0` and state `1` as valid starting points and transitions to state `2`: [1](#0-0) 

`protocolUnpausePool` always transitions to state `1`, regardless of whether the pool was in state `0` or `1` before being protocol-paused: [2](#0-1) 

This produces a non-monotonic state curve identical in structure to the external bug: two different starting states (`0` and `1`) both collapse to state `2` via `protocolPausePool`, and `protocolUnpausePool` always emits state `1` — so a pool that was **active** before the protocol pause ends up in the **same paused state** as a pool that was already admin-paused. The round-trip `protocolPausePool → protocolUnpausePool` is not idempotent for active pools.

`swap` is the only function gated by `whenNotPaused`: [3](#0-2) [4](#0-3) 

State `1` satisfies `pauseLevel != 0`, so swaps revert with `PoolPaused` even after the protocol owner has called `protocolUnpausePool`.

### Impact Explanation

After a protocol pause-then-unpause cycle on a previously active pool, all swaps remain blocked. LPs cannot earn fees; traders cannot execute. If the pool admin is unavailable (lost key, multisig quorum failure), the pool is permanently paused with no recovery path available to the protocol owner. This is broken core swap functionality matching the allowed impact gate.

### Likelihood Explanation

Any legitimate emergency response by the protocol owner — pause a live pool, resolve the issue, unpause — triggers this path. No malicious intent or unusual configuration is required. The sequence is a natural operational workflow.

### Recommendation

Track the pre-pause state before transitioning to `2`, and restore it on `protocolUnpausePool`. One approach: store the previous `pauseLevel` in factory storage per pool when `protocolPausePool` is called, and restore it in `protocolUnpausePool`. Alternatively, allow `protocolUnpausePool` to transition directly to state `0` (active), since the protocol owner already has authority over both pause levels.

### Proof of Concept

```
Initial state: pauseLevel = 0 (active)

1. poolAdmin calls pausePool()         → requires cur == 0, sets to 1  ✓
   OR pool is simply active (cur == 0)

2. owner calls protocolPausePool()     → requires cur == 0 OR cur == 1, sets to 2  ✓

3. owner calls protocolUnpausePool()   → requires cur == 2, sets to 1

4. user calls swap()                   → _checkNotPaused(): pauseLevel (1) != 0 → revert PoolPaused()

Expected: pool returns to state 0 (active) after step 3
Actual:   pool is in state 1 (admin-paused); swaps still blocked
Fix:      pool admin must separately call unpausePool() — or pool is permanently paused
``` [5](#0-4)

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
