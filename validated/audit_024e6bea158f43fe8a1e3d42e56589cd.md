Looking at the pause state machine in `MetricOmmPoolFactory.sol` and `MetricOmmPool.sol` for the analog to the external "wrong unit/value" bug class.

**Key observations:**

1. `_checkNotPaused` blocks swaps when `pauseLevel != 0` — both level 1 and level 2 block swaps.
2. `protocolPausePool` accepts pools at state 0 **or** 1 → transitions to 2.
3. `protocolUnpausePool` always transitions 2 → **1** (not 0), regardless of pre-pause state.
4. `unpausePool` (admin) transitions 1 → 0.

This means: if the protocol pauses a fully-active pool (state 0) and then unpauses it, the pool lands at state 1 — still blocking all swaps — while the protocol owner believes the pool is operational.

---

### Title
`protocolUnpausePool` Always Transitions to Admin-Paused Level 1 Instead of Restoring Pre-Pause Active State, Leaving Swaps Permanently Blocked After Protocol Unpause — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`protocolUnpausePool` hard-codes the target pause level to `1` (admin-paused) regardless of the pool's state before the protocol pause. When the protocol pauses a fully-active pool (level 0) and later unpauses it, the pool is left at level 1, where `_checkNotPaused` still reverts every swap. The protocol owner believes the pool is restored; it is not.

### Finding Description
The pool's pause state machine has three levels:

| Level | Meaning | Swaps |
|-------|---------|-------|
| 0 | Active | Allowed |
| 1 | Admin-paused | Blocked |
| 2 | Protocol-paused | Blocked |

`_checkNotPaused` in `MetricOmmPool` reverts on **any** non-zero level: [1](#0-0) 

`swap` carries `whenNotPaused`; `addLiquidity` and `removeLiquidity` do not, so only swaps are affected.

`protocolPausePool` accepts pools at level 0 **or** 1: [2](#0-1) 

`protocolUnpausePool` unconditionally targets level 1: [3](#0-2) 

The factory stores no record of the pool's pre-pause level. After

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L643-645)
```text
  function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
  }
```

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
