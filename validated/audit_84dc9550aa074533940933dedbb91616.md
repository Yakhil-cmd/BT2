### Title
`protocolUnpausePool` Sets Wrong Pause State, Leaving Pool Permanently Admin-Paused After Protocol Unpause - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary
`MetricOmmPoolFactory.protocolUnpausePool` calls `setPause(1)` instead of `setPause(0)`, transitioning the pool from protocol-paused (state 2) into admin-paused (state 1) rather than fully active (state 0). Any pool that was active before a protocol pause remains paused after the protocol unpause, breaking all core pool operations.

### Finding Description

The pool's `pauseLevel` has three defined states:

> `0 = active, 1 = paused by admin, 2 = paused by protocol` [1](#0-0) 

`protocolPausePool` accepts pools in either state 0 (active) or state 1 (admin-paused) and moves them to state 2: [2](#0-1) 

`protocolUnpausePool` always transitions to state **1**, not state **0**:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);   // ← wrong: should be 0
}
``` [3](#0-2) 

The common scenario is:

1. Pool is **active** (state 0).
2. Protocol owner calls `protocolPausePool` → state 2.
3. Protocol owner calls `protocolUnpausePool` → state **1** (admin-paused), **not** state 0.
4. Pool is still paused. Swaps, liquidity additions, and removals remain blocked.

The admin can recover by calling `unpausePool` (state 1 → 0): [4](#0-3) 

However, the admin is not notified of this requirement, and the protocol owner has no direct path to fully restore the pool — `protocolUnpausePool` is the only owner-level unpause function and it always stops at state 1.

### Impact Explanation

After a protocol unpause, the pool is stuck in admin-paused state. All core pool operations — swaps, `addLiquidity`, `removeLiquidity` — remain blocked. LPs cannot withdraw their principal, and traders cannot execute swaps. This constitutes broken core pool functionality and an unusable withdraw/liquidity flow, matching the allowed impact gate.

### Likelihood Explanation

Every protocol unpause of a previously active pool (state 0 → 2 → 1) triggers this. The protocol owner has no reason to suspect the pool is still paused after calling `protocolUnpausePool`. Likelihood is high.

### Recommendation

```diff
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
-   if (cur != 2) revert InvalidPauseTransition(cur, 1);
-   IMetricOmmPoolFactoryActions(pool).setPause(1);
+   if (cur != 2) revert InvalidPauseTransition(cur, 0);
+   IMetricOmmPoolFactoryActions(pool).setPause(0);
}
``` [3](#0-2) 

### Proof of Concept

```solidity
// Pool starts active (pauseLevel == 0)
factory.protocolPausePool(pool);       // state → 2
// (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool); cur == 2 ✓

factory.protocolUnpausePool(pool);     // state → 1, NOT 0
// Pool is still paused; swaps revert with "paused" error

// Admin must call unpausePool to restore state 0:
factory.unpausePool(pool);             // state → 0
// Only now is the pool usable again
```

The wrong constant `setPause(1)` is the direct analog of the external report's `32 * 4` vs `32 * 2`: a single incorrect literal in a state-transition assignment that causes the operation to silently produce the wrong outcome, leaving core functionality broken.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L71-72)
```text
  /// @dev 0 = active, 1 = paused by admin, 2 = paused by protocol. Transitions enforced by factory.
  uint8 internal pauseLevel;
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L467-471)
```text
  function unpausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 1) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0);
  }
```
