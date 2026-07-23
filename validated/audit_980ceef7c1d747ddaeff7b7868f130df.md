### Title
`protocolUnpausePool` Leaves Pool Permanently Swap-Paused After Protocol Unpause — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`protocolUnpausePool` calls `setPause(1)` instead of `setPause(0)`. Because `pauseLevel != 0` is the sole guard in `_checkNotPaused`, the pool remains swap-paused after the protocol owner executes what is supposed to be an unpause. This is the direct analog of the Spartan `_approve` bug: an operation that appears to restore a value instead silently leaves the system in a broken state.

---

### Finding Description

The pause-level semantics are defined in `MetricOmmPool.sol`:

> `0 = active, 1 = paused by admin, 2 = paused by protocol`

`_checkNotPaused` enforces:

```solidity
function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
}
``` [1](#0-0) 

`protocolPausePool` accepts pools at level 0 **or** level 1 and promotes them to level 2:

```solidity
function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}
``` [2](#0-1) 

`protocolUnpausePool` then sets the level to **1**, not **0**:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);   // ← should be 0
}
``` [3](#0-2) 

Level 1 still satisfies `pauseLevel != 0`, so every subsequent `swap` call reverts with `PoolPaused`. The pool is not active after the protocol "unpauses" it.

The only recovery path is for the pool admin to separately call `unpausePool`, which requires `cur == 1` and sets to 0:

```solidity
function unpausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 1) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0);
}
``` [4](#0-3) 

The pool admin is not notified by any on-chain mechanism that this extra step is required. If the pool was at level 0 (fully active) before the protocol pause, the admin has no reason to believe they must act.

---

### Impact Explanation

After `protocolUnpausePool` executes, `swap` remains permanently blocked for all users. LPs cannot trade, arbitrageurs cannot rebalance, and any protocol or integration that monitors for the `PauseLevelUpdated(2 → 1)` event and treats it as "pool is live again" will route orders into a pool that reverts every swap. The pool is operationally dead until the admin independently discovers and executes `unpausePool`. If the admin key is unavailable or the admin is unaware, the pool is permanently stuck.

---

### Likelihood Explanation

The trigger is a routine, privileged-but-valid operation: the protocol owner pauses a live pool (level 0 → 2) and later unpauses it. This is the documented emergency-response flow. The bug fires every single time this sequence is executed on a pool that was active before the protocol pause. No attacker input is required; the protocol owner's own correct use of the API causes the failure.

---

### Recommendation

Change `protocolUnpausePool` to set the pause level to `0` (active), not `1`:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0);
}
```

If the design intent is to restore the pool to its pre-protocol-pause level (0 or 1), the factory must record the level at the time of `protocolPausePool` and restore it on unpause.

---

### Proof of Concept

1. Pool is active: `pauseLevel == 0`.
2. Protocol owner calls `protocolPausePool(pool)` → `setPause(2)` → `pauseLevel == 2`. Swaps revert.
3. Protocol owner calls `protocolUnpausePool(pool)` → `setPause(1)` → `pauseLevel == 1`.
4. Any user calls `swap(...)` → `_checkNotPaused()` → `pauseLevel != 0` → **`PoolPaused` revert**.
5. Pool admin must independently discover the situation and call `unpausePool(pool)` → `setPause(0)` to restore trading. Until then, all swap functionality is broken.

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L399-403)
```text
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
