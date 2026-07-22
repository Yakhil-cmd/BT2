### Title
`protocolUnpausePool` Passes Wrong Pause Level to `setPause`, Leaving Pool Permanently Paused After Protocol Unpause — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`protocolUnpausePool` is intended to restore a protocol-paused pool (level 2) to active state (level 0). Instead, it calls `setPause(1)`, which transitions the pool to admin-paused state (level 1). The pool remains paused after the protocol owner calls `protocolUnpausePool`, breaking swap functionality until the pool admin separately calls `unpausePool`.

---

### Finding Description

The pool has three pause levels:

- `0` = active
- `1` = paused by admin
- `2` = paused by protocol [1](#0-0) 

`protocolPausePool` correctly escalates from level 0 or 1 to level 2: [2](#0-1) 

`protocolUnpausePool` is the symmetric counterpart. It validates that the current level is 2, then calls `setPause(1)` — not `setPause(0)`: [3](#0-2) 

The wrong constant `1` is passed to `setPause` where `0` is required to restore the pool to active. This is the direct analog of the NFTX bug: a function accepts the correct intent (unpause) but internally forwards the wrong value (`1` instead of `0`) to the sub-function (`setPause`).

`swap` is gated by `whenNotPaused`, which reverts on any non-zero pause level: [4](#0-3) 

So after `protocolUnpausePool`, the pool is at level 1 and `swap` still reverts.

---

### Impact Explanation

After the protocol owner calls `protocolUnpausePool` on a pool that was active (level 0) before being protocol-paused (level 2), the pool transitions to level 1 (admin-paused) rather than level 0 (active). All swaps remain blocked. The pool admin must separately call `unpausePool` (which requires `cur == 1`) to fully restore the pool: [5](#0-4) 

Until the admin acts, the core swap flow is broken. This matches the allowed impact gate: **broken core pool functionality causing unusable swap flows**.

---

### Likelihood Explanation

The trigger is the protocol owner calling `protocolUnpausePool` — a routine, expected operation after a security pause is resolved. No malicious setup is required. Every invocation on a previously-active pool (level 0 → 2 → 1) silently fails to restore swap functionality.

---

### Recommendation

Change `setPause(1)` to `setPause(0)` in `protocolUnpausePool`:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0); // update expected target in error
    IMetricOmmPoolFactoryActions(pool).setPause(0);       // was: setPause(1)
}
```

---

### Proof of Concept

1. Pool is active: `pauseLevel == 0`.
2. Protocol owner calls `protocolPausePool(pool)` → `setPause(2)` → `pauseLevel == 2`. Swaps revert.
3. Issue is resolved. Protocol owner calls `protocolUnpausePool(pool)`.
4. `cur == 2` passes the guard. `setPause(1)` is called → `pauseLevel == 1`.
5. `swap` is called → `_checkNotPaused()` → `pauseLevel != 0` → `revert PoolPaused()`.
6. Pool remains paused. The protocol owner's unpause had no effect on swap availability.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L71-72)
```text
  /// @dev 0 = active, 1 = paused by admin, 2 = paused by protocol. Transitions enforced by factory.
  uint8 internal pauseLevel;
```

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
