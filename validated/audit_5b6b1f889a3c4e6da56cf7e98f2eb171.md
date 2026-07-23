Searching the pause transition logic in the factory for the analog to the inverted-direction bug.

### Title
`protocolUnpausePool` Sets Pause Level to 1 (Admin-Paused) Instead of 0 (Active), Leaving Swaps Permanently Blocked — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`protocolUnpausePool` is supposed to restore a protocol-paused pool to the active state. Instead it transitions `pauseLevel` from 2 to 1 (admin-paused), which still satisfies the `whenNotPaused` guard (`pauseLevel != 0`). Swaps remain blocked after the protocol owner "unpauses" the pool. Full restoration requires the pool admin to separately call `unpausePool`, a party the protocol cannot compel.

---

### Finding Description

The three pause levels are:

| Level | Meaning |
|---|---|
| 0 | Active |
| 1 | Paused by admin |
| 2 | Paused by protocol |

`protocolPausePool` transitions directly from level 0 **or** level 1 to level 2 in a single call: [1](#0-0) 

`protocolUnpausePool` is the symmetric counterpart. It checks that the current level is 2, then calls `setPause(1)` — leaving the pool in admin-paused state: [2](#0-1) 

The `whenNotPaused` modifier on `swap` rejects any `pauseLevel != 0`: [3](#0-2) 

So after `protocolUnpausePool` executes, `pauseLevel == 1`, the modifier still reverts, and swaps remain completely blocked. The only path to level 0 is through the pool admin's `unpausePool`: [4](#0-3) 

The protocol owner — who holds higher authority — cannot unilaterally restore swap functionality. The pool admin, a semi-trusted party, must cooperate.

The asymmetry is the bug: `protocolPausePool` is a one-step operation (0 or 1 → 2), but `protocolUnpausePool` only moves one level (2 → 1) instead of going all the way to 0. The correct target is `setPause(0)`.

---

### Impact Explanation

After a protocol-level emergency pause is resolved and the owner calls `protocolUnpausePool`, all swaps remain reverted. LPs can still call `removeLiquidity` (no `whenNotPaused` guard there), but the core swap flow — the primary mechanism for price discovery and fee generation — is entirely unusable until the pool admin separately acts. If the admin is unresponsive, the pool is permanently stuck at level 1 with no recourse for the protocol owner.

---

### Likelihood Explanation

This triggers on every normal use of `protocolUnpausePool` when the pool was active (level 0) before the protocol pause. No special conditions, no attacker required — the protocol owner's own call produces the broken state.

---

### Recommendation

Change the target in `protocolUnpausePool` from `1` to `0`:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0);
-   IMetricOmmPoolFactoryActions(pool).setPause(1);
+   IMetricOmmPoolFactoryActions(pool).setPause(0);
}
```

If the two-step design (protocol → admin) is intentional, rename the function to `protocolDowngradePause` and document that the admin must still call `unpausePool` to restore swaps.

---

### Proof of Concept

1. Pool is active: `pauseLevel == 0`.
2. Protocol owner calls `protocolPausePool(pool)` → `pauseLevel == 2`. Swaps revert.
3. Emergency resolved. Protocol owner calls `protocolUnpausePool(pool)`.
4. `setPause(1)` executes → `pauseLevel == 1`.
5. Any call to `swap(...)` hits `_checkNotPaused()` → `pauseLevel != 0` → `revert PoolPaused()`.
6. Pool admin must call `unpausePool(pool)` to reach level 0. If admin is absent, swaps are permanently blocked. [2](#0-1) [5](#0-4)

### Citations

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
