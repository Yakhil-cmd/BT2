### Title
`protocolUnpausePool` Sets Wrong Pause Level, Leaving Pool Permanently Swap-Blocked — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.protocolUnpausePool()` transitions the pool to pause level `1` (admin-paused) instead of `0` (active). After the protocol "unpauses" a pool that was previously active, swaps remain blocked indefinitely until the pool admin separately calls `unpausePool()`.

---

### Finding Description

The pool has three pause levels:

- `0` = active (swaps allowed)
- `1` = paused by admin (swaps blocked)
- `2` = paused by protocol (swaps blocked)

`protocolPausePool` can pause from level `0` **or** level `1` to level `2`: [1](#0-0) 

`protocolUnpausePool` always transitions to level `1`, never to `0`: [2](#0-1) 

The `whenNotPaused` modifier in `MetricOmmPool` blocks swaps whenever `pauseLevel != 0`: [3](#0-2) [4](#0-3) 

The `swap` function carries `whenNotPaused`: [5](#0-4) 

So after `protocolUnpausePool` executes, the pool is at level `1` — swaps are still blocked. The pool admin must then call `unpausePool()` (which only transitions `1 → 0`) to restore swap functionality: [6](#0-5) 

---

### Impact Explanation

Every call to `protocolUnpausePool` on a pool that was at level `0` before the protocol pause leaves the pool stuck at level `1`. Swaps are completely unusable until the pool admin manually calls `unpausePool`. If the pool admin is unavailable, unresponsive, or the admin key is lost, swaps are permanently blocked. This is broken core pool functionality — the primary revenue-generating operation of the protocol is disabled by a routine administrative action that is supposed to restore it.

---

### Likelihood Explanation

The normal operational flow is: protocol pauses a pool (level `0 → 2`) for an emergency, then unpauses it (level `2 → 0`) to restore service. Every single invocation of `protocolUnpausePool` on a previously-active pool triggers this bug. No special conditions, attacker, or malicious setup is required — the factory owner simply calls the function as intended.

---

### Recommendation

`protocolUnpausePool` should set the pause level to `0` (active), not `1`:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0);
-   IMetricOmmPoolFactoryActions(pool).setPause(1);
+   IMetricOmmPoolFactoryActions(pool).setPause(0);
}
```

If the design intent is to hand off to the admin after a protocol unpause, the function should be documented clearly and renamed (e.g., `protocolReleasePause`), and a separate `protocolFullyUnpausePool` path should exist for the common case.

---

### Proof of Concept

1. Pool is deployed and active (`pauseLevel = 0`).
2. Factory owner calls `protocolPausePool(pool)` → pool transitions to `pauseLevel = 2`. Swaps revert with `PoolPaused`.
3. Emergency resolved. Factory owner calls `protocolUnpausePool(pool)`.
4. `setPause(1)` is called → `pauseLevel = 1`.
5. Any user calls `swap(...)` → `_checkNotPaused()` sees `pauseLevel != 0` → reverts with `PoolPaused`.
6. Swaps remain blocked. Only the pool admin calling `unpausePool()` can restore them. If the admin is unavailable, the pool is permanently swap-bricked.

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

**File:** metric-core/contracts/MetricOmmPool.sol (L217-224)
```text
  function swap(
    address recipient,
    bool zeroForOne,
    int128 amountSpecified,
    uint128 priceLimitX64,
    bytes calldata callbackData,
    bytes calldata extensionData
  ) external whenNotPaused nonReentrant(PoolActions.SWAP) returns (int128, int128) {
```

**File:** metric-core/contracts/MetricOmmPool.sol (L643-645)
```text
  function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
  }
```
