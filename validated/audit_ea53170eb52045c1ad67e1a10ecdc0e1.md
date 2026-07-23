### Title
`protocolUnpausePool` Sets Pause Level to 1 (Admin-Paused) Instead of 0 (Active), Leaving Pool Permanently Paused After Protocol Unpause — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.protocolUnpausePool` calls `setPause(1)` instead of `setPause(0)`. After the protocol owner invokes this function to lift a protocol-level pause, the pool remains paused at level 1 (admin-paused). All swaps continue to revert with `PoolPaused`. The protocol owner has no further path to set the pool to active (level 0); only the pool admin can do so by separately calling `unpausePool`. If the pool admin is unresponsive or uncooperative, the pool is permanently frozen.

---

### Finding Description

The pool pause system uses three levels:

| Level | Meaning |
|---|---|
| 0 | Active |
| 1 | Paused by admin |
| 2 | Paused by protocol | [1](#0-0) 

`protocolPausePool` correctly transitions from 0 or 1 → 2: [2](#0-1) 

But `protocolUnpausePool` transitions from 2 → **1**, not 2 → **0**: [3](#0-2) 

The `whenNotPaused` modifier on `swap` rejects any non-zero pause level: [4](#0-3) 

So after `protocolUnpausePool`, swaps still revert. The only recovery path is the pool admin calling `unpausePool`, which requires `cur == 1` → sets to 0: [5](#0-4) 

The protocol owner has no direct path to set the pool to level 0. The factory's `onlyOwner` functions only call `setPause(2)` or `setPause(1)`.

---

### Impact Explanation

After `protocolUnpausePool` is called, the pool is still paused at level 1. Every `swap` call reverts with `PoolPaused`. Traders cannot execute any swaps, and the pool is effectively dead until the pool admin separately calls `unpausePool`. If the pool admin is unavailable, malicious, or has been transferred away, the pool is permanently frozen — a complete loss of core swap functionality for all users and LPs.

---

### Likelihood Explanation

This triggers on every invocation of `protocolUnpausePool` without exception. No special preconditions are required. Any time the protocol owner pauses and then attempts to unpause a pool that was originally active (level 0), the pool is left in admin-paused state (level 1). The bug is unconditional.

---

### Recommendation

Change `protocolUnpausePool` to set the pause level to 0 (active) instead of 1:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0);
-   IMetricOmmPoolFactoryActions(pool).setPause(1);
+   IMetricOmmPoolFactoryActions(pool).setPause(0);
}
```

If the intended design is to hand control back to the admin (level 1) rather than fully unpause, the function must be renamed to reflect that (e.g., `protocolReleaseToAdminPause`) and the protocol owner must be given a separate path to set level 0 directly.

---

### Proof of Concept

1. Pool is deployed and active (level 0).
2. Protocol owner calls `protocolPausePool(pool)` → pool transitions to level 2.
3. Protocol owner calls `protocolUnpausePool(pool)` → pool transitions to level **1** (still paused).
4. Any user calls `pool.swap(...)` → reverts with `PoolPaused`.
5. Pool admin is the only entity that can call `unpausePool` to reach level 0. If the admin is absent, the pool is permanently frozen. [3](#0-2) [6](#0-5) [7](#0-6)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L71-72)
```text
  /// @dev 0 = active, 1 = paused by admin, 2 = paused by protocol. Transitions enforced by factory.
  uint8 internal pauseLevel;
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
