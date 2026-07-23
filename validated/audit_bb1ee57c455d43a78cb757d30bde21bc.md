### Title
`protocolUnpausePool` hardcodes target pause level to 1 (admin-paused) instead of 0 (active), leaving pool permanently swap-blocked after protocol unpause — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.protocolUnpausePool` always calls `setPause(1)` — the admin-paused level — instead of `setPause(0)` (active). When the factory owner pauses an active pool (level 0 → 2) and then calls `protocolUnpausePool`, the pool lands at level 1 (admin-paused) rather than returning to level 0 (active). Swaps remain blocked; only the pool admin can complete the recovery.

---

### Finding Description

The pool's three-level pause system is:

| Level | Meaning | Who sets it |
|---|---|---|
| 0 | Active — swaps allowed | — |
| 1 | Admin-paused — swaps blocked | Pool admin |
| 2 | Protocol-paused — swaps blocked | Factory owner |

`protocolPausePool` accepts level 0 **or** level 1 as a valid starting state (both transition to 2): [1](#0-0) 

`protocolUnpausePool`, however, unconditionally targets level 1 regardless of what the pool's level was before the protocol pause: [2](#0-1) 

The hardcoded `setPause(1)` call is the root cause — the exact same "wrong constant" pattern as the Derby `AaveProvider.exchangeRate()` always returning `1`: [3](#0-2) 

Scenario that triggers the bug:

1. Pool is at level 0 (active).
2. Factory owner calls `protocolPausePool` → pool moves to level 2.
3. Factory owner calls `protocolUnpausePool` → pool moves to level **1** (admin-paused), **not** level 0.
4. Swaps are still blocked by `whenNotPaused`.
5. The factory owner has no further lever to restore the pool; only the pool admin's `unpausePool` (level 1 → 0) can complete the recovery. [4](#0-3) 

The `swap` function is gated by `whenNotPaused`, so level 1 blocks swaps identically to level 2: [5](#0-4) 

---

### Impact Explanation

After the factory owner calls `protocolUnpausePool` on a previously-active pool, the pool remains at pause level 1. All swap traffic is blocked. If the pool admin is unavailable, unresponsive, or the admin key is lost, the pool is permanently frozen for swaps with no recovery path available to the factory owner. This is broken core pool functionality (unusable swap flow) matching the allowed impact gate.

---

### Likelihood Explanation

Emergency-pause-then-restore is a standard operational pattern. Every time the factory owner pauses an active (level 0) pool and later calls `protocolUnpausePool`, the bug fires unconditionally. No special preconditions or attacker involvement are required — the factory owner's own legitimate action produces the stuck state.

---

### Recommendation

`protocolUnpausePool` should restore the pool to level 0 (active), not level 1:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0); // target is active
    IMetricOmmPoolFactoryActions(pool).setPause(0);       // restore to active
}
```

If the design intent is to hand control back to the pool admin after a protocol pause, that should be documented explicitly and the function renamed accordingly (e.g., `protocolHandBackToAdmin`). As written, the name `protocolUnpausePool` implies full restoration to active state.

---

### Proof of Concept

```
State:  pool.pauseLevel == 0  (active, swaps working)

Step 1: owner calls protocolPausePool(pool)
        → setPause(2)  ✓  pool.pauseLevel == 2

Step 2: owner calls protocolUnpausePool(pool)
        → setPause(1)  ✗  pool.pauseLevel == 1  (still paused!)

Step 3: swap(...)  →  reverts via whenNotPaused  (level 1 ≠ 0)

Step 4: only poolAdmin calling unpausePool(pool) → setPause(0) can fix this.
        If poolAdmin is unavailable, pool is permanently swap-frozen.
``` [2](#0-1) [6](#0-5)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L455-461)
```text
  function setPause(uint8 newLevel) external onlyFactory {
    if (newLevel > 2) revert InvalidPauseLevel();
    if (newLevel == pauseLevel) return;
    uint8 prev = pauseLevel;
    pauseLevel = newLevel;
    emit PauseLevelUpdated(prev, newLevel);
  }
```
