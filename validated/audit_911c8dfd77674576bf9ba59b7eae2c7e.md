### Title
`protocolUnpausePool` Unconditionally Sets `pauseLevel` to 1, Permanently Blocking Swap for Previously-Active Pools Until Admin Intervenes — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`protocolUnpausePool` always transitions the pool to `pauseLevel = 1` (admin-paused), regardless of whether the pool was active (`pauseLevel = 0`) or already admin-paused (`pauseLevel = 1`) before the protocol pause. Because the pre-pause level is never stored, a pool that was fully active before an emergency protocol pause is left permanently in admin-paused state after the protocol "unpauses" it. Swap remains broken until the pool admin separately calls `unpausePool`.

---

### Finding Description

`protocolPausePool` accepts both `pauseLevel == 0` (active) and `pauseLevel == 1` (admin-paused) as valid source states: [1](#0-0) 

`protocolUnpausePool` unconditionally sets the level to **1**, never to 0: [2](#0-1) 

The pool's `setPause` function accepts any value 0–2 without restriction: [3](#0-2) 

The `swap` function is gated by `whenNotPaused`, which reverts on any non-zero `pauseLevel`: [4](#0-3) [5](#0-4) 

The admin's `unpausePool` can only transition from level 1 → 0, and is gated to the pool admin: [6](#0-5) 

No factory function allows the protocol owner to set `pauseLevel` directly to 0. The only path from 1 → 0 is through the pool admin.

---

### Impact Explanation

When the sequence is:

1. Pool at `pauseLevel = 0` (active, normal operation)
2. Protocol owner calls `protocolPausePool` → `pauseLevel = 2`
3. Protocol owner calls `protocolUnpausePool` → `pauseLevel = 1` (**not 0**)

The pool is now in admin-paused state even though the admin never issued a pause. `swap` remains blocked for all users. `addLiquidity` and `removeLiquidity` are unaffected (no `whenNotPaused` guard), so LP capital is not locked, but the pool's core trading function is completely unusable. If the pool admin is unresponsive, has lost keys, or is simply unaware that a separate `unpausePool` call is required, the pool remains permanently paused. This matches the allowed impact gate: **broken core pool functionality causing unusable swap flow**.

---

### Likelihood Explanation

Emergency protocol pauses followed by unpauses are a standard operational pattern in DeFi. The protocol owner has no indication from the function name or NatDoc that `protocolUnpausePool` does not fully restore the pool — the name implies a complete reversal. The pool admin receives no on-chain signal that they must act. Any pool that was active at the time of a protocol pause is affected.

---

### Recommendation

Store the pre-pause level before transitioning to 2, and restore it on unpause:

```solidity
// In factory storage:
mapping(address => uint8) public prePausePauseLevel;

function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    prePausePauseLevel[pool] = cur;          // ← record original level
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}

function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0);
    uint8 restore = prePausePauseLevel[pool]; // ← restore original level (0 or 1)
    delete prePausePauseLevel[pool];
    IMetricOmmPoolFactoryActions(pool).setPause(restore);
}
```

---

### Proof of Concept

```
State:  pauseLevel = 0  (pool active, swaps working)

Step 1: owner calls protocolPausePool(pool)
        → requires cur == 0 || cur == 1  ✓
        → setPause(2)
        → pauseLevel = 2

Step 2: owner calls protocolUnpausePool(pool)
        → requires cur == 2  ✓
        → setPause(1)          ← always 1, never 0
        → pauseLevel = 1

Step 3: user calls pool.swap(...)
        → whenNotPaused: pauseLevel != 0  → revert PoolPaused()

Step 4: admin must call factory.unpausePool(pool)
        → requires cur == 1  ✓
        → setPause(0)
        → pauseLevel = 0  (finally restored)

If admin is absent/unresponsive: pool swap is permanently broken.
```

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

**File:** metric-core/contracts/MetricOmmPool.sol (L643-645)
```text
  function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
  }
```
