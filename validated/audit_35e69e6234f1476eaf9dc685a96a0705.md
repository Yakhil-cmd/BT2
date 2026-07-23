Looking at the external bug class: **incorrect state restoration after a revoke/remove action** — only a partial amount is subtracted/restored, leaving the system in a wrong state. I need to find the same pattern in Metric OMM's factory/admin/pause paths.

The most direct analog is in the pause-level state machine in `MetricOmmPoolFactory.sol`.

---

### Title
`protocolUnpausePool` Always Restores Pause Level to 1 Instead of Pre-Pause Level, Leaving Active Pools Permanently Admin-Paused — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`protocolPausePool` accepts pools at level 0 (active) **or** level 1 (admin-paused) and moves them to level 2 (protocol-paused). `protocolUnpausePool` always sets the level back to 1, never to 0. A pool that was fully active before the protocol pause is left in admin-paused state after the protocol unpause, blocking all swaps until the pool admin takes a separate, unexpected action.

---

### Finding Description

The pool's pause-level encoding is:

```
0 = active
1 = paused by admin
2 = paused by protocol
```

`protocolPausePool` accepts both level-0 and level-1 pools:

```solidity
// metric-core/contracts/MetricOmmPoolFactory.sol  lines 392-396
function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}
```

`protocolUnpausePool` unconditionally writes level 1, discarding the pre-pause level:

```solidity
// metric-core/contracts/MetricOmmPoolFactory.sol  lines 399-403
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);   // ← always 1, never 0
}
```

The `swap` function enforces `whenNotPaused`, which reverts on any non-zero level:

```solidity
// metric-core/contracts/MetricOmmPool.sol  lines 643-645
function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
}
```

**Scenario that triggers the bug:**

| Step | Actor | Action | Resulting level |
|------|-------|--------|-----------------|
| 1 | — | Pool is live | 0 (active) |
| 2 | Protocol owner | `protocolPausePool` | 2 |
| 3 | Protocol owner | `protocolUnpausePool` | **1** ← wrong; should be 0 |
| 4 | Any user | `swap(...)` | **reverts `PoolPaused`** |

After step 3 the pool is labelled "paused by admin" even though the admin never paused it. The admin must now call `unpausePool` — a function that checks `cur == 1` — to restore level 0. Until that separate transaction is sent, every swap, `simulateSwapAndRevert`, and `getSellAndBuyPrices` call reverts.

This is structurally identical to the seed bug: just as `revokeVestingSchedule` subtracts only the withdrawable portion from the checkpoint (leaving the user with excess voting power), `protocolUnpausePool` restores only part of the pool's pre-pause state (writing level 1 instead of level 0), leaving the pool in an incorrect, more-restricted state than it was before the protocol pause.

---

### Impact Explanation

All swaps are blocked after a protocol pause/unpause cycle on a previously-active pool. This is a direct "unusable swap flow" impact. Protocol fees and LP spread income stop accruing for the duration of the unexpected admin-paused window. The pool admin may not be aware that a separate `unpausePool` call is required, extending the outage indefinitely.

---

### Likelihood Explanation

The trigger is the protocol owner calling `protocolPausePool` followed by `protocolUnpausePool` on any pool that was at level 0 at the time of the pause. Emergency pauses on active pools are the primary use-case for `protocolPausePool`, so this scenario is the common path, not an edge case.

---

### Recommendation

Store the pre-protocol-pause level and restore it on unpause:

```diff
// In factory storage
+ mapping(address => uint8) public prePausedLevel;

function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
+   prePausedLevel[pool] = cur;
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}

function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
-   IMetricOmmPoolFactoryActions(pool).setPause(1);
+   uint8 restore = prePausedLevel[pool];
+   delete prePausedLevel[pool];
+   IMetricOmmPoolFactoryActions(pool).setPause(restore);
}
```

Alternatively, always restore to level 0 on protocol unpause if the intent is that the protocol override fully lifts the pause.

---

### Proof of Concept

```
1. Deploy pool → pauseLevel == 0 (active)
2. owner.protocolPausePool(pool)  → pauseLevel == 2
3. owner.protocolUnpausePool(pool) → pauseLevel == 1  (bug: should be 0)
4. user.swap(...)  → reverts PoolPaused()
5. admin.unpausePool(pool) → pauseLevel == 0  (unexpected extra step required)
6. user.swap(...)  → succeeds
```

The pool is stuck in admin-paused state between steps 3 and 5 with no on-chain signal that the admin needs to act. The pre-pause level (0) is silently discarded by `protocolUnpausePool`. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L392-403)
```text
  function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
  }

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);
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
