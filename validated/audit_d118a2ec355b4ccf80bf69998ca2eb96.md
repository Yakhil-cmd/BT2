### Title
`protocolUnpausePool` Hardcodes Target State to Admin-Paused (1) Instead of Restoring Pre-Pause State, Leaving Active Pools Permanently Swap-Blocked — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`protocolUnpausePool` always transitions the pool to pause level `1` (admin-paused) regardless of what state the pool was in before the protocol pause. When the protocol pauses an **active** pool (level `0`) and later unpauses it, the pool lands in admin-paused state (level `1`), not active state (level `0`). Swaps remain blocked. The factory stores no record of the pre-pause level, so the protocol owner cannot recover the original state without the pool admin's cooperation.

---

### Finding Description

The pause state machine has three levels:

| Level | Meaning | Who can exit |
|---|---|---|
| `0` | Active | — |
| `1` | Admin-paused | Pool admin (`unpausePool`) |
| `2` | Protocol-paused | Protocol owner (`protocolUnpausePool`) |

`protocolPausePool` accepts **both** level `0` and level `1` as valid source states:

```solidity
// MetricOmmPoolFactory.sol line 393-396
function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}
```

`protocolUnpausePool` **always** targets level `1`, unconditionally:

```solidity
// MetricOmmPoolFactory.sol line 399-403
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);   // ← always 1, never 0
}
```

The pool's `swap` function is gated by `whenNotPaused`, which reverts on **any** non-zero pause level:

```solidity
// MetricOmmPool.sol line 643-645
function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
}
```

After `protocolUnpausePool` executes, `pauseLevel == 1`, so `PoolPaused` is still thrown on every swap attempt. The factory stores no `prePauseLevel` mapping, so the protocol owner has no way to restore the pool to level `0` directly — only the pool admin can call `unpausePool` (level `1 → 0`).

---

### Impact Explanation

**Severity: Medium**

- Swaps are permanently blocked on any pool that was active (level `0`) before a protocol pause, until the pool admin explicitly calls `unpausePool`.
- The protocol owner calling `protocolUnpausePool` receives no error and no indication that the pool is still paused; the `PauseLevelUpdated(2, 1)` event looks like a successful unpause.
- If the pool admin key is lost, rotated away, or the admin is unresponsive, the pool is permanently stuck in admin-paused state with all LP assets locked from swap settlement.
- `addLiquidity` and `removeLiquidity` are not gated by `whenNotPaused`, so LP principal can be withdrawn, but the pool's core swap functionality — and therefore all fee generation — is permanently disabled.

---

### Likelihood Explanation

**Likelihood: Medium**

The protocol owner is expected to use `protocolPausePool` during emergencies (oracle failure, exploit response). After the emergency is resolved, calling `protocolUnpausePool` is the natural next step. The bug fires every time the paused pool was at level `0` (active) before the protocol pause, which is the common case. No attacker action is required; the bug is triggered by the protocol owner's own legitimate recovery flow.

---

### Recommendation

Store the pre-pause level in the factory and restore it on unpause:

```solidity
mapping(address => uint8) public prePauseLevel;

function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    prePauseLevel[pool] = cur;                        // ← record original level
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}

function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    uint8 restore = prePauseLevel[pool];              // ← restore original level
    delete prePauseLevel[pool];
    IMetricOmmPoolFactoryActions(pool).setPause(restore);
}
```

---

### Proof of Concept

1. Pool is deployed and active (`pauseLevel == 0`).
2. Protocol owner calls `protocolPausePool(pool)` — pool transitions `0 → 2`.
3. Emergency resolved; protocol owner calls `protocolUnpausePool(pool)` — pool transitions `2 → 1` (admin-paused). No revert, event emitted.
4. Any user calls `pool.swap(...)` — reverts with `PoolPaused` because `pauseLevel == 1 != 0`.
5. Protocol owner has no further lever to restore the pool; only the pool admin can call `factory.unpausePool(pool)` to transition `1 → 0`.
6. If the pool admin is unavailable, the pool is permanently swap-disabled despite the protocol owner having "unpaused" it. [1](#0-0) [2](#0-1) [3](#0-2)

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
