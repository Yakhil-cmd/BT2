### Title
`protocolUnpausePool` Always Transitions to Admin-Paused State (1) Instead of Restoring Pre-Pause Active State (0), Leaving Swaps Permanently Blocked After Protocol Unpause - (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.protocolUnpausePool` unconditionally sets `pauseLevel` to `1` (admin-paused) regardless of the pool's state before the protocol pause. When the protocol owner pauses an **active** pool (state `0`) and later calls `protocolUnpausePool`, the pool is left in admin-paused state (`1`) — not restored to active (`0`). Because `MetricOmmPool.swap` enforces `whenNotPaused` which rejects any `pauseLevel != 0`, swaps remain blocked after the protocol owner's unpause action.

---

### Finding Description

The pause state machine has three levels:

| Level | Meaning | Who sets it |
|---|---|---|
| `0` | Active | Pool admin (`unpausePool`) |
| `1` | Admin-paused | Pool admin (`pausePool`) |
| `2` | Protocol-paused | Factory owner (`protocolPausePool`) |

`protocolPausePool` accepts both state `0` and state `1` as valid starting states before transitioning to `2`:

```solidity
// metric-core/contracts/MetricOmmPoolFactory.sol L392-L396
function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}
```

But `protocolUnpausePool` **always** transitions to state `1`, never to `0`:

```solidity
// metric-core/contracts/MetricOmmPoolFactory.sol L398-L403
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);
}
```

The pre-pause state is never saved, so the "undo" path is incomplete. The `whenNotPaused` modifier in `MetricOmmPool.swap` rejects both state `1` and state `2`:

```solidity
// metric-core/contracts/MetricOmmPool.sol L643-L645
function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
}
```

After `protocolUnpausePool`, the pool is in state `1` — swaps still revert with `PoolPaused`. The only recovery path is for the pool admin to separately call `unpausePool` (which transitions `1 → 0`):

```solidity
// metric-core/contracts/MetricOmmPoolFactory.sol L467-L471
function unpausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 1) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0);
}
```

This is the direct analog to the external bug: the secondary path (`protocolUnpausePool`) omits a critical state restoration step that the primary path (`protocolPausePool`) implicitly requires to be undone.

---

### Impact Explanation

After the protocol owner calls `protocolUnpausePool` on a pool that was **active** (state `0`) before the protocol pause, all swap calls continue to revert with `PoolPaused`. The pool's core functionality — swapping — remains broken despite the protocol owner's explicit intent to restore it. The pool admin must take a separate, uncoordinated action (`unpausePool`) to reach state `0`. If the pool admin is a multisig, DAO, or unresponsive contract, the pool can remain swap-disabled indefinitely. `addLiquidity` and `removeLiquidity` are not gated by `whenNotPaused`, so LP principal is not directly at risk, but the pool is commercially inoperable.

---

### Likelihood Explanation

Every pool that was in active state (`0`) at the time of a protocol pause will exhibit this behavior — it is not an edge case. The protocol owner has no mechanism to directly restore a pool to state `0`; only the pool admin can do so. The trigger is a routine, valid admin action (`protocolUnpausePool`) by the factory owner, requiring no special conditions.

---

### Recommendation

Save the pre-pause state before transitioning to `2`, and restore it on unpause:

```solidity
mapping(address => uint8) public prePauseLevel; // new storage

function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    prePauseLevel[pool] = cur; // save original state
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}

function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    uint8 restore = prePauseLevel[pool]; // 0 or 1
    delete prePauseLevel[pool];
    IMetricOmmPoolFactoryActions(pool).setPause(restore);
}
```

Alternatively, add a dedicated `protocolForceUnpauseToActive` that transitions `2 → 0` directly, giving the protocol owner the ability to fully restore a pool without depending on the pool admin.

---

### Proof of Concept

1. Pool is deployed and active: `pauseLevel == 0`.
2. Factory owner calls `protocolPausePool(pool)` → `pauseLevel` becomes `2`.
3. Factory owner calls `protocolUnpausePool(pool)` → `pauseLevel` becomes `1` (not `0`).
4. Any user calls `pool.swap(...)` → reverts with `PoolPaused` because `pauseLevel (1) != 0`.
5. Pool admin must separately call `factory.unpausePool(pool)` to reach `pauseLevel == 0`.
6. Until step 5 completes, all swaps are blocked despite the protocol owner having "unpaused" the pool. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L643-645)
```text
  function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
  }
```
