Looking at the pause state machine in `MetricOmmPoolFactory.sol`, I found a direct analog to the external bug's "Invalid Validation" class: a wrong target value in `protocolUnpausePool` that leaves the pool still paused after the protocol owner intends to unpause it.

---

### Title
`protocolUnpausePool` Transitions Pool to Admin-Paused (Level 1) Instead of Active (Level 0), Leaving Pool Permanently Paused After Protocol Unpause — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`protocolUnpausePool` calls `setPause(1)` instead of `setPause(0)`. After the protocol owner invokes this function to restore a protocol-paused pool, the pool remains paused at level 1 (admin-paused). Every swap, add-liquidity, and remove-liquidity call continues to revert with `PoolPaused` until the pool admin separately calls `unpausePool`.

---

### Finding Description

The pool uses a three-level pause state machine:

- `0` = active
- `1` = paused by admin
- `2` = paused by protocol

`_checkNotPaused` reverts for **any** non-zero level: [1](#0-0) 

`protocolUnpausePool` is the protocol owner's path to restore a level-2 pool. It reads the current level, validates it is 2, then calls `setPause(1)`: [2](#0-1) 

Level 1 is non-zero, so `_checkNotPaused` still reverts. The pool is not unpaused — it is merely demoted from protocol-paused to admin-paused. The `swap` function carries `whenNotPaused`: [3](#0-2) 

so every user-facing trade continues to revert. `addLiquidity` and `removeLiquidity` do not carry `whenNotPaused` themselves, but the pool is effectively broken for its primary function.

For comparison, the admin's own unpause correctly targets level 0: [4](#0-3) 

The protocol path does not.

---

### Impact Explanation

After `protocolUnpausePool` executes, the pool sits at pause level 1. All `swap` calls revert with `PoolPaused`. The protocol owner believes the pool is live; it is not. Recovery requires the pool admin to separately call `unpausePool`. If the pool admin is a multisig, a DAO, or simply slow to act, the pool remains unusable for an indefinite period — breaking the core swap and liquidity-withdrawal flows for all users and locking LP assets inside a non-functional pool.

---

### Likelihood Explanation

This triggers every time the protocol owner pauses a pool that was previously active (level 0) and then calls `protocolUnpausePool`. That is the normal pause/unpause lifecycle. No special conditions are required; any protocol owner action on any active pool reproduces the issue.

---

### Recommendation

Change the target level in `protocolUnpausePool` from `1` to `0`:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0);
-   IMetricOmmPoolFactoryActions(pool).setPause(1);
+   IMetricOmmPoolFactoryActions(pool).setPause(0);
}
```

If the intent is to preserve a pre-existing admin pause, the factory must store the pre-protocol-pause level and restore it on unpause.

---

### Proof of Concept

1. Pool is at level 0 (active). Users can swap normally.
2. Protocol owner calls `protocolPausePool(pool)` → pool transitions `0 → 2`. Swaps revert.
3. Protocol owner calls `protocolUnpausePool(pool)` → pool transitions `2 → 1`. **Pool is still paused.**
4. User calls `swap(...)` → reverts with `PoolPaused` (level 1 ≠ 0).
5. Pool admin must separately call `unpausePool(pool)` to reach level 0.

The protocol owner's unpause action has no effect on pool liveness; the pool admin holds the only key to restore trading.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L224-224)
```text
  ) external whenNotPaused nonReentrant(PoolActions.SWAP) returns (int128, int128) {
```

**File:** metric-core/contracts/MetricOmmPool.sol (L643-645)
```text
  function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
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
