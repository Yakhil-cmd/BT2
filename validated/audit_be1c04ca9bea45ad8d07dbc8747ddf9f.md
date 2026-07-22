### Title
`protocolUnpausePool` Always Transitions to Admin-Paused State (1), Permanently Locking Swap Functionality When Pool Admin Is Unavailable — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory::protocolUnpausePool` unconditionally transitions a pool from protocol-paused (state 2) to admin-paused (state 1), regardless of the pool's pre-pause state. If the pool was active (state 0) before the protocol pause, the protocol owner has no path to restore state 0 directly. The pool admin must call `unpausePool` as a mandatory second step. If the pool admin is unavailable (lost key, broken multisig, renounced role), the pool is permanently stuck in state 1 with all swaps disabled — a core functionality loss with no recovery path.

---

### Finding Description

The factory defines a three-level pause state machine:

| State | Meaning |
|---|---|
| 0 | Active |
| 1 | Admin-paused |
| 2 | Protocol-paused |

The four transitions are: [1](#0-0) [2](#0-1) 

`protocolUnpausePool` hardcodes the target state to `1`:

```solidity
// MetricOmmPoolFactory.sol L399-403
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(1);   // ← always 1, never 0
}
``` [3](#0-2) 

The only path from state 1 → 0 is `unpausePool`, which is restricted to `onlyPoolAdmin`: [4](#0-3) 

The pool's `swap` function enforces `whenNotPaused`, which reverts on any non-zero `pauseLevel`: [5](#0-4) [6](#0-5) 

So state 1 permanently blocks all swaps. The protocol owner has no function that can set state 0 directly.

---

### Impact Explanation

If a pool was active (state 0) and the protocol owner emergency-pauses it (0 → 2), then later calls `protocolUnpausePool` (2 → 1), the pool lands in admin-paused state. The protocol owner cannot proceed further — only the pool admin can call `unpausePool` (1 → 0). If the pool admin is unavailable (key loss, multisig failure, admin contract self-destructed, or admin transferred to a dead address), the pool is permanently stuck in state 1:

- All `swap` calls revert with `PoolPaused`.
- `addLiquidity` and `removeLiquidity` are unaffected (no `whenNotPaused` guard), so LP principal is recoverable.
- The pool's core trading function is permanently broken with no on-chain recovery path.

**Impact: Medium** — core swap functionality permanently disabled; LP principal not directly lost but the pool is rendered non-functional as a trading venue.

---

### Likelihood Explanation

The trigger requires two conditions: (1) the protocol owner performs an emergency pause on a pool that was in state 0, then unpauses it; (2) the pool admin is subsequently unavailable. Pool admin unavailability is a realistic operational risk (key rotation failure, multisig quorum loss, admin contract upgrade gone wrong). The protocol owner performing an emergency pause is an expected operational event. **Likelihood: Low**, but the combination is plausible in production.

---

### Recommendation

`protocolUnpausePool` should restore the pool to the state it was in before the protocol pause, or at minimum provide the protocol owner a direct path to state 0. Two options:

1. **Store pre-pause state**: Before `protocolPausePool` transitions to state 2, record the current state (0 or 1) in factory storage. `protocolUnpausePool` restores to that recorded state.

2. **Allow protocol owner to target state 0 directly**: Add a separate `protocolFullyUnpausePool` function that transitions 2 → 0, bypassing the admin-paused intermediate state.

---

### Proof of Concept

1. Pool is deployed and active: `pauseLevel == 0`.
2. Protocol owner calls `protocolPausePool(pool)`: state transitions 0 → 2.
3. Emergency resolved; protocol owner calls `protocolUnpausePool(pool)`: state transitions 2 → 1 (admin-paused). Pool is NOT restored to active.
4. Pool admin key is lost (or admin is a multisig that has lost quorum).
5. No on-chain function exists for the protocol owner to call `setPause(0)` on the pool — `protocolUnpausePool` requires `cur == 2` (already consumed), and `unpausePool` requires `msg.sender == poolAdmin[pool]` (unavailable).
6. Every `swap(...)` call reverts with `PoolPaused` indefinitely. The pool is permanently non-functional as a trading venue. [2](#0-1) [1](#0-0) [7](#0-6) [5](#0-4)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L174-177)
```text
  modifier whenNotPaused() {
    _checkNotPaused();
    _;
  }
```

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
