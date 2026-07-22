### Title
`protocolUnpausePool` Always Restores to Admin-Paused State (1) Instead of Active State (0), Leaving Pool Permanently Swap-Blocked — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`protocolUnpausePool` hard-codes the target pause level to `1` (admin-paused) instead of restoring the pool to its pre-protocol-pause state. When the protocol pauses an **active** pool (state `0`) and later unpauses it, the pool lands in state `1` (admin-paused) rather than state `0` (active). Because `whenNotPaused` blocks all swaps for any non-zero pause level, the pool remains swap-dead after the protocol owner believes it has been restored.

---

### Finding Description

The factory defines three pause levels:

| Level | Meaning |
|---|---|
| `0` | Active — swaps allowed |
| `1` | Paused by pool admin |
| `2` | Paused by protocol |

`protocolPausePool` accepts pools in **either** state `0` or `1` and moves them to state `2`:

```solidity
// MetricOmmPoolFactory.sol L393-L396
function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}
```

`protocolUnpausePool` then **always** moves the pool to state `1`, regardless of whether it was at `0` or `1` before the protocol pause:

```solidity
// MetricOmmPoolFactory.sol L399-L403
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);   // ← always 1, never 0
}
```

The `whenNotPaused` guard in `MetricOmmPool` blocks swaps for **any** non-zero level:

```solidity
// MetricOmmPool.sol L643-L645
function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
}
```

**Execution path for the broken invariant:**

1. Pool is in state `0` (active, normal operation).
2. Protocol owner calls `protocolPausePool` → state becomes `2`.
3. Protocol owner calls `protocolUnpausePool` → state becomes `1` (admin-paused), **not** `0`.
4. Every subsequent `swap()` call reverts with `PoolPaused` even though the protocol owner believes the pool is live.
5. Recovery requires the pool admin to separately call `unpausePool` (state `1` → `0`). If the pool admin key is unavailable or the admin is unresponsive, the pool is permanently swap-blocked.

---

### Impact Explanation

All swaps are blocked after a protocol unpause of a previously-active pool. LPs cannot trade; the pool's core function is broken. `removeLiquidity` carries no `whenNotPaused` guard so LP principal withdrawal is still possible, preventing direct principal loss. However, the pool is rendered commercially insolvent (no fee revenue, no swap settlement) until the pool admin independently intervenes — an action the protocol owner has no power to force.

**Severity: Medium** — broken core pool functionality; no direct loss of user principal, but swap flows are completely unusable and the protocol owner's unpause action silently fails to restore the pool.

---

### Likelihood Explanation

The trigger is a routine, privileged-but-valid operation: the protocol owner pausing and then unpausing a pool. No malicious setup is required. Any pool that was active (`0`) at the time of a protocol pause will be affected every time `protocolUnpausePool` is called. The bug fires deterministically on the common case (pausing an active pool).

---

### Recommendation

Store the pre-protocol-pause state before overwriting it, and restore it on unpause. The simplest fix is to record whether the pool was at `0` or `1` before the protocol pause (e.g., in a factory mapping `prePausePauseLevel[pool]`) and use that value as the argument to `setPause` in `protocolUnpausePool`. Alternatively, restrict `protocolPausePool` to only accept state `0` (active) pools and hard-code the restore target to `0` — but this removes the ability to protocol-pause an already-admin-paused pool.

---

### Proof of Concept

```
1. Deploy pool → pauseLevel = 0 (active).
2. Factory owner calls protocolPausePool(pool).
   → pool.setPause(2) → pauseLevel = 2.
3. Factory owner calls protocolUnpausePool(pool).
   → pool.setPause(1) → pauseLevel = 1.
4. Any user calls pool.swap(...).
   → _checkNotPaused() → pauseLevel (1) != 0 → revert PoolPaused().
5. Pool admin must call factory.unpausePool(pool) to reach state 0.
   If pool admin is absent, pool is permanently swap-blocked.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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
