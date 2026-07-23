Looking at the external bug's invariant — an operation that should complete a chain of state transitions fails because the wrong value/address is used at a critical step — I searched the Metric OMM factory, admin, pause, and extension-config paths for the same class of failure.

The closest match is in the pause state machine inside `MetricOmmPoolFactory`.

---

### Title
`protocolUnpausePool` Sets Pool to Admin-Paused State (Level 1) Instead of Active (Level 0), Leaving Core Swap Functionality Permanently Broken — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
`protocolUnpausePool` always writes `pauseLevel = 1` (admin-paused) instead of `pauseLevel = 0` (active). When the protocol pauses an active pool (0 → 2) and then calls `protocolUnpausePool` (2 → 1), the pool is still paused. Swaps revert with `PoolPaused` and the pool admin must take an additional explicit action to restore the pool — an action the protocol cannot force.

### Finding Description

The pause-level state machine is documented as:

> `0 = active, 1 = paused by admin, 2 = paused by protocol` [1](#0-0) 

The factory enforces these transitions:

| Caller | Function | Allowed `cur` | Sets to |
|---|---|---|---|
| Pool admin | `pausePool` | 0 | 1 |
| Pool admin | `unpausePool` | 1 | 0 |
| Protocol owner | `protocolPausePool` | 0 or 1 | 2 |
| Protocol owner | `protocolUnpausePool` | 2 | **1** ← bug |

`protocolUnpausePool` is implemented as:

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);   // ← writes 1, not 0
}
``` [2](#0-1) 

The `swap` function enforces `whenNotPaused`, which reverts whenever `pauseLevel != 0`: [3](#0-2) [4](#0-3) 

After `protocolUnpausePool` completes, `pauseLevel = 1`, so every `swap` call still reverts. The only recovery path is for the pool admin to call `unpausePool` (1 → 0): [5](#0-4) 

The protocol owner has no function that can write `pauseLevel = 0` directly. If the pool admin is unresponsive, the pool is permanently stuck in a broken swap state even though the protocol has "unpaused" it.

### Impact Explanation
Every call to `protocolUnpausePool` on a pool that was active before the protocol pause leaves the pool in admin-paused state. All `swap` calls revert with `PoolPaused`. `removeLiquidity` is unaffected (no `whenNotPaused` guard), so LP principal is not at risk, but the core swap flow is completely unusable until the admin acts. This matches the allowed impact: *"Broken core pool functionality causing... unusable... swap... flows."*

### Likelihood Explanation
The trigger is the protocol owner (semi-trusted) calling `protocolUnpausePool` — a routine administrative action after any emergency pause. The broken state is reached every time the protocol pauses an active pool and then unpauses it. The protocol owner may not realize the pool is still paused after the call returns successfully.

### Recommendation
`protocolUnpausePool` should restore the pool to active state (level 0), not admin-paused state (level 1):

```solidity
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0);   // restore to active
}
```

If the design intent is to preserve a pre-existing admin pause, the factory should record the pause level before `protocolPausePool` and restore it on `protocolUnpausePool`.

### Proof of Concept

```
1. Pool starts at pauseLevel = 0 (active). Swaps succeed.
2. Protocol owner calls protocolPausePool(pool)  → pauseLevel = 2.
3. Protocol owner calls protocolUnpausePool(pool) → pauseLevel = 1.
4. User calls pool.swap(...)  → reverts: PoolPaused.
5. Protocol owner has no function to set pauseLevel = 0.
6. Pool admin must call unpausePool(pool) → pauseLevel = 0.
   If admin is unresponsive, pool is permanently broken for swaps.
``` [6](#0-5)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L71-72)
```text
  /// @dev 0 = active, 1 = paused by admin, 2 = paused by protocol. Transitions enforced by factory.
  uint8 internal pauseLevel;
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L467-471)
```text
  function unpausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 1) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0);
  }
```
