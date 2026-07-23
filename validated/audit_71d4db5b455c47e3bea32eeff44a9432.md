### Title
`protocolUnpausePool` Always Transitions to Admin-Paused Level 1, Leaving Previously-Active Pools Permanently Swap-Blocked Until Admin Intervenes — (`File: metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`protocolUnpausePool` unconditionally sets `pauseLevel` to `1` (admin-paused) regardless of the pool's pre-protocol-pause state. When the protocol pauses a pool that was fully active (`pauseLevel == 0`) and later unpauses it, the pool is left at `pauseLevel == 1`, which still blocks all swaps. The pool admin must separately call `unpausePool` to restore swap functionality — an action the admin never initiated and may not know is required.

---

### Finding Description

The pool tracks three pause states:

- `0` — active (swaps allowed)
- `1` — paused by admin
- `2` — paused by protocol [1](#0-0) 

`protocolPausePool` accepts pools at either level `0` or `1` and moves them to `2`: [2](#0-1) 

`protocolUnpausePool` always transitions from `2` to `1`, never to `0`: [3](#0-2) 

The `_checkNotPaused` guard blocks swaps for **any** non-zero `pauseLevel`: [4](#0-3) 

The `swap` function enforces this guard: [5](#0-4) 

The existing test `test_protocolPausePool_fromZero_skipsAdminLevel` explicitly documents this behavior — after protocol pause/unpause of an active pool, the pool lands at level `1` and the admin must call `unpausePool` to reach `0`: [6](#0-5) 

The admin's `unpausePool` only accepts `cur == 1` as a precondition, so it will succeed — but only if the admin is aware the pool is stuck and chooses to act: [7](#0-6) 

The state flag that was never set by the admin (`pauseLevel == 1`) is not cleared when the protocol "restores" the pool, directly mirroring the external bug where `isAddressCompromised` was not cleared on restoration.

---

### Impact Explanation

After `protocolUnpausePool` is called on a pool that was at `pauseLevel == 0` before the protocol pause:

- All `swap` calls revert with `PoolPaused` — core pool functionality is broken.
- LPs earn zero spread fees during the unexpected admin-pause window.
- Traders cannot execute against the pool.
- The pool admin must discover the unexpected state and submit a separate `unpausePool` transaction. If the admin is a multisig or DAO with governance delay, the pool can remain swap-blocked for an extended period with no on-chain mechanism to force recovery.

---

### Likelihood Explanation

This triggers every time the protocol pauses and then unpauses a pool that was in active state (`pauseLevel == 0`). Protocol pausing of active pools is a normal operational action (e.g., oracle incident, emergency). The condition requires no attacker — it is a consequence of the standard protocol owner workflow.

---

### Recommendation

`protocolUnpausePool` should restore the pool to the state it held **before** the protocol pause, not unconditionally to `1`. The factory should record the pre-protocol-pause level (either `0` or `1`) when `protocolPausePool` is called, and restore that level on `protocolUnpausePool`:

```solidity
// In factory storage:
mapping(address => uint8) public prePausedLevel;

function protocolPausePool(address pool) external onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    prePausedLevel[pool] = cur;          // record pre-pause state
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}

function protocolUnpausePool(address pool) external onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    uint8 restore = prePausedLevel[pool]; // 0 or 1
    delete prePausedLevel[pool];
    IMetricOmmPoolFactoryActions(pool).setPause(restore);
}
```

---

### Proof of Concept

The existing test already demonstrates the broken invariant:

```
1. Pool deployed → pauseLevel = 0 (active)
2. factory.protocolPausePool(pool)  → pauseLevel = 2
3. factory.protocolUnpausePool(pool) → pauseLevel = 1  ← still paused!
4. pool.swap(...)  → reverts PoolPaused
5. admin must call factory.unpausePool(pool) → pauseLevel = 0
``` [6](#0-5) 

Step 4 is the broken invariant: a pool the protocol declared "unpaused" still rejects all swaps, because `pauseLevel == 1` satisfies `pauseLevel != 0` in `_checkNotPaused`. [4](#0-3)

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

**File:** metric-core/test/MetricOmmPoolFactory.t.sol (L340-351)
```text
  function test_protocolPausePool_fromZero_skipsAdminLevel() public {
    address pool = _createPool();
    factory.protocolPausePool(pool);
    assertEq(_pauseLevel(pool), 2);

    factory.protocolUnpausePool(pool);
    assertEq(_pauseLevel(pool), 1);

    vm.prank(admin);
    factory.unpausePool(pool);
    assertEq(_pauseLevel(pool), 0);
  }
```
