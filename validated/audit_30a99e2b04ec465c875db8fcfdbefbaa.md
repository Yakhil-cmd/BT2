### Title
Pool Admin Can Permanently Block Swaps That Factory Owner Cannot Override - (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

The three-level pause system (`0` = active, `1` = admin-paused, `2` = protocol-paused) is designed so that the factory owner (`onlyOwner`, governance equivalent) can never transition a pool directly to level `0`. Only the pool admin can do that via `unpausePool` (`1 → 0`). A malicious or uncooperative pool admin can therefore permanently block all swaps on a pool, and the factory owner has no path to override it.

### Finding Description

`MetricOmmPoolFactory` enforces the following pause transitions:

| Caller | Function | Allowed transition |
|---|---|---|
| Pool admin | `pausePool` | `0 → 1` |
| Pool admin | `unpausePool` | `1 → 0` |
| Factory owner | `protocolPausePool` | `0 or 1 → 2` |
| Factory owner | `protocolUnpausePool` | `2 → 1` | [1](#0-0) 

The factory owner's `protocolUnpausePool` is explicitly capped at level `1`, not `0`: [2](#0-1) 

The interface comment confirms this is the intended design:

> "Intentionally transitions only **2 → 1**. Full resume to level **0** requires the pool admin to call `unpausePool`." [3](#0-2) 

Because `_checkNotPaused` blocks swaps at any non-zero pause level, a pool at level `1` is fully swap-dead: [4](#0-3) 

The factory owner also has no path to forcibly replace the pool admin — `proposePoolAdminTransfer` and `cancelPoolAdminTransfer` are both `onlyPoolAdmin`: [5](#0-4) 

### Impact Explanation

A pool admin who pauses a pool (level `0 → 1`) and then refuses to call `unpausePool` leaves the pool permanently swap-blocked. The factory owner's only recourse is to escalate to level `2` (`protocolPausePool`) and then back to level `1` (`protocolUnpausePool`) — which changes nothing observable. There is no factory-owner function that reaches level `0`. All `swap` calls revert with `PoolPaused` indefinitely. `addLiquidity` and `removeLiquidity` are not gated by `whenNotPaused`, so LPs can exit, but the pool's core swap functionality is permanently broken.

### Likelihood Explanation

The scenario mirrors the external report exactly: a pool admin who observes that governance is about to replace them (via a proposed admin transfer they did not initiate) has a strong incentive to pause the pool before the new admin accepts. Because `proposePoolAdminTransfer` is callable only by the current pool admin, governance cannot initiate the replacement either — the current admin must cooperate. The pool admin therefore holds a unilateral veto over both swap resumption and admin succession.

### Recommendation

Add a factory-owner function that can transition a pool directly to level `0` (full resume), bypassing the pool admin's cooperation requirement. For example:

```solidity
function protocolForceUnpausePool(address pool) external onlyOwner nonReentrant {
    IMetricOmmPoolFactoryActions(pool).setPause(0);
}
```

Alternatively, allow `protocolUnpausePool` to accept a target level parameter so the owner can choose `0` or `1` depending on context. This gives governance the same authority over resumption that it already has over escalation.

### Proof of Concept

1. Pool is deployed with `poolAdmin = Alice`.
2. Governance (factory owner) proposes to replace Alice — but `proposePoolAdminTransfer` is `onlyPoolAdmin`, so governance cannot initiate this; Alice must cooperate.
3. Alice calls `pausePool(pool)` → pool transitions `0 → 1`; all `swap` calls now revert.
4. Factory owner calls `protocolPausePool(pool)` → `1 → 2`.
5. Factory owner calls `protocolUnpausePool(pool)` → `2 → 1`. Pool is still swap-blocked.
6. Factory owner has no further function to reach level `0`. Alice refuses to call `unpausePool`.
7. Pool remains permanently swap-dead. LPs can remove liquidity but no trading is possible. [6](#0-5) [1](#0-0) [7](#0-6)

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L510-534)
```text
  function proposePoolAdminTransfer(address pool, address newAdmin) external override nonReentrant onlyPoolAdmin(pool) {
    if (newAdmin == address(0)) revert InvalidAdmin();
    if (newAdmin == poolAdmin[pool]) revert InvalidAdmin();
    pendingPoolAdmin[pool] = newAdmin;
    emit PoolAdminTransferProposed(pool, poolAdmin[pool], newAdmin);
  }

  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
  function acceptPoolAdmin(address pool) external override nonReentrant {
    address pending = pendingPoolAdmin[pool];
    if (pending == address(0)) revert NoPendingPoolAdminTransfer();
    if (msg.sender != pending) revert NotPendingPoolAdmin(pool, msg.sender, pending);
    address previousAdmin = poolAdmin[pool];
    poolAdmin[pool] = pending;
    delete pendingPoolAdmin[pool];
    emit PoolAdminTransferred(pool, previousAdmin, pending);
  }

  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
  function cancelPoolAdminTransfer(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    address pending = pendingPoolAdmin[pool];
    if (pending == address(0)) revert NoPendingPoolAdminTransfer();
    delete pendingPoolAdmin[pool];
    emit PoolAdminTransferCancelled(pool, pending);
  }
```

**File:** metric-core/contracts/interfaces/IMetricOmmPoolFactory/IMetricOmmPoolFactoryOwner.sol (L65-67)
```text
  /// @notice Clear protocol pause on `pool` when allowed by pause rules.
  /// @dev Intentionally transitions only **2 → 1**. Full resume to level **0** requires the pool admin to call `unpausePool`.
  function protocolUnpausePool(address pool) external;
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
