Looking at the factory's pause transition logic in `MetricOmmPoolFactory.sol`, I can identify a direct analog to the external bug.

---

### Title
`protocolUnpausePool` Unconditionally Overwrites Pre-Pause State, Leaving Previously-Active Pools Permanently Admin-Paused After Protocol Unpause — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`protocolUnpausePool` always sets the pool's pause level to `1` (admin-paused) regardless of what the pool's pause level was before the protocol pause. When the protocol pauses a pool that was at level `0` (active) and then unpauses it, the pool ends up at level `1` (admin-paused) — still fully paused — requiring an additional, unsolicited admin action to restore swap functionality.

### Finding Description

The pool has three pause levels:
- `0` = active (swaps allowed)
- `1` = paused by admin
- `2` = paused by protocol

`protocolPausePool` accepts pools at **either** level `0` or level `1` as valid pre-conditions: [1](#0-0) 

`protocolUnpausePool` unconditionally transitions to level `1`, not back to the pool's original state: [2](#0-1) 

`_checkNotPaused` in the pool reverts for **any** non-zero pause level: [3](#0-2) 

The factory stores no record of the pre-protocol-pause level. The relevant factory state variables are `poolAdmin`, `poolFeeConfig`, `priceProviderTimelock`, etc. — none of which capture the pause level at the time of protocol pause: [4](#0-3) 

**Concrete broken invariant:** A pool at level `0` (active) is protocol-paused to level `2`. The protocol then calls `protocolUnpausePool`. The pool lands at level `1` — still paused — even though it was fully active before the protocol intervened. The pool admin, who never called `pausePool`, now finds their pool in an admin-paused state they did not initiate and must explicitly call `unpausePool` to restore swap functionality.

This is the direct analog to the external bug: just as `early_withdraw_fixed` zeroed `tick_lower`/`tick_upper`/`fixed_side_capacity` that were set by a different function (vault creation), `protocolUnpausePool` writes a pause level (`1`) that was set by a different actor (the admin), overwriting the pool's actual pre-pause configuration.

### Impact Explanation

After any protocol pause/unpause cycle on a pool that was previously active, all swaps remain blocked. The `whenNotPaused` modifier on `swap` reverts for `pauseLevel != 0`, so level `1` is functionally identical to level `2` from a user perspective. LPs cannot trade, arbitrageurs cannot rebalance, and the pool accumulates price drift against the oracle until the admin notices and manually unpauses. This is broken core pool functionality matching the allowed impact gate.

### Likelihood Explanation

The protocol owner is expected to pause pools in emergency situations (e.g., oracle manipulation, exploit response). The most common target is an active pool (level `0`). Every such pause/unpause cycle silently leaves the pool admin-paused. The admin has no on-chain notification; they must poll state or monitor events to discover the residual level-`1` state.

### Recommendation

The factory should record the pre-protocol-pause level and restore it on unpause:

```solidity
mapping(address => uint8) public prePausePauseLevel;

function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    prePausePauseLevel[pool] = cur;          // save original level
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}

function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 0);
    uint8 restore = prePausePauseLevel[pool]; // restore original level
    delete prePausePauseLevel[pool];
    IMetricOmmPoolFactoryActions(pool).setPause(restore);
}
```

### Proof of Concept

1. Pool is deployed and active: `pauseLevel = 0`.
2. Protocol owner calls `protocolPausePool(pool)` → `pauseLevel = 2`. Pool is paused.
3. Emergency resolved; protocol owner calls `protocolUnpausePool(pool)` → `pauseLevel = 1`. Pool is **still paused**.
4. Any call to `swap(...)` reverts with `PoolPaused()` because `pauseLevel != 0`.
5. Pool admin, who never called `pausePool`, must now call `unpausePool(pool)` to bring `pauseLevel` back to `0`.
6. Until the admin acts, all LP positions are illiquid and all swap flows are broken.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L71-99)
```text
  mapping(address => address) public override poolAdmin;

  /// @inheritdoc IMetricOmmPoolFactory
  mapping(address => address) public override pendingPoolAdmin;

  /// @inheritdoc IMetricOmmPoolFactory
  mapping(address => address) public override pendingPriceProvider;

  /// @inheritdoc IMetricOmmPoolFactory
  mapping(address => uint256) public override pendingPriceProviderExecuteAfter;

  /// @inheritdoc IMetricOmmPoolFactory
  mapping(address => uint256) public override priceProviderTimelock;

  /// @inheritdoc IMetricOmmPoolFactory
  mapping(address => PoolFeeConfig) public override poolFeeConfig;

  /// @inheritdoc IMetricOmmPoolFactory
  mapping(address => address) public override poolAdminFeeDestination;

  /// @inheritdoc IMetricOmmPoolFactory
  uint256 public override nextPoolIdx;

  /// @inheritdoc IMetricOmmPoolFactory
  mapping(uint256 => address) public override idxToPool;

  /// @inheritdoc IMetricOmmPoolFactory
  mapping(address => uint256) public override poolToIdx;

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

**File:** metric-core/contracts/MetricOmmPool.sol (L643-645)
```text
  function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
  }
```
