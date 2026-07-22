### Title
Protocol Cannot Restore Pool to Active State Without Pool Admin Cooperation — Permanent Swap Deadlock if Admin Is Lost or Compromised - (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

The two-actor pause system in `MetricOmmPoolFactory` creates a governance deadlock: the factory owner (protocol) can only unpause a pool from level 2 to level 1, never directly to level 0. The sole path from level 1 to level 0 is `unpausePool`, which is exclusively callable by the pool admin. If the pool admin key is lost, the admin contract is bricked, or the admin is compromised and uncooperative, the factory owner has no mechanism to restore swap functionality. Swaps are permanently blocked for the affected pool with no protocol-level escape hatch.

---

### Finding Description

The pause state machine enforces strict, non-overlapping transitions between two actors:

| Transition | Caller |
|---|---|
| 0 → 1 | Pool admin (`pausePool`) |
| 1 → 0 | Pool admin (`unpausePool`) |
| 0 or 1 → 2 | Factory owner (`protocolPausePool`) |
| 2 → 1 | Factory owner (`protocolUnpausePool`) |

`protocolUnpausePool` hard-codes the target as level 1, never 0: [1](#0-0) 

`unpausePool` (the only 1→0 path) is gated by `onlyPoolAdmin`: [2](#0-1) 

`swap` enforces `whenNotPaused`, which reverts on any non-zero pause level: [3](#0-2) [4](#0-3) 

The factory owner also has no function to force-replace a pool admin. `proposePoolAdminTransfer` is callable only by the current pool admin, and `acceptPoolAdmin` requires the pending admin to call it: [5](#0-4) 

The deadlock sequence:
1. Pool is at level 0 (active).
2. Pool admin is compromised, lost, or bricked.
3. Factory owner calls `protocolPausePool` (0→2) then `protocolUnpausePool` (2→1). Pool is now at level 1.
4. Factory owner has no further lever: no function transitions 1→0 without pool admin.
5. Pool admin cannot or will not call `unpausePool`.
6. Swaps are permanently blocked.

The factory owner cannot escape this loop regardless of how many times it cycles through levels 2→1.

---

### Impact Explanation

`addLiquidity` and `removeLiquidity` are intentionally not gated by pause, so LP principal is not directly locked: [6](#0-5) 

However, `swap` is permanently unusable for the affected pool. This constitutes broken core pool functionality — the primary revenue-generating and price-discovery mechanism of the protocol is irrecoverably disabled with no on-chain remedy available to the protocol owner.

---

### Likelihood Explanation

The trigger requires the pool admin to become uncooperative: key loss, admin contract self-destruction, or a compromised admin that refuses to unpause. Pool admins are documented as semi-trusted and the guidelines recommend multisigs, but the protocol provides no fallback if that assumption fails. Because the factory owner has zero override capability, a single admin failure permanently bricks swap functionality for that pool.

---

### Recommendation

Add a factory-owner override that can transition directly from level 1 to level 0, bypassing the admin requirement after a sufficiently long safety delay (e.g., 7 days of inactivity at level 1). Alternatively, allow the factory owner to force-replace a pool admin via a timelocked proposal that does not require the current admin's cooperation. Either change preserves the intended two-actor consent model under normal operation while providing an escape hatch when the admin is irrecoverably lost.

```diff
// In MetricOmmPoolFactory:
+ uint256 public constant ADMIN_RECOVERY_DELAY = 7 days;
+ mapping(address => uint256) public adminRecoveryProposedAt;

+ function proposeAdminRecoveryUnpause(address pool) external onlyOwner {
+     require(_pauseLevel(pool) == 1, "Pool not at level 1");
+     adminRecoveryProposedAt[pool] = block.timestamp;
+ }

+ function executeAdminRecoveryUnpause(address pool) external onlyOwner {
+     require(block.timestamp >= adminRecoveryProposedAt[pool] + ADMIN_RECOVERY_DELAY);
+     require(_pauseLevel(pool) == 1, "Pool not at level 1");
+     IMetricOmmPoolFactoryActions(pool).setPause(0);
+ }
```

---

### Proof of Concept

```
State: pool at pauseLevel = 0, poolAdmin = 0xDEAD (lost key)

1. factory.owner calls protocolPausePool(pool)
   → pool.pauseLevel = 2  ✓

2. factory.owner calls protocolUnpausePool(pool)
   → pool.pauseLevel = 1  ✓

3. factory.owner attempts unpausePool(pool)
   → REVERT: NotPoolAdmin  ✗

4. factory.owner attempts proposePoolAdminTransfer(pool, newAdmin)
   → REVERT: NotPoolAdmin  ✗

5. Any user calls pool.swap(...)
   → REVERT: PoolPaused  ✗

Result: swap permanently blocked; no on-chain path to pauseLevel = 0 exists.
``` [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L399-403)
```text
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L509-526)
```text
  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
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

**File:** metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolActions.sol (L7-8)
```text
/// @notice User-facing mutators on Metric OMM pools: liquidity (shares per bin) and swap execution.
/// @dev State reads live on the concrete pool or libraries. Liquidity paths use native ERC20 amounts in callbacks; bin events carry scaled balances (`BinBalanceDelta`, see `PoolOperation.sol`). Successful `swap` consults the live price provider and is blocked when `pauseLevel != 0` (`PoolPaused`); `addLiquidity` / `removeLiquidity` are not gated by pause so ops policy can diverge (e.g. unwind while swaps are off).
```

**File:** metric-core/contracts/interfaces/IMetricOmmPoolFactory/IMetricOmmPoolFactoryOwner.sol (L62-67)
```text
  /// @notice Force pool to protocol pause level `2`.
  function protocolPausePool(address pool) external;

  /// @notice Clear protocol pause on `pool` when allowed by pause rules.
  /// @dev Intentionally transitions only **2 → 1**. Full resume to level **0** requires the pool admin to call `unpausePool`.
  function protocolUnpausePool(address pool) external;
```
