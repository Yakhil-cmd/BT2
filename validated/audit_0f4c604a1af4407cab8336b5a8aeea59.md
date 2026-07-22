Looking at the pause state machine in `MetricOmmPoolFactory.sol` and `MetricOmmPool.sol`, I can identify a structural analog to the EMPAM private-key grief bug.

---

### Title
Pool Admin Pause Creates Permanent Swap DoS With No Protocol Recovery Path — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
The three-level pause state machine enforces strict one-way transitions that leave the protocol owner with no path to force a pool from level 1 (admin-paused) back to level 0 (active). If the pool admin pauses the pool and then becomes unresponsive (lost keys, multisig quorum failure), swaps are permanently blocked with no on-chain remedy.

### Finding Description

The pool uses a `pauseLevel` variable with three states: 0 = active, 1 = paused by admin, 2 = paused by protocol. The `swap()` function is gated by `whenNotPaused`, which reverts on any non-zero pause level. [1](#0-0) [2](#0-1) [3](#0-2) 

The factory enforces these exact transitions:

| Caller | From | To | Function |
|---|---|---|---|
| Pool admin | 0 | 1 | `pausePool` |
| Pool admin | 1 | 0 | `unpausePool` |
| Protocol owner | 0 or 1 | 2 | `protocolPausePool` |
| Protocol owner | 2 | **1 only** | `protocolUnpausePool` | [4](#0-3) [5](#0-4) 

The critical gap: **the protocol owner cannot transition a pool from level 1 to level 0**. Only the pool admin can execute the 1→0 transition via `unpausePool`. If the pool admin pauses the pool and then becomes unresponsive, the protocol owner is trapped in an infinite loop:

1. Pool admin calls `pausePool(pool)` → level 0→1
2. Admin becomes unresponsive (lost key, multisig quorum failure)
3. Protocol owner calls `protocolUnpausePool(pool)` → **reverts** (`InvalidPauseTransition(1, 1)`) because `cur != 2`
4. Protocol owner calls `protocolPausePool(pool)` → level 1→2
5. Protocol owner calls `protocolUnpausePool(pool)` → level 2→1
6. Back to step 3 — swaps permanently blocked [6](#0-5) 

`removeLiquidity` does **not** carry `whenNotPaused`, so LP principal is not locked — but swap functionality is permanently destroyed. [7](#0-6) 

### Impact Explanation
Core swap functionality is permanently unusable. All traders are blocked from executing swaps against the pool. LPs cannot earn spread or notional fees. This satisfies the "unusable swap flows" criterion in the allowed impact gate.

### Likelihood Explanation
Pool admins are commonly multisigs. Multisig quorum failure (key holder unavailability, organizational changes) is a realistic and documented failure mode in DeFi. The pool admin pausing for maintenance is a normal operation; the inability to recover is the latent defect. No attacker action is required — the grief is triggered by a valid semi-trusted action (admin pause) followed by a realistic operational failure.

### Recommendation
Add a `protocolForceUnpausePool` function that allows the protocol owner to transition a pool directly from level 1 to level 0, bypassing the admin requirement. Alternatively, modify `protocolUnpausePool` to accept `cur == 1` as a valid source state and transition directly to 0.

```solidity
function protocolForceUnpausePool(address pool) external nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 1 && cur != 2) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0);
}
```

### Proof of Concept

```
State: pool at pauseLevel = 0 (active)

1. poolAdmin calls pausePool(pool)
   → pauseLevel = 1, swaps blocked

2. poolAdmin's multisig loses quorum (realistic: key holder unavailable)

3. protocolOwner calls protocolUnpausePool(pool)
   → reverts: InvalidPauseTransition(1, 1)  // cur==1, not 2

4. protocolOwner calls protocolPausePool(pool)
   → pauseLevel = 2

5. protocolOwner calls protocolUnpausePool(pool)
   → pauseLevel = 1  // back to step 3

Result: swap() permanently reverts with PoolPaused().
        removeLiquidity() still works (no whenNotPaused guard).
        No on-chain path exists to restore swaps.
```

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L174-177)
```text
  modifier whenNotPaused() {
    _checkNotPaused();
    _;
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L199-212)
```text
  function removeLiquidity(address owner, uint80 salt, LiquidityDelta calldata deltas, bytes calldata extensionData)
    external
    nonReentrant(PoolActions.REMOVE_LIQUIDITY)
    returns (uint256 amount0Removed, uint256 amount1Removed)
  {
    if (deltas.binIdxs.length == 0) return (0, 0);
    if (deltas.binIdxs.length != deltas.shares.length) revert LiquidityDeltaLengthMismatch();
    if (msg.sender != owner) revert NotPositionOwner();
    _beforeRemoveLiquidity(msg.sender, owner, salt, deltas, extensionData);
    (amount0Removed, amount1Removed) = LiquidityLib.removeLiquidity(
      _liquidityContext(), owner, salt, deltas, binTotals, _binStates, _binTotalShares, _positionBinShares
    );
    _afterRemoveLiquidity(msg.sender, owner, salt, deltas, amount0Removed, amount1Removed, extensionData);
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
