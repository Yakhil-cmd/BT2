### Title
Paused pool allows `addLiquidity` and `removeLiquidity` to execute, bypassing the pause invariant — (File: `metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

The `whenNotPaused` modifier is applied exclusively to `swap()`. Both `addLiquidity()` and `removeLiquidity()` lack this guard, so any LP can add or remove liquidity from a pool at any pause level (1 = admin-paused, 2 = protocol-paused). This is the direct Metric OMM analog of the Astaria shutdown-bypass: the pause flag is set and read by the factory, but the pool's liquidity entry-points never consult it.

---

### Finding Description

`MetricOmmPool` stores a `pauseLevel` (0 = active, 1 = admin-paused, 2 = protocol-paused) and enforces it through `_checkNotPaused()`:

```solidity
function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
}
``` [1](#0-0) 

The `whenNotPaused` modifier wraps only `swap()`:

```solidity
function swap(...) external whenNotPaused nonReentrant(PoolActions.SWAP) ...
``` [2](#0-1) 

`addLiquidity()` and `removeLiquidity()` carry no such guard:

```solidity
function addLiquidity(...) external nonReentrant(PoolActions.ADD_LIQUIDITY) ...
function removeLiquidity(...) external nonReentrant(PoolActions.REMOVE_LIQUIDITY) ...
``` [3](#0-2) 

The factory's `pausePool` and `protocolPausePool` read `pauseLevel` via `PoolStateLibrary._slot0` and set it, but the pool itself never checks it inside the liquidity paths:

```solidity
function pausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);
}
``` [4](#0-3) 

---

### Impact Explanation

When a pool is paused in response to a security incident (e.g., oracle manipulation, extension-hook exploit, or corrupted bin accounting caused by a swap-path bug), the pause only blocks further swaps. `removeLiquidity` remains callable, allowing:

1. **Informed LPs to exit ahead of uninformed LPs** — if the pause was triggered because pool accounting is corrupted, an attacker who caused the corruption can immediately call `removeLiquidity` to withdraw more than their proportional share before the pool is drained or fixed, directly taking other LPs' principal.
2. **`addLiquidity` extension hooks remain reachable** — `_beforeAddLiquidity` / `_afterAddLiquidity` invoke extension callbacks even during a pause, so any extension-level vulnerability the pause was meant to contain is still exploitable through the liquidity path. [5](#0-4) 

This matches the "broken core pool functionality causing loss of funds" criterion: the pause mechanism — the primary emergency brake — does not freeze fund-moving operations as intended.

---

### Likelihood Explanation

- The pool admin or protocol owner must first pause the pool (a semi-trusted, valid action within scope).
- Any LP with an existing position can immediately call `removeLiquidity` — no special privilege required.
- The window is the entire duration the pool remains paused, which can be hours or days during an incident response.

---

### Recommendation

Apply `whenNotPaused` to both `addLiquidity` and `removeLiquidity`:

```solidity
function addLiquidity(...) external whenNotPaused nonReentrant(PoolActions.ADD_LIQUIDITY) ...
function removeLiquidity(...) external whenNotPaused nonReentrant(PoolActions.REMOVE_LIQUIDITY) ...
``` [6](#0-5) 

---

### Proof of Concept

1. LP adds liquidity to an active pool (level 0).
2. Pool admin detects an anomaly and calls `factory.pausePool(pool)` → `pauseLevel` becomes 1.
3. Any call to `pool.swap(...)` reverts with `PoolPaused`.
4. The same LP (or an attacker who holds shares) calls `pool.removeLiquidity(owner, salt, deltas, "")` — **succeeds**, withdrawing token0 and token1 from the paused pool.
5. Protocol fees and other LPs' principal are exposed to the same drain path for the entire pause duration. [7](#0-6)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L174-177)
```text
  modifier whenNotPaused() {
    _checkNotPaused();
    _;
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L182-212)
```text
  function addLiquidity(
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    bytes calldata callbackData,
    bytes calldata extensionData
  ) external nonReentrant(PoolActions.ADD_LIQUIDITY) returns (uint256 amount0Added, uint256 amount1Added) {
    if (deltas.binIdxs.length == 0) return (0, 0);
    if (deltas.binIdxs.length != deltas.shares.length) revert LiquidityDeltaLengthMismatch();
    _beforeAddLiquidity(msg.sender, owner, salt, deltas, extensionData);
    (amount0Added, amount1Added) = LiquidityLib.addLiquidity(
      _liquidityContext(), owner, salt, deltas, callbackData, binTotals, _binStates, _binTotalShares, _positionBinShares
    );
    _afterAddLiquidity(msg.sender, owner, salt, deltas, amount0Added, amount1Added, extensionData);
  }

  /// @inheritdoc IMetricOmmPoolActions
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L460-464)
```text
  function pausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);
  }
```
