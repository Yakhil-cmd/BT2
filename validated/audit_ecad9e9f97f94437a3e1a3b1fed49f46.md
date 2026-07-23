### Title
Missing `whenNotPaused` on `addLiquidity` allows fund deposits into paused pools — (`metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

The `whenNotPaused` modifier is defined in `MetricOmmPool` and applied to `swap`, but is absent from `addLiquidity`. This allows any user to deposit tokens into a pool that has been paused for safety reasons, directly analogous to the external bug's pattern of a guard that exists but is not invoked on all critical paths.

---

### Finding Description

`MetricOmmPool` defines a `whenNotPaused` modifier backed by `_checkNotPaused()`: [1](#0-0) [2](#0-1) 

The modifier is correctly applied to `swap`: [3](#0-2) 

But `addLiquidity` carries only `nonReentrant(PoolActions.ADD_LIQUIDITY)` — `whenNotPaused` is absent: [4](#0-3) 

The factory exposes two pause paths — pool-admin pause (level 1) and protocol pause (level 2) — both of which are intended to halt pool interaction during a safety incident: [5](#0-4) [6](#0-5) 

Despite either pause level being active (`pauseLevel != 0`), `addLiquidity` executes fully: it calls `_beforeAddLiquidity` (extension hooks), runs `LiquidityLib.addLiquidity` to credit shares and pull tokens via callback, and calls `_afterAddLiquidity`: [7](#0-6) 

The guard exists, is imported, and is wired to the pause state — it is simply never invoked on the deposit path.

---

### Impact Explanation

When a pool is paused due to a security incident (e.g., oracle manipulation, accounting discrepancy, or a compromised extension), the pause is intended to freeze all user-facing interactions that can result in fund movement. Because `addLiquidity` bypasses this freeze, users can deposit tokens into a pool whose internal state is known to be unsafe. Specifically:

- If the pool was paused because the price oracle is returning manipulated values, a user who adds liquidity during the pause deposits tokens that will be priced against the manipulated oracle once the pool is unpaused, resulting in direct loss of deposited principal.
- Extension hooks (`_beforeAddLiquidity`, `_afterAddLiquidity`) are still executed during the paused state, meaning any extension that relies on the pause invariant (e.g., to gate accounting side-effects) is also bypassed.

The corrupted value is the user's deposited token balance: tokens enter the pool's accounting (`binTotals.scaledToken0/1`) during a window when the pool's safety invariants are known to be violated.

---

### Likelihood Explanation

- A pool being paused is an explicit, reachable operational state triggered by either the pool admin or the protocol owner — not a hypothetical.
- `addLiquidity` is a standard, permissionless user action with no access control; any address can call it.
- A user or bot unaware of the pause (or acting on stale UI state) can trivially trigger this path.
- The trigger requires no privileged access, no malicious token, and no non-standard ERC20 behavior.

---

### Recommendation

Apply `whenNotPaused` to `addLiquidity` in `MetricOmmPool.sol`:

```solidity
function addLiquidity(
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    bytes calldata callbackData,
    bytes calldata extensionData
-) external nonReentrant(PoolActions.ADD_LIQUIDITY) returns (uint256 amount0Added, uint256 amount1Added) {
+) external whenNotPaused nonReentrant(PoolActions.ADD_LIQUIDITY) returns (uint256 amount0Added, uint256 amount1Added) {
```

`removeLiquidity` intentionally omits `whenNotPaused` to allow LP exits during a pause — that asymmetry is correct. Only the deposit direction needs the guard.

---

### Proof of Concept

1. Pool is deployed and active (`pauseLevel == 0`).
2. A price oracle anomaly is detected; the protocol owner calls `protocolPausePool(pool)`, setting `pauseLevel = 2`.
3. Any call to `swap` now reverts with `PoolPaused`.
4. An unsuspecting user (or a bot) calls `addLiquidity` on the same pool — the call **succeeds** because `whenNotPaused` is absent. Tokens are transferred from the user into the pool via the liquidity callback and credited to `binTotals`.
5. The protocol investigates, fixes the oracle, and calls `protocolUnpausePool(pool)`.
6. Swaps resume against the (previously manipulated) bin state. The user's newly deposited tokens are now subject to the distorted accounting, and the user suffers a loss on removal that would not have occurred had the deposit been blocked during the pause.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L174-177)
```text
  modifier whenNotPaused() {
    _checkNotPaused();
    _;
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L188-188)
```text
  ) external nonReentrant(PoolActions.ADD_LIQUIDITY) returns (uint256 amount0Added, uint256 amount1Added) {
```

**File:** metric-core/contracts/MetricOmmPool.sol (L191-195)
```text
    _beforeAddLiquidity(msg.sender, owner, salt, deltas, extensionData);
    (amount0Added, amount1Added) = LiquidityLib.addLiquidity(
      _liquidityContext(), owner, salt, deltas, callbackData, binTotals, _binStates, _binTotalShares, _positionBinShares
    );
    _afterAddLiquidity(msg.sender, owner, salt, deltas, amount0Added, amount1Added, extensionData);
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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L392-396)
```text
  function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
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
