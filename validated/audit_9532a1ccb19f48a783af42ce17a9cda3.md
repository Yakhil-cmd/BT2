### Title
`DepositAllowlistExtension` checks caller-controlled `owner` instead of actual `sender`, allowing allowlist bypass — (File: `metric-periphery/contracts/extensions/DepositAllowlistExtension.sol`)

---

### Summary

`DepositAllowlistExtension.beforeAddLiquidity` silently ignores the `sender` argument (the actual `msg.sender` of `addLiquidity`) and instead gates access on the caller-controlled `owner` parameter. Any address not on the allowlist can bypass the deposit restriction by supplying an allowlisted address as `owner`.

---

### Finding Description

`MetricOmmPool.addLiquidity` accepts a caller-supplied `owner` (the position beneficiary) and passes both the real caller and the owner to the extension hook:

```solidity
// MetricOmmPool.sol – addLiquidity
_beforeAddLiquidity(msg.sender, owner, salt, deltas, extensionData);
``` [1](#0-0) 

`ExtensionCalling._beforeAddLiquidity` faithfully forwards both values:

```solidity
abi.encodeCall(IMetricOmmExtensions.beforeAddLiquidity, (sender, owner, salt, deltas, extensionData))
``` [2](#0-1) 

`DepositAllowlistExtension.beforeAddLiquidity` then discards `sender` entirely (unnamed first parameter) and checks only `owner`:

```solidity
function beforeAddLiquidity(address, address owner, uint80, LiquidityDelta calldata, bytes calldata)
    external view override returns (bytes4)
{
    if (!allowAllDepositors[msg.sender] && !allowedDepositor[msg.sender][owner]) {
        revert IMetricOmmPoolActions.NotAllowedToDeposit();
    }
    ...
}
``` [3](#0-2) 

The sibling `SwapAllowlistExtension.beforeSwap` does the opposite — it checks `sender` (the actual caller) and discards `recipient`:

```solidity
function beforeSwap(address sender, address, ...) external view override returns (bytes4) {
    if (!allowAllSwappers[msg.sender] && !allowedSwapper[msg.sender][sender]) {
        revert IMetricOmmPoolActions.NotAllowedToSwap();
    }
``` [4](#0-3) 

The public API naming (`setAllowedToDeposit`, `depositor`) and the parallel with `SwapAllowlistExtension` both confirm the intended invariant is **restricting the caller**, not the position beneficiary. The implementation inverts this: it restricts the beneficiary while leaving the caller unchecked.

---

### Impact Explanation

A pool admin deploys `DepositAllowlistExtension` to create a permissioned liquidity pool where only approved addresses may deposit. An attacker who is **not** on the allowlist calls:

```
pool.addLiquidity(owner = allowlisted_address, ...)
```

The extension evaluates `allowedDepositor[pool][allowlisted_address]` → `true` and does not revert. The attacker's callback pays the tokens; the position is credited to `allowlisted_address`. The allowlist gate — the pool admin's sole mechanism for controlling who can provide liquidity — is completely bypassed by any external caller. The pool admin's access-control boundary is broken by an unprivileged path.

---

### Likelihood Explanation

The trigger is a single permissionless call to `addLiquidity` with `owner` set to any address already on the allowlist. No special role, no flash loan, no prior state is required. Any address can execute this at any time against any pool using `DepositAllowlistExtension`.

---

### Recommendation

Check `sender` (the actual depositor) instead of `owner` in `beforeAddLiquidity`, mirroring `SwapAllowlistExtension`:

```solidity
function beforeAddLiquidity(address sender, address, uint80, LiquidityDelta calldata, bytes calldata)
    external view override returns (bytes4)
{
    if (!allowAllDepositors[msg.sender] && !allowedDepositor[msg.sender][sender]) {
        revert IMetricOmmPoolActions.NotAllowedToDeposit();
    }
    return IMetricOmmExtensions.beforeAddLiquidity.selector;
}
``` [3](#0-2) 

---

### Proof of Concept

1. Pool is deployed with `DepositAllowlistExtension`; only `alice` is added via `setAllowedToDeposit(pool, alice, true)`.
2. `bob` (not on allowlist) calls `pool.addLiquidity(owner=alice, salt=0, deltas=..., callbackData=..., extensionData="")`.
3. `beforeAddLiquidity` is invoked with `sender=bob`, `owner=alice`.
4. Extension evaluates `allowedDepositor[pool][alice]` → `true`; no revert.
5. `bob`'s callback transfers tokens into the pool; the position is recorded under `alice`.
6. `bob` has successfully deposited into a pool that was supposed to reject him. The allowlist is defeated. [5](#0-4) [6](#0-5)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L182-196)
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
```

**File:** metric-core/contracts/ExtensionCalling.sol (L95-98)
```text
    _callExtensionsInOrder(
      BEFORE_ADD_LIQUIDITY_ORDER,
      abi.encodeCall(IMetricOmmExtensions.beforeAddLiquidity, (sender, owner, salt, deltas, extensionData))
    );
```

**File:** metric-periphery/contracts/extensions/DepositAllowlistExtension.sol (L17-42)
```text

  function setAllowedToDeposit(address pool_, address depositor, bool allowed) external onlyPoolAdmin(pool_) {
    allowedDepositor[pool_][depositor] = allowed;
    emit AllowedToDepositSet(pool_, depositor, allowed);
  }

  function setAllowAllDepositors(address pool_, bool allowed) external onlyPoolAdmin(pool_) {
    allowAllDepositors[pool_] = allowed;
    emit AllowAllDepositorsSet(pool_, allowed);
  }

  function isAllowedToDeposit(address pool_, address depositor) external view returns (bool) {
    return allowAllDepositors[pool_] || allowedDepositor[pool_][depositor];
  }

  function beforeAddLiquidity(address, address owner, uint80, LiquidityDelta calldata, bytes calldata)
    external
    view
    override
    returns (bytes4)
  {
    if (!allowAllDepositors[msg.sender] && !allowedDepositor[msg.sender][owner]) {
      revert IMetricOmmPoolActions.NotAllowedToDeposit();
    }
    return IMetricOmmExtensions.beforeAddLiquidity.selector;
  }
```

**File:** metric-periphery/contracts/extensions/SwapAllowlistExtension.sol (L31-41)
```text
  function beforeSwap(address sender, address, bool, int128, uint128, uint256, uint128, uint128, bytes calldata)
    external
    view
    override
    returns (bytes4)
  {
    if (!allowAllSwappers[msg.sender] && !allowedSwapper[msg.sender][sender]) {
      revert IMetricOmmPoolActions.NotAllowedToSwap();
    }
    return IMetricOmmExtensions.beforeSwap.selector;
  }
```
