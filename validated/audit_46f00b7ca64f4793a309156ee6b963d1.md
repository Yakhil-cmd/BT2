### Title
LP Principal Permanently Frozen When Position Owner Is Blacklisted by USDC/USDT — (`metric-core/contracts/libraries/LiquidityLib.sol`)

### Summary

`removeLiquidity` hardcodes the token recipient as `owner` with no way to redirect funds to an alternative address. If the position owner is blacklisted by USDC or USDT after depositing, their LP principal is permanently locked in the pool.

### Finding Description

`MetricOmmPool.removeLiquidity` enforces `msg.sender == owner` and then delegates to `LiquidityLib.removeLiquidity`, which unconditionally transfers withdrawn tokens to `owner`:

```solidity
// MetricOmmPool.sol
function removeLiquidity(address owner, uint80 salt, LiquidityDelta calldata deltas, bytes calldata extensionData)
    external nonReentrant(PoolActions.REMOVE_LIQUIDITY)
    returns (uint256 amount0Removed, uint256 amount1Removed)
{
    ...
    if (msg.sender != owner) revert NotPositionOwner();
    ...
}
``` [1](#0-0) 

```solidity
// LiquidityLib.sol
if (amount0Removed > 0) {
    IERC20(ctx.token0).safeTransfer(owner, amount0Removed);
}
if (amount1Removed > 0) {
    IERC20(ctx.token1).safeTransfer(owner, amount1Removed);
}
``` [2](#0-1) 

There is no `recipient` parameter and no position-transfer mechanism (the protocol uses internal share accounting keyed by `owner` address with no LP token). Once `owner` is blacklisted by USDC or USDT, every call to `removeLiquidity` will revert inside `safeTransfer`, and there is no escape hatch.

### Impact Explanation

The LP's entire deposited principal (token0 and/or token1) is permanently frozen inside the pool contract. The pool's `binTotals` accounting is decremented correctly, but the `safeTransfer` reverts, so the tokens remain in the pool with no claimant. This is a direct, irrecoverable loss of user principal.

### Likelihood Explanation

USDC and USDT both implement address blacklisting. The Metric OMM protocol is designed to support any ERC-20 pair permissionlessly, explicitly including USDC/USDT. Blacklisting of an LP address is a low-probability event (e.g., regulatory action, sanctions compliance), but the consequence is total and permanent loss of principal with no recovery path. This matches the Medium severity threshold used in the reference report.

### Recommendation

Add an optional `recipient` parameter to `removeLiquidity` (defaulting to `owner` when omitted), so the position owner can redirect withdrawn tokens to a non-blacklisted address:

```solidity
function removeLiquidity(
    address owner,
    address recipient,   // <-- new
    uint80 salt,
    LiquidityDelta calldata deltas,
    bytes calldata extensionData
) external nonReentrant(PoolActions.REMOVE_LIQUIDITY) ...
```

Pass `recipient` through to `LiquidityLib.removeLiquidity` and replace `safeTransfer(owner, ...)` with `safeTransfer(recipient, ...)`. The `msg.sender == owner` ownership check remains unchanged.

### Proof of Concept

1. Alice (an EOA) adds liquidity to a USDC/WETH pool. Her position is recorded under `owner = Alice`.
2. Alice is later added to the USDC blacklist.
3. Alice calls `removeLiquidity(Alice, salt, deltas, "")`.
4. `MetricOmmPool` passes the call to `LiquidityLib.removeLiquidity`, which correctly computes `amount0Removed` (USDC) and decrements bin state.
5. `IERC20(USDC).safeTransfer(Alice, amount0Removed)` reverts because Alice is blacklisted.
6. The entire transaction reverts; bin state is rolled back. Alice's shares remain in the pool.
7. Alice has no alternative: she cannot change `owner`, there are no LP tokens to transfer, and `removeLiquidity` always sends to `owner`. Her USDC principal is permanently frozen.

### Citations

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

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L242-247)
```text
      if (amount0Removed > 0) {
        IERC20(ctx.token0).safeTransfer(owner, amount0Removed);
      }
      if (amount1Removed > 0) {
        IERC20(ctx.token1).safeTransfer(owner, amount1Removed);
      }
```
