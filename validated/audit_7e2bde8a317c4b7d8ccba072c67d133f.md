### Title
Lack of Minimum Output Protection in `removeLiquidity` Exposes LPs to Front-Running and Composition Drift — (`metric-core/contracts/MetricOmmPool.sol`)

### Summary
`MetricOmmPool.removeLiquidity` burns an exact number of shares per bin but provides no `minAmount0` / `minAmount1` guard. Because each bin's token composition changes as swaps traverse it, an LP who submits a removal transaction can receive materially fewer tokens than they observed on-chain when they built the transaction.

### Finding Description
`removeLiquidity` accepts a `LiquidityDelta` (per-bin share counts) and returns the tokens those shares are worth at execution time:

```solidity
// MetricOmmPool.sol
function removeLiquidity(address owner, uint80 salt, LiquidityDelta calldata deltas, bytes calldata extensionData)
    external
    nonReentrant(PoolActions.REMOVE_LIQUIDITY)
    returns (uint256 amount0Removed, uint256 amount1Removed)
{
    ...
    (amount0Removed, amount1Removed) = LiquidityLib.removeLiquidity(
      _liquidityContext(), owner, salt, deltas, binTotals, _binStates, _binTotalShares, _positionBinShares
    );
    _afterRemoveLiquidity(...);
}
``` [1](#0-0) 

The token amounts returned are proportional to each bin's current `token0BalanceScaled` / `token1BalanceScaled`:

```solidity
// BinState fields consumed by LiquidityLib.removeLiquidity
token0BalanceScaled: 0, token1BalanceScaled: 0, lengthE6: length, ...
``` [2](#0-1) 

These balances change with every swap that traverses the bin. There is no periphery wrapper for `removeLiquidity` — unlike `addLiquidity`, which is routed through `MetricOmmPoolLiquidityAdder` and enforces `maxAmountToken0` / `maxAmountToken1` caps in the callback:

```solidity
if (amount0Delta > max0 || amount1Delta > max1) {
    revert MaxAmountExceeded(amount0Delta, amount1Delta, max0, max1);
}
``` [3](#0-2) 

No equivalent protection exists on the output side of `removeLiquidity`. The function also accepts no deadline parameter, so a pending transaction can sit in the mempool indefinitely while the pool state drifts.

### Impact Explanation
An LP who observes bin state off-chain, decides to remove shares expecting ≥ X tokens, and submits the transaction can receive arbitrarily fewer tokens if one or more swaps execute first and drain the bin of the token the LP expected. Because `removeLiquidity` is called directly on the pool with no minimum-output guard, the LP has no on-chain recourse. This is a direct loss of owed LP assets.

### Likelihood Explanation
Any active pool will have swaps interleaved with liquidity removals. A searcher who sees a `removeLiquidity` transaction in the mempool can sandwich it with a swap that shifts the bin composition, causing the LP to receive a worse token mix. No special privilege is required; any caller can trigger a swap.

### Recommendation
Add `minAmount0` and `minAmount1` parameters to `removeLiquidity` (or to a periphery wrapper) and revert if the actual output falls below the caller-specified floor:

```solidity
function removeLiquidity(
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    uint256 minAmount0,
    uint256 minAmount1,
    bytes calldata extensionData
) external ... returns (uint256 amount0Removed, uint256 amount1Removed) {
    ...
    if (amount0Removed < minAmount0 || amount1Removed < minAmount1)
        revert InsufficientOutput(amount0Removed, amount1Removed, minAmount0, minAmount1);
}
```

Alternatively, a periphery `MetricOmmPoolLiquidityRemover` contract (mirroring `MetricOmmPoolLiquidityAdder`) can enforce these checks without changing the core pool interface.

### Proof of Concept
1. Bin 0 holds 1 000 token0 and 1 000 token1 across 10 000 total shares.
2. LP owns 5 000 shares; off-chain preview shows ~500 token0 + 500 token1.
3. LP submits `removeLiquidity({binIdxs:[0], shares:[5000]}, ...)`.
4. Before the LP's tx lands, a searcher executes a large `zeroForOne` swap that buys all token1 from bin 0, leaving bin 0 with 2 000 token0 and 0 token1.
5. LP's tx executes: 5 000 / 10 000 × 2 000 token0 = 1 000 token0, 0 token1.
6. LP receives 1 000 token0 and 0 token1 instead of the expected 500/500 split. If the LP required token1 (e.g., to repay a loan), they suffer a direct shortfall with no on-chain protection. [1](#0-0)

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L628-631)
```text
          nonNegativeBinStates[k] = BinState({
            token0BalanceScaled: 0, token1BalanceScaled: 0, lengthE6: length, addFeeBuyE6: buyFee, addFeeSellE6: sellFee
          });
          k++;
```

**File:** metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol (L165-167)
```text
    if (amount0Delta > max0 || amount1Delta > max1) {
      revert MaxAmountExceeded(amount0Delta, amount1Delta, max0, max1);
    }
```
