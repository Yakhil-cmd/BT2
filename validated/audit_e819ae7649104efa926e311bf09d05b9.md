### Title
LP Funds Permanently Frozen When Position Owner Is Blacklisted by Token Contract — (`metric-core/contracts/MetricOmmPool.sol`)

### Summary

`removeLiquidity` transfers withdrawn tokens directly to the `owner` address with no `recipient` parameter. If the LP's address is blacklisted by token0 or token1 (e.g., USDC), every attempt to withdraw reverts at the token transfer step, permanently locking the LP's principal in the pool.

### Finding Description

`removeLiquidity` enforces `msg.sender == owner` and then delegates to `LiquidityLib.removeLiquidity`, which transfers the recovered token amounts back to `owner`. The function signature accepts no `recipient` argument:

```solidity
function removeLiquidity(
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    bytes calldata extensionData
) external nonReentrant(PoolActions.REMOVE_LIQUIDITY)
    returns (uint256 amount0Removed, uint256 amount1Removed)
``` [1](#0-0) 

Unlike `addLiquidity`, which carries a `callbackData` parameter that lets the caller control token routing, `removeLiquidity` has no equivalent escape hatch. If token0 or token1 is a contract with a blacklist (USDC, USDT), and the `owner` address is added to that blacklist after depositing, every `safeTransfer` to `owner` will revert unconditionally. There is no factory-level function analogous to `setPoolAdminFeeDestination` that would let an LP migrate their position claim to a different address. [2](#0-1) 

The `collectFees` path does not share this problem: `poolAdminFeeDestination` is mutable via `setPoolAdminFeeDestination`, so a blacklisted admin fee destination can be rotated. [3](#0-2) 

No equivalent escape exists for LP positions.

### Impact Explanation

An LP whose address is blacklisted by the pool's token contract loses their entire deposited principal. The funds remain locked in the pool's bin accounting indefinitely — `binTotals` and `_positionBinShares` still record the position, but every withdrawal attempt reverts. No admin or factory path can force-transfer the position to a different address.

### Likelihood Explanation

Blacklisting by USDC/USDT is a real, documented event (e.g., OFAC-sanctioned addresses). Metric OMM pools are explicitly designed to support arbitrary ERC-20 pairs including USDC and USDT. The probability for any individual LP is low, but the impact when it occurs is total loss of principal, matching the Medium severity threshold used in the reference report.

### Recommendation

Add a `recipient` parameter to `removeLiquidity` and pass it through to `LiquidityLib.removeLiquidity` for the token transfer destination. Restrict its use so that only `msg.sender == owner` may redirect to an arbitrary recipient:

```diff
 function removeLiquidity(
     address owner,
     uint80 salt,
     LiquidityDelta calldata deltas,
+    address recipient,
     bytes calldata extensionData
 ) external nonReentrant(PoolActions.REMOVE_LIQUIDITY)
     returns (uint256 amount0Removed, uint256 amount1Removed)
 {
     if (deltas.binIdxs.length == 0) return (0, 0);
     if (deltas.binIdxs.length != deltas.shares.length) revert LiquidityDeltaLengthMismatch();
     if (msg.sender != owner) revert NotPositionOwner();
+    if (recipient == address(0)) recipient = owner;
     ...
     (amount0Removed, amount1Removed) = LiquidityLib.removeLiquidity(
-        _liquidityContext(), owner, salt, deltas, ...
+        _liquidityContext(), owner, salt, deltas, recipient, ...
     );
```

### Proof of Concept

1. Alice provides liquidity to a USDC/WETH pool; her address is recorded as `owner` in `_positionBinShares`.
2. Alice's address is added to USDC's blacklist (e.g., OFAC sanction).
3. Alice calls `removeLiquidity` with her own address.
4. `LiquidityLib.removeLiquidity` computes `amount0Removed` and calls `IERC20(TOKEN0).safeTransfer(owner, amount0Removed)`.
5. USDC's `transfer` reverts because `owner` is blacklisted.
6. The transaction reverts; Alice's shares remain in `_positionBinShares` and her tokens remain in `binTotals`. No factory or admin function can rescue them. [1](#0-0)

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

**File:** metric-core/contracts/MetricOmmPool.sol (L565-571)
```text
  function transferToken0(address to, uint256 amount) internal {
    IERC20(TOKEN0).safeTransfer(to, amount);
  }

  function transferToken1(address to, uint256 amount) internal {
    IERC20(TOKEN1).safeTransfer(to, amount);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L438-447)
```text
  function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
  }
```
