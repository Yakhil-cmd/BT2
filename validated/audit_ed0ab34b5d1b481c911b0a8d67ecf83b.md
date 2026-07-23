### Title
LP Funds Permanently Locked When `removeLiquidity` Transfers to a USDC-Blacklisted Owner - (File: metric-core/contracts/libraries/LiquidityLib.sol)

---

### Summary

`LiquidityLib.removeLiquidity` transfers pool tokens directly to the position `owner` address. If that address is blacklisted by USDC (or any token with a transfer blacklist), every call to `removeLiquidity` reverts, permanently locking the LP's principal inside the pool with no recovery path.

---

### Finding Description

In `LiquidityLib.removeLiquidity`, after all share accounting is completed, the function performs direct `safeTransfer` calls to `owner`:

```solidity
if (amount0Removed > 0) {
    IERC20(ctx.token0).safeTransfer(owner, amount0Removed);
}
if (amount1Removed > 0) {
    IERC20(ctx.token1).safeTransfer(owner, amount1Removed);
}
``` [1](#0-0) 

`safeTransfer` reverts on failure. USDC implements a blacklist that causes `transfer` to revert when the recipient is a blocked address. If `owner` (which equals `msg.sender`, enforced by the pool) is blacklisted by USDC after depositing liquidity, every subsequent call to `removeLiquidity` will revert at the transfer step.

Because the share-accounting state updates (bin balance decrements, share burns) happen before the transfer and are rolled back on revert, the LP's position remains intact but permanently unwithdrawable:

```solidity
binState.token0BalanceScaled -= uint104(amount0Scaled);
binState.token1BalanceScaled -= uint104(amount1Scaled);
binTotalShares[binIdx] = binTotalSharesVal - sharesToRemove;
positionBinShares[posKey] = newUserShares;
``` [2](#0-1) 

There is no position-transfer mechanism, no alternative withdrawal path, and no admin rescue function. The pool enforces `msg.sender == owner`:

```solidity
if (msg.sender != owner) revert NotPositionOwner();
``` [3](#0-2) 

So no third party can withdraw on the LP's behalf.

---

### Impact Explanation

An LP who holds a position in any pool whose `token0` or `token1` is USDC (or USDT with a similar blacklist) and whose address is subsequently blacklisted by the token issuer loses their entire deposited principal permanently. The funds remain accounted for in `binTotals` and `binStates` but can never be extracted. This is a direct, irreversible loss of user principal with no on-chain recovery path.

---

### Likelihood Explanation

USDC blacklisting is an explicit in-scope token behavior per the contest rules. The trigger requires: (1) a USDC pool exists, (2) an LP has an active position, and (3) USDC's issuer blacklists that LP's address. Condition (3) is rare but not negligible — USDC has blacklisted hundreds of addresses for regulatory and sanctions reasons. No privileged action by the LP is required to trigger the lock; the blacklisting is imposed externally.

---

### Recommendation

Replace the push pattern with a pull pattern. Instead of transferring tokens directly to `owner` inside `removeLiquidity`, credit an internal `pendingWithdrawals[owner][token]` mapping and emit an event. Introduce a separate `claimWithdrawal(address token)` function that the owner calls to pull their balance. This decouples the accounting step from the transfer step, so a failed transfer does not block the position from being burned.

Alternatively, wrap each transfer in a `try/catch` and, on failure, credit the pending-withdrawal mapping so the owner can claim later.

---

### Proof of Concept

1. Deploy a `MetricOmmPool` with `token0 = USDC`, `token1 = WETH`.
2. Alice calls `addLiquidity` for bin 0, depositing 1000 USDC and 1 WETH. Her shares are recorded in `_positionBinShares[keccak256(alice, salt, 0)]`.
3. USDC's issuer blacklists Alice's address (e.g., via a sanctions action).
4. Alice calls `removeLiquidity` with her full share amount.
5. `LiquidityLib.removeLiquidity` computes `amount0Removed = 1000e6` (USDC) and `amount1Removed = 1e18` (WETH).
6. `IERC20(USDC).safeTransfer(alice, 1000e6)` reverts because Alice is blacklisted.
7. The entire transaction reverts; Alice's shares are unchanged.
8. Every subsequent call to `removeLiquidity` by Alice produces the same revert.
9. Alice's 1000 USDC and 1 WETH are permanently locked in the pool with no recovery mechanism. [4](#0-3) [5](#0-4)

### Citations

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L161-251)
```text
  function removeLiquidity(
    PoolContext memory ctx,
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    BinTotals storage binTotals,
    mapping(int256 => BinState) storage binStates,
    mapping(int256 => uint256) storage binTotalShares,
    mapping(bytes32 => uint256) storage positionBinShares
  ) public returns (uint256 amount0Removed, uint256 amount1Removed) {
    unchecked {
      uint256 length = deltas.binIdxs.length;
      if (length == 0) return (0, 0);

      uint256 totalToken0ToRemoveScaled = 0;
      uint256 totalToken1ToRemoveScaled = 0;

      BinBalanceDelta[] memory binBalanceDeltas = new BinBalanceDelta[](length);

      for (uint256 i = 0; i < length; i++) {
        int256 binIdx = deltas.binIdxs[i];
        uint256 sharesToRemove = deltas.shares[i];

        if (binIdx < ctx.lowestBin || binIdx > ctx.highestBin) {
          revert IMetricOmmPoolActions.InvalidBinIndex(binIdx);
        }
        if (sharesToRemove == 0) continue;

        {
          // safe because -128 <= LOWEST_BIN <= HIGHEST_BIN <= 127 (enforced by factory)
          // forge-lint: disable-next-line(unsafe-typecast)
          bytes32 posKey = _positionBinKey(owner, salt, int8(binIdx));
          uint256 binTotalSharesVal = binTotalShares[binIdx];
          uint256 userShares = positionBinShares[posKey];

          if (userShares < sharesToRemove) {
            revert IMetricOmmPoolActions.InsufficientLiquidity(sharesToRemove, userShares);
          }
          uint256 newUserShares = userShares - sharesToRemove;
          if (newUserShares > 0 && newUserShares < ctx.minimalMintableLiquidity) {
            revert IMetricOmmPoolActions.MinimalLiquidity(newUserShares, ctx.minimalMintableLiquidity);
          }

          BinState storage binState = binStates[binIdx];
          uint256 amount0Scaled = _checkedMul(binState.token0BalanceScaled, sharesToRemove) / binTotalSharesVal;
          uint256 amount1Scaled = _checkedMul(binState.token1BalanceScaled, sharesToRemove) / binTotalSharesVal;

          // casting to uint104 is safe because amount0Scaled and amount1Scaled are less than token(0|1)BalanceScaled
          // forge-lint: disable-next-line(unsafe-typecast)
          binState.token0BalanceScaled -= uint104(amount0Scaled);
          // forge-lint: disable-next-line(unsafe-typecast)
          binState.token1BalanceScaled -= uint104(amount1Scaled);
          binTotalShares[binIdx] = binTotalSharesVal - sharesToRemove;
          positionBinShares[posKey] = newUserShares;

          totalToken0ToRemoveScaled += amount0Scaled;
          totalToken1ToRemoveScaled += amount1Scaled;

          binBalanceDeltas[i] = BinBalanceDelta({
            // safe because amount0Scaled is bounded by uint104 bin balances.
            // forge-lint: disable-next-line(unsafe-typecast)
            delta0Scaled: -int256(amount0Scaled),
            // safe because amount1Scaled is bounded by uint104 bin balances.
            // forge-lint: disable-next-line(unsafe-typecast)
            delta1Scaled: -int256(amount1Scaled)
          });
        }
      }

      if (totalToken0ToRemoveScaled > 0) {
        // forge-lint: disable-next-line(unsafe-typecast)
        binTotals.scaledToken0 = uint128(uint256(binTotals.scaledToken0) - totalToken0ToRemoveScaled);
      }
      if (totalToken1ToRemoveScaled > 0) {
        // forge-lint: disable-next-line(unsafe-typecast)
        binTotals.scaledToken1 = uint128(uint256(binTotals.scaledToken1) - totalToken1ToRemoveScaled);
      }

      (amount0Removed, amount1Removed) =
        _deltasScaledToExternal(totalToken0ToRemoveScaled, totalToken1ToRemoveScaled, ctx, Math.Rounding.Floor);

      if (amount0Removed > 0) {
        IERC20(ctx.token0).safeTransfer(owner, amount0Removed);
      }
      if (amount1Removed > 0) {
        IERC20(ctx.token1).safeTransfer(owner, amount1Removed);
      }

      emit IMetricOmmPoolActions.LiquidityRemoved(owner, salt, deltas.binIdxs, binBalanceDeltas, deltas.shares);
    }
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
