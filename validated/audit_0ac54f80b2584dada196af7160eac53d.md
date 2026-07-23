### Title
`removeLiquidity()` Lacks `recipient` Parameter, Permanently Trapping LP Principal When Owner Is Blacklisted by Token0 — (`metric-core/contracts/MetricOmmPool.sol`, `metric-core/contracts/libraries/LiquidityLib.sol`)

---

### Summary

`removeLiquidity()` hardcodes the token transfer destination to `owner` (= `msg.sender`) with no way to specify an alternative recipient. If the LP's address is blacklisted by token0 (e.g., USDC), the `safeTransfer` of token0 reverts, making it impossible to recover token0 from any bin and token1 from the active bin, permanently trapping LP principal.

---

### Finding Description

`MetricOmmPool.removeLiquidity()` enforces `msg.sender == owner` and delegates to `LiquidityLib.removeLiquidity()`, which unconditionally transfers both tokens to `owner`: [1](#0-0) 

Inside `LiquidityLib.removeLiquidity()`, after accumulating scaled amounts across all requested bins, the transfers are issued: [2](#0-1) 

There is no `recipient` parameter anywhere in this call chain. The function signature is: [3](#0-2) 

By contrast, `swap()` already accepts a `recipient` parameter distinct from `msg.sender`, demonstrating the design already supports this pattern: [4](#0-3) 

**Failure scenario**: If `owner` is blacklisted by USDC (token0), then `IERC20(ctx.token0).safeTransfer(owner, amount0Removed)` reverts. Because both token transfers occur in the same atomic call, token1 owed from the active bin (which holds both tokens) is also unrecoverable. The LP's shares have already been decremented in storage before the transfer: [5](#0-4) 

Wait — actually the share decrement and the transfer are in the same transaction, so if the transfer reverts, the share decrement also reverts. The LP retains their shares but **cannot ever call `removeLiquidity()` successfully** because every attempt to remove from a token0-containing bin will revert at the `safeTransfer` step. Token0 principal and token1 principal in the active bin are permanently trapped.

---

### Impact Explanation

- **Token0 principal**: Permanently unrecoverable from all bins above or at the current price, because every `removeLiquidity` call that yields `amount0Removed > 0` reverts.
- **Token1 principal in the active bin**: Unrecoverable because the active bin yields both tokens; the token0 transfer reverts before token1 is sent.
- **Token1 principal in bins strictly below current price**: Recoverable (those bins yield `amount0Removed == 0`, so no token0 transfer is attempted). This is the only partial escape.
- **Severity**: Medium — direct, permanent loss of LP principal for a realistic USDC-pool scenario; no admin action can rescue the funds because the pool has no sweep path for LP positions.

---

### Likelihood Explanation

USDC and USDT blacklisting is explicitly in scope per the contest rules. Any LP address (EOA or contract) can be added to the USDC blacklist by Circle at any time. Pools pairing USDC as token0 with any other asset (e.g., WETH) are the primary deployment target for this protocol. The trigger requires no privileged or malicious action by the LP themselves.

---

### Recommendation

Add a `recipient` address parameter to `removeLiquidity()` and thread it through `LiquidityLib.removeLiquidity()`, replacing the hardcoded `owner` in the two `safeTransfer` calls. The position ownership check (`msg.sender == owner`) should remain unchanged — only the transfer destination changes.

```diff
- function removeLiquidity(address owner, uint80 salt, LiquidityDelta calldata deltas, bytes calldata extensionData)
+ function removeLiquidity(address owner, address recipient, uint80 salt, LiquidityDelta calldata deltas, bytes calldata extensionData)

  // in LiquidityLib.removeLiquidity:
- IERC20(ctx.token0).safeTransfer(owner, amount0Removed);
+ IERC20(ctx.token0).safeTransfer(recipient, amount0Removed);
- IERC20(ctx.token1).safeTransfer(owner, amount1Removed);
+ IERC20(ctx.token1).safeTransfer(recipient, amount1Removed);
```

---

### Proof of Concept

1. Deploy a pool with USDC as `token0` and WETH as `token1`.
2. LP (`alice`) adds liquidity across bins spanning the active bin (bins −2 to +2), depositing both USDC and WETH.
3. Circle blacklists `alice`'s address on USDC.
4. `alice` calls `pool.removeLiquidity(alice, salt, deltas, "")` targeting any bin with token0 exposure.
5. `LiquidityLib.removeLiquidity` computes `amount0Removed > 0`, reaches `IERC20(USDC).safeTransfer(alice, amount0Removed)`, which reverts because `alice` is blacklisted.
6. The entire transaction reverts. `alice`'s shares are unchanged but she can never successfully withdraw token0 or the token1 co-located in the active bin.
7. `alice` attempts to remove only from bins below current price (token1-only bins) — this succeeds, recovering only that portion of her token1.
8. All USDC principal and the token1 in the active bin remain permanently locked in the pool with no recovery path.

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

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L210-217)
```text
          binState.token0BalanceScaled -= uint104(amount0Scaled);
          // forge-lint: disable-next-line(unsafe-typecast)
          binState.token1BalanceScaled -= uint104(amount1Scaled);
          binTotalShares[binIdx] = binTotalSharesVal - sharesToRemove;
          positionBinShares[posKey] = newUserShares;

          totalToken0ToRemoveScaled += amount0Scaled;
          totalToken1ToRemoveScaled += amount1Scaled;
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

**File:** metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolActions.sol (L164-174)
```text
  /// @notice Burn shares across bins for `(owner, salt)` and send underlying tokens to `owner`.
  /// @dev Requires `msg.sender == owner` (`NotPositionOwner` otherwise). No callback: tokens are transferred out directly.
  /// @param owner Must equal `msg.sender`.
  /// @param salt Position salt with `owner`.
  /// @param deltas Parallel arrays of bins and share burns.
  /// @param extensionData Opaque bytes forwarded to liquidity extensions (beforeRemoveLiquidity / afterRemoveLiquidity).
  /// @return amount0Removed Total token0 sent from the pool to `owner` (native).
  /// @return amount1Removed Total token1 sent from the pool to `owner` (native).
  function removeLiquidity(address owner, uint80 salt, LiquidityDelta calldata deltas, bytes calldata extensionData)
    external
    returns (uint256 amount0Removed, uint256 amount1Removed);
```
