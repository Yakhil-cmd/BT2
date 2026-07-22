### Title
LP Principal Permanently Stuck When Owner Address Is Blacklisted by USDC/USDT — (`metric-core/contracts/libraries/LiquidityLib.sol`)

### Summary
`LiquidityLib.removeLiquidity` transfers withdrawn tokens unconditionally to the position `owner` address. If the pool uses USDC or USDT and the LP's address is subsequently blacklisted by the token contract, every call to `removeLiquidity` reverts at the `safeTransfer` step. There is no emergency withdrawal path, no position-transfer mechanism, and no factory-level rescue function that reaches pool balances, so the LP's principal is permanently locked.

### Finding Description
In `LiquidityLib.removeLiquidity`, after computing the amounts owed, the library executes:

```solidity
if (amount0Removed > 0) {
    IERC20(ctx.token0).safeTransfer(owner, amount0Removed);
}
if (amount1Removed > 0) {
    IERC20(ctx.token1).safeTransfer(owner, amount1Removed);
}
``` [1](#0-0) 

The recipient is always `owner` — the address that holds the position shares. There is no alternative `recipient` parameter, no pull-payment pattern, and no way to redirect the transfer.

The pool enforces `msg.sender == owner` before entering the library:

```solidity
if (msg.sender != owner) revert NotPositionOwner();
``` [2](#0-1) 

Positions are keyed by `keccak256(abi.encode(owner, salt, bin))`: [3](#0-2) 

There is no mechanism to re-key a position to a different owner address, so the LP cannot delegate withdrawal to an un-blacklisted address.

The factory's `collectTokens` rescue function only sweeps the **factory's own balance**, not the pool's:

```solidity
function collectTokens(address token, address to, uint256 amount) external override onlyOwner {
    uint256 balance = IERC20(token).balanceOf(address(this)); // address(this) == factory
    ...
}
``` [4](#0-3) 

No equivalent rescue function exists on `MetricOmmPool` itself.

### Impact Explanation
An LP who deposited into a USDC/USDT pool and is later blacklisted by the token issuer loses 100% of their deposited principal. The pool's stated solvency invariant — "every LP can withdraw their proportional share" — is broken for that position. The funds remain in the pool contract indefinitely with no recovery path for the LP, the pool admin, or the factory owner. [5](#0-4) 

### Likelihood Explanation
USDC and USDT both maintain on-chain blacklists exercised in regulatory and sanctions enforcement actions. Pools pairing USDC or USDT are the most common production deployments on Ethereum and Base (the protocol's primary target chains). A blacklisting event affecting an LP address is a realistic, documented occurrence. No attacker action is required — the external token issuer triggers the condition unilaterally.

### Recommendation
Add an emergency withdrawal path on `MetricOmmPool` (callable only by the factory owner or a dedicated multisig with timelock) that transfers a specified token balance to a chosen recipient, bypassing the `owner`-only transfer. Alternatively, allow `removeLiquidity` to accept an explicit `recipient` address distinct from `owner`, so a blacklisted LP can redirect proceeds to a clean address they control. Either change should be gated behind appropriate access control to avoid introducing new centralization risks.

### Proof of Concept
1. Deploy a pool with USDC as `token0`.
2. LP calls `addLiquidity`; USDC is transferred into the pool via the modify-liquidity callback.
3. USDC issuer blacklists the LP's address (e.g., regulatory action).
4. LP calls `removeLiquidity` → `LiquidityLib.removeLiquidity` computes `amount0Removed > 0` → `IERC20(USDC).safeTransfer(owner, amount0Removed)` → USDC reverts because `owner` is blacklisted → entire transaction reverts.
5. LP cannot supply a different recipient (no such parameter). LP cannot transfer the position (no transfer mechanism). Factory owner's `collectTokens` only drains the factory address, not the pool. LP's USDC principal is permanently locked in the pool. [6](#0-5)

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

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L256-259)
```text
  function _positionBinKey(address owner, uint80 salt, int8 bin) internal pure returns (bytes32 key) {
    // forge-lint: disable-next-line(asm-keccak256)
    return keccak256(abi.encode(owner, salt, bin));
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L206-206)
```text
    if (msg.sender != owner) revert NotPositionOwner();
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L262-268)
```text
  function collectTokens(address token, address to, uint256 amount) external override onlyOwner {
    uint256 balance = IERC20(token).balanceOf(address(this));
    uint256 amountToCollect = amount == 0 ? balance : amount;
    if (amountToCollect > 0) {
      IERC20(token).safeTransfer(to, amountToCollect);
      emit TokensCollected(token, to, amountToCollect);
    }
```

**File:** README.md (L45-45)
```markdown
Solvency: pool token balances always cover all LP claims + owed fees; every LP can withdraw their proportional share. Withdraw (remove-liquidity) must work even when the pool is paused (pause only blocks swaps).
```
