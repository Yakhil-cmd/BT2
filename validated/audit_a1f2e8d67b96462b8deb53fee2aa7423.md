### Title
Griefing DOS on `removeLiquidity` via Unprivileged `addLiquidity` for Arbitrary `owner` — (`metric-core/contracts/libraries/LiquidityLib.sol`)

### Summary

`addLiquidity` allows any `msg.sender` to mint shares into any `owner`'s position. An attacker can frontrun a victim's full-withdrawal transaction by depositing a dust amount (as few as 1 share) into the victim's position, causing the victim's `removeLiquidity` to revert with `MinimalLiquidity` indefinitely.

### Finding Description

`MetricOmmPool.addLiquidity` accepts an arbitrary `owner` address and does not require `msg.sender == owner`: [1](#0-0) 

Inside `LiquidityLib.addLiquidity`, the only guard on the resulting share count is:

```solidity
uint256 newUserShares = userShares + sharesToAdd;
if (newUserShares < ctx.minimalMintableLiquidity) {
    revert IMetricOmmPoolActions.MinimalLiquidity(...);
}
``` [2](#0-1) 

If the victim already holds `X >= minimalMintableLiquidity` shares, the attacker can add any `Y >= 1` share and the check passes (`X + Y > minimalMintableLiquidity`).

`LiquidityLib.removeLiquidity` then enforces:

```solidity
uint256 newUserShares = userShares - sharesToRemove;
if (newUserShares > 0 && newUserShares < ctx.minimalMintableLiquidity) {
    revert IMetricOmmPoolActions.MinimalLiquidity(...);
}
``` [3](#0-2) 

When the victim submits `removeLiquidity` with `sharesToRemove = X` (their full balance), the attacker frontruns with `addLiquidity(owner=victim, sharesToAdd=1)`. Storage now holds `X + 1` shares. The victim's transaction computes `newUserShares = (X + 1) - X = 1`. Since `1 > 0 && 1 < minimalMintableLiquidity`, the call reverts. The attacker repeats this every time the victim retries.

### Impact Explanation

The victim is permanently unable to fully exit a bin position. Their principal (LP tokens) is locked in the pool as long as the attacker continues the griefing. This breaks the core `removeLiquidity` flow and constitutes a loss of access to user principal / unusable withdraw flow, which is within the allowed impact gate.

### Likelihood Explanation

- **Trigger**: Any unprivileged address can call `addLiquidity` with `owner = victim` directly on the pool (no periphery required).
- **Cost**: 1 share worth of tokens per frontrun. For pools with 18-decimal tokens and a small `initialScaledToken*PerShareE18`, this is economically negligible.
- **Repeatability**: The attacker can repeat indefinitely; the victim cannot escape by reading current state because the attacker can always frontrun the next attempt.
- **Salt visibility**: The victim's `salt` is visible on-chain from prior `LiquidityAdded` events. [4](#0-3) 

### Recommendation

Restrict `addLiquidity` so that shares can only be minted into a position owned by `msg.sender`, or require explicit approval from the `owner` before a third party can add to their position. Alternatively, add a `maxSharesToRemove` parameter to `removeLiquidity` that removes all shares up to a caller-supplied ceiling (analogous to the Timeswap fix of clamping the repayment amount), so the victim can always drain their position regardless of concurrent additions.

### Proof of Concept

1. Victim holds `X = 10_000` shares in bin `4` (`X >= MINIMAL_MINTABLE_LIQUIDITY = 1000`).
2. Victim submits `pool.removeLiquidity(victim, salt, [{binIdx:4, shares:10_000}], "")`.
3. Attacker sees the pending tx and frontruns: `pool.addLiquidity(victim, salt, [{binIdx:4, shares:1}], callbackData, "")` — attacker pays the token cost of 1 share.
4. Storage: `positionBinShares[posKey] = 10_001`.
5. Victim's tx executes: `newUserShares = 10_001 - 10_000 = 1`. Check: `1 > 0 && 1 < 1000` → `revert MinimalLiquidity(1, 1000)`.
6. Attacker repeats step 3 on every retry. Victim's liquidity is permanently locked. [5](#0-4)

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

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L76-79)
```text
          uint256 newUserShares = userShares + sharesToAdd;
          if (newUserShares < ctx.minimalMintableLiquidity) {
            revert IMetricOmmPoolActions.MinimalLiquidity(newUserShares, ctx.minimalMintableLiquidity);
          }
```

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L196-214)
```text
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
```

**File:** metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolActions.sol (L74-78)
```text
  /// @notice Mint would leave the position with non-zero liquidity in a bin but below the pool’s dust floor.
  /// @dev Raised when the resulting share balance is `> 0` and `< MINIMAL_MINTABLE_LIQUIDITY` so tiny positions cannot clog storage; either add more shares or remove to zero.
  /// @param afterOperation Share amount in the affected bin after the attempted operation.
  /// @param minimalRequired Pool immutable `MINIMAL_MINTABLE_LIQUIDITY`.
  error MinimalLiquidity(uint256 afterOperation, uint256 minimalRequired);
```
