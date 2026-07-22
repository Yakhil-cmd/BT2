### Title
Permissionless `addLiquidity` Operator Pattern Enables Griefing Attack on LP Full-Withdrawal — (`metric-core/contracts/MetricOmmPool.sol`)

---

### Summary

`addLiquidity` allows any `msg.sender` to mint shares into an arbitrary `owner`'s position (operator pattern). `removeLiquidity` enforces `msg.sender == owner` but also enforces a dust floor: if the remaining shares after removal are `> 0 && < minimalMintableLiquidity`, the call reverts with `MinimalLiquidity`. An attacker can front-run a victim's full-withdrawal transaction by donating a sub-floor dust amount of shares into the victim's position, causing the victim's removal to leave exactly that dust remainder and revert. The attack can be repeated indefinitely at low cost.

---

### Finding Description

`addLiquidity` in `MetricOmmPool.sol` explicitly supports the operator pattern: [1](#0-0) 

There is no restriction on who may supply `owner`; any caller that implements `IMetricOmmModifyLiquidityCallback` and pays the required tokens can mint shares into any address's position.

`removeLiquidity` enforces `msg.sender == owner` but also enforces the dust floor on the *resulting* share balance: [2](#0-1) 

The `MinimalLiquidity` error is defined as: [3](#0-2) 

The two invariants collide: anyone can increase a victim's share balance, but the victim's own removal is constrained by the resulting dust floor. If the attacker adds exactly `minimalMintableLiquidity - 1` shares to the victim's position before the victim's full-withdrawal transaction executes, the victim's removal leaves `minimalMintableLiquidity - 1` shares remaining, which satisfies `> 0 && < minimalMintableLiquidity` and reverts.

---

### Impact Explanation

An LP who intends to fully exit a position (remove all shares from a bin) can have their transaction permanently griefed. Every time the victim re-queries their balance and resubmits with the updated total, the attacker can front-run again with another dust donation. The victim cannot exit without either (a) removing the attacker-donated shares too (requiring them to know the exact new total on-chain at execution time, which the attacker can invalidate again), or (b) accepting a permanent dust position they did not create. This breaks the core LP withdrawal flow and constitutes broken core pool functionality causing loss of usability of the withdraw path.

---

### Likelihood Explanation

- `addLiquidity` is a standard public entry point; no special role is required.
- The attacker only needs to deploy a minimal callback contract and hold a small token amount (`minimalMintableLiquidity - 1` shares worth of tokens, which is pool-configurable and can be very small).
- The attack is repeatable: each time the victim adjusts their removal amount, the attacker can front-run again.
- Mempool visibility of `removeLiquidity` calls makes targeting straightforward on any non-private mempool chain.

---

### Recommendation

Restrict `addLiquidity` so that shares can only be minted into a position owned by `msg.sender`, **or** require explicit approval from `owner` before a third party may mint into their position (similar to ERC-20 allowance). Alternatively, remove the `MinimalLiquidity` revert on `removeLiquidity` when the resulting share count is zero (i.e., only enforce the dust floor for partial removals, not full exits). The simplest targeted fix:

```solidity
// In removeLiquidity / LiquidityLib.removeLiquidity:
uint256 newUserShares = userShares - sharesToRemove;
// Only enforce dust floor on partial removals, not full exits:
if (newUserShares > 0 && newUserShares < ctx.minimalMintableLiquidity) {
    revert MinimalLiquidity(newUserShares, ctx.minimalMintableLiquidity);
}
```

This already exists; the complementary fix is on the add side — require `owner == msg.sender` or an explicit approval mapping so that third parties cannot silently inflate another LP's position.

---

### Proof of Concept

1. Alice holds `N = 10 000` shares in bin 4 under `(alice, salt)`. She calls `removeLiquidity(alice, salt, {binIdxs:[4], shares:[10000]}, "")`.

2. Bob observes Alice's pending transaction in the mempool. Bob deploys a minimal `IMetricOmmModifyLiquidityCallback` contract, funds it with tokens for `minimalMintableLiquidity - 1 = 999` shares, and calls `pool.addLiquidity(alice, salt, {binIdxs:[4], shares:[999]}, callbackData, "")`. Bob's callback pays the required tokens; the pool mints 999 shares into Alice's position. Alice now holds 10 999 shares.

3. Alice's original transaction executes: `removeLiquidity` computes `newUserShares = 10999 - 10000 = 999`.

4. The check `999 > 0 && 999 < 1000` is true → `revert MinimalLiquidity(999, 1000)`.

5. Alice's full exit is blocked. Bob repeats the attack each time Alice resubmits with an updated share count. [4](#0-3) [5](#0-4)

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

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L193-214)
```text
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
```

**File:** metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolActions.sol (L74-83)
```text
  /// @notice Mint would leave the position with non-zero liquidity in a bin but below the pool’s dust floor.
  /// @dev Raised when the resulting share balance is `> 0` and `< MINIMAL_MINTABLE_LIQUIDITY` so tiny positions cannot clog storage; either add more shares or remove to zero.
  /// @param afterOperation Share amount in the affected bin after the attempted operation.
  /// @param minimalRequired Pool immutable `MINIMAL_MINTABLE_LIQUIDITY`.
  error MinimalLiquidity(uint256 afterOperation, uint256 minimalRequired);

  /// @notice Burn asked for more shares than exist for that position in a bin.
  /// @param requested `deltas.shares[i]` for the offending bin.
  /// @param available Shares recorded for `owner`+`salt` in that bin before the call.
  error InsufficientLiquidity(uint256 requested, uint256 available);
```
