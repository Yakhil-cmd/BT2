### Title
JIT Liquidity Attack Steals LP Spread Fees from Existing Providers via Atomic Add/Remove — (File: `metric-core/contracts/libraries/LiquidityLib.sol`)

### Summary

The Metric OMM pool imposes no time lock, no minimum holding period, and no fee-growth snapshot on liquidity positions. LP spread fees from swaps are deposited directly into each bin's `token0BalanceScaled` / `token1BalanceScaled`, and `removeLiquidity` distributes them proportionally to all current share holders at the moment of removal. A MEV bot can front-run a large pending swap with `addLiquidity`, allow the swap to execute (depositing LP fees into the bin), then immediately back-run with `removeLiquidity` to extract a proportional share of those fees — stealing yield that should belong to long-term LPs.

### Finding Description

**Fee accumulation into bin balance**

Every swap variant in `SwapMath` deposits the LP fee directly into the bin's token balance. For example, `buyToken0InBinSpecifiedIn`:

```solidity
// SwapMath.sol lines 639-641
binState.token0BalanceScaled -= out0Scaled.toUint104();
binState.token1BalanceScaled =
    uint256((binState.token1BalanceScaled) + totalIn1Scaled - protocolFeeAmountScaled).toUint104();
```

`totalIn1Scaled - protocolFeeAmountScaled` includes the LP fee (`token1FeeScaled - protocolFeeAmountScaled`). After the swap, the bin balance is permanently higher by the LP fee amount. [1](#0-0) 

**Proportional withdrawal with no time guard**

`removeLiquidity` computes the withdrawn amount as a simple ratio of current bin balance to total shares:

```solidity
// LiquidityLib.sol lines 205-206
uint256 amount0Scaled = _checkedMul(binState.token0BalanceScaled, sharesToRemove) / binTotalSharesVal;
uint256 amount1Scaled = _checkedMul(binState.token1BalanceScaled, sharesToRemove) / binTotalSharesVal;
```

Any LP who holds shares at the moment of removal receives a proportional slice of the current bin balance — including LP fees from swaps that occurred after they added liquidity. [2](#0-1) 

**No time lock exists**

`addLiquidity` and `removeLiquidity` are both gated only by a transient-storage reentrancy guard keyed to their own action IDs (`ADD_LIQUIDITY` and `REMOVE_LIQUIDITY`). Transient storage is cleared after each call, so sequential calls within the same transaction are fully permitted. There is no block-number check, no minimum holding period, and no fee-growth snapshot taken at deposit time. [3](#0-2) 

**Attack flow**

1. MEV bot observes a large pending swap in the mempool.
2. Bot front-runs with `addLiquidity(binIdx=activeOrTraversedBin, shares=A)`, depositing tokens proportional to the pre-swap bin balance (`B * A / S`).
3. The victim swap executes; LP fee `F` is added to the bin balance.
4. Bot back-runs with `removeLiquidity(shares=A)`, receiving `(B*(S+A)/S + F) * A / (S+A) = B*A/S + F*A/(S+A)`.
5. Bot profit: `F * A / (S+A)` — exactly the fee stolen from existing LPs.

The `addLiquidity` path for a bin that already has shares uses:

```solidity
// LiquidityLib.sol lines 109-110
amount0Scaled = Math.ceilDiv(_checkedMul(binState.token0BalanceScaled, sharesToAdd), binTotalSharesVal);
amount1Scaled = Math.ceilDiv(_checkedMul(binState.token1BalanceScaled, sharesToAdd), binTotalSharesVal);
```

The bot pays the pre-swap balance per share, not the post-swap balance, so the LP fee `F` is captured for free. [4](#0-3) 

### Impact Explanation

Existing LPs lose a portion of their earned spread fees proportional to the attacker's share of the bin. If the attacker provides `A` shares and existing LPs hold `S` shares, the attacker captures `F * A / (S + A)` of the LP fee `F`, while existing LPs receive only `F * S / (S + A)` instead of `F`. For a swap generating $100,000 in LP fees with the attacker providing 50% of the bin liquidity, the attacker extracts $50,000 that should have accrued to long-term providers. This is a direct loss of owed LP assets.

### Likelihood Explanation

MEV bots routinely monitor mempools for large pending swaps on Ethereum (a primary target chain). The attack is:
- **Unprivileged**: any address can call `addLiquidity` and `removeLiquidity`.
- **Profitable**: LP fee captured exceeds gas costs for swaps above a modest threshold (e.g., if LP fee rate is 1% and the attacker provides 50% of bin liquidity, a $200,000 swap yields ~$1,000 profit after gas).
- **Executable via flashbots bundle**: front-run and back-run can be submitted atomically, eliminating execution risk.

### Recommendation

Implement one of the following:

1. **Fee-growth snapshot**: Record a per-position fee-growth accumulator at deposit time (analogous to Uniswap v3's `feeGrowthInside0LastX128`). On removal, only distribute fees earned after the position was opened.
2. **Minimum holding period**: Require that shares be held for at least one block before `removeLiquidity` is permitted (e.g., store `depositBlock` per position and revert if `block.number == depositBlock`).
3. **Extension hook enforcement**: Require that the `beforeRemoveLiquidity` extension hook enforce a configurable cooldown, and document this as a required production configuration.

### Proof of Concept

**Setup**: Bin 0 (active bin) has `token1BalanceScaled = 1,000,000`, `binTotalShares = 10,000`. Existing LP holds all 10,000 shares. A pending swap will generate LP fee = 10,000 scaled units in bin 0.

1. **Bot front-runs**: calls `addLiquidity(bin=0, shares=10,000)`.
   - Deposits `1,000,000 * 10,000 / 10,000 = 1,000,000` token1 (ceiling-rounded).
   - New state: `token1BalanceScaled = 2,000,000`, `binTotalShares = 20,000`.

2. **Victim swap executes**: LP fee 10,000 added to bin.
   - New state: `token1BalanceScaled = 2,010,000`.

3. **Bot back-runs**: calls `removeLiquidity(bin=0, shares=10,000)`.
   - Receives `2,010,000 * 10,000 / 20,000 = 1,005,000` token1.
   - Bot profit: `1,005,000 - 1,000,000 = 5,000` token1.

4. **Existing LP removes their 10,000 shares**:
   - Receives `1,005,000` token1 instead of `1,010,000`.
   - Loss: 5,000 token1 — exactly the amount stolen by the bot. [5](#0-4) [6](#0-5)

### Citations

**File:** metric-core/contracts/libraries/SwapMath.sol (L636-650)
```text
      uint256 token1FeeScaled = lpFeeScaledFromGrossInput(totalIn1Scaled, currBinBuyFeeX64, onePlusBuyFeeX64);

      uint256 protocolFeeAmountScaled = (token1FeeScaled * spreadFeeE6) / 1e6;
      binState.token0BalanceScaled -= out0Scaled.toUint104();
      binState.token1BalanceScaled =
        uint256((binState.token1BalanceScaled) + totalIn1Scaled - protocolFeeAmountScaled).toUint104();

      state.amountSpecifiedRemainingScaled -= totalIn1Scaled;
      state.amountCalculatedScaled += out0Scaled;
      state.protocolFeeAmountScaled += protocolFeeAmountScaled;

      delta0Scaled = -out0Scaled.toInt256();
      delta1Scaled = (totalIn1Scaled - protocolFeeAmountScaled).toInt256();
      binLpFeeAmount = token1FeeScaled - protocolFeeAmountScaled;
      return (targetPos, out0Scaled, delta0Scaled, delta1Scaled, binLpFeeAmount);
```

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L108-111)
```text
          } else {
            amount0Scaled = Math.ceilDiv(_checkedMul(binState.token0BalanceScaled, sharesToAdd), binTotalSharesVal);
            amount1Scaled = Math.ceilDiv(_checkedMul(binState.token1BalanceScaled, sharesToAdd), binTotalSharesVal);
          }
```

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L161-245)
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
```

**File:** metric-core/contracts/MetricOmmPool.sol (L182-212)
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

  /// @inheritdoc IMetricOmmPoolActions
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
