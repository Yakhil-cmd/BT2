### Title
LP Principal Permanently Locked When USDC Blacklists the Position Owner — (`metric-core/contracts/libraries/LiquidityLib.sol`)

---

### Summary

`removeLiquidity` unconditionally transfers withdrawn tokens to the hardcoded `owner` address with no alternative recipient and no recovery path. When a pool contains USDC (or USDT) and the LP's address is blacklisted after deposit, every subsequent `removeLiquidity` call reverts, permanently locking the LP's principal inside the pool.

---

### Finding Description

`MetricOmmPool.removeLiquidity` enforces `msg.sender == owner` and delegates to `LiquidityLib.removeLiquidity`, which ends with:

```solidity
// LiquidityLib.sol lines 242-247
if (amount0Removed > 0) {
    IERC20(ctx.token0).safeTransfer(owner, amount0Removed);
}
if (amount1Removed > 0) {
    IERC20(ctx.token1).safeTransfer(owner, amount1Removed);
}
``` [1](#0-0) 

The recipient is always `owner`; there is no `recipient` parameter, no try/catch, and no admin escape hatch for LP funds. The USDC contract's `notBlacklisted` modifier causes `safeTransfer` to revert when `owner` is blacklisted, making the call permanently fail.

The pool-level function that calls into this library:

```solidity
// MetricOmmPool.sol lines 199-212
function removeLiquidity(address owner, uint80 salt, LiquidityDelta calldata deltas, bytes calldata extensionData)
    external
    nonReentrant(PoolActions.REMOVE_LIQUIDITY)
    returns (uint256 amount0Removed, uint256 amount1Removed)
{
    ...
    if (msg.sender != owner) revert NotPositionOwner();
    ...
    (amount0Removed, amount1Removed) = LiquidityLib.removeLiquidity(...);
}
``` [2](#0-1) 

The `msg.sender == owner` guard means the LP cannot route the withdrawal to a different address even if they wanted to. There is no factory-level or admin-level function that can rescue LP shares on behalf of a blacklisted owner — the only admin-accessible fund-recovery path in the factory is `collectTokens`, which sweeps the factory's own balance, not LP shares held in the pool.

---

### Impact Explanation

**Critical/High — direct, permanent loss of LP principal.**

Any LP who deposits USDC (or USDT) into a Metric OMM pool and is subsequently blacklisted by the USDC contract loses their entire deposited principal with no on-chain recovery path. The shares remain recorded in `positionBinShares` but the underlying tokens can never be extracted because every `removeLiquidity` call reverts at the `safeTransfer` step. No admin, factory owner, or third party can withdraw on the LP's behalf.

---

### Likelihood Explanation

**Medium** — identical to the external report's assessment. An LP address is not blacklisted at deposit time (otherwise the `addLiquidity` callback would also fail), but USDC's blacklist is operated by Circle and can be applied at any time after deposit. Pools with large USDC TVL and long-lived LP positions are the highest-risk scenario.

---

### Recommendation

Add an optional `recipient` parameter to `removeLiquidity` (defaulting to `owner` when zero) so the LP can direct proceeds to a non-blacklisted address. Alternatively, implement a factory-level emergency withdrawal function that allows the pool admin or factory owner to transfer LP-owned shares to a substitute address after a governance process, analogous to the `withdrawBlacklistedFunds()` fix applied in the referenced USDC bridge report.

---

### Proof of Concept

1. A pool is deployed with USDC as `token0`.
2. Alice calls `addLiquidity(alice, salt, deltas, ...)` — succeeds; Alice's USDC is deposited and shares are minted.
3. Circle blacklists Alice's address in the USDC contract.
4. Alice calls `removeLiquidity(alice, salt, deltas, "")`.
5. Inside `LiquidityLib.removeLiquidity`, share accounting is updated (state is mutated), then `IERC20(USDC).safeTransfer(alice, amount0Removed)` is called.
6. USDC's `notBlacklisted(alice)` modifier reverts the transfer.
7. The entire transaction reverts; Alice's shares are still recorded but the underlying USDC can never be extracted.
8. No factory or admin function exists to rescue Alice's LP position — her principal is permanently locked.

### Citations

**File:** metric-core/contracts/libraries/LiquidityLib.sol (L242-247)
```text
      if (amount0Removed > 0) {
        IERC20(ctx.token0).safeTransfer(owner, amount0Removed);
      }
      if (amount1Removed > 0) {
        IERC20(ctx.token1).safeTransfer(owner, amount1Removed);
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
