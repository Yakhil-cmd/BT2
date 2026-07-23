Now I have enough context to analyze the finding. Let me verify the exact timelock check logic:

### Title
Zero-Timelock Price Provider Allows Pool Admin to Sandwich Swaps with Malicious Oracle — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

When a pool is created with `priceProviderTimelock == 0`, the pool admin can call `proposePoolPriceProvider` and `executePoolPriceProviderUpdate` in the **same transaction**, because the guard `block.timestamp < execAfter` evaluates to `block.timestamp < block.timestamp` which is always `false`. This collapses the two-step propose/execute flow into an instantaneous oracle switch, letting the admin sandwich any swap with a malicious price provider and drain LP funds.

### Finding Description

`proposePoolPriceProvider` computes the execution deadline as:

```solidity
uint256 executeAfter = block.timestamp + timelock;   // = block.timestamp when timelock == 0
``` [1](#0-0) 

`executePoolPriceProviderUpdate` then enforces:

```solidity
if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(...);
``` [2](#0-1) 

When `timelock == 0`, `execAfter == block.timestamp`, so `block.timestamp < block.timestamp` is `false` and the revert is never triggered. Both calls succeed in the same block/transaction.

The factory's `createPool` stores `params.priceProviderTimelock` verbatim with no minimum-value check:

```solidity
priceProviderTimelock[pool] = params.priceProviderTimelock;
``` [3](#0-2) 

`_validatePoolParameters` checks fees, tokens, admin, and initial amounts, but imposes **no lower bound on `priceProviderTimelock`** for the mutable-oracle path: [4](#0-3) 

The only special value is `type(uint256).max` (immutable mode). Any other value, including `0`, is accepted as a valid mutable configuration.

The `_validatePriceProvider` check only verifies that the new provider exposes the correct `token0`/`token1` pair — it does not constrain the bid/ask prices the provider returns: [5](#0-4) 

### Impact Explanation

A pool admin who created the pool with `priceProviderTimelock == 0` can execute the following atomic sandwich in a single transaction:

1. Deploy a malicious `IPriceProvider` that returns the correct `token0`/`token1` but an extreme bid/ask (e.g., bid = 1 wei in Q64, ask = 2 wei in Q64 for a token worth $1 000).
2. Call `proposePoolPriceProvider(pool, maliciousProvider)` — sets `pendingPriceProviderExecuteAfter = block.timestamp`.
3. Call `executePoolPriceProviderUpdate(pool)` — passes immediately; malicious provider is now active.
4. Call `swap(...)` — the pool reads `getBidAndAskPrice()` from the malicious provider and executes at the manipulated price, letting the admin buy token0 at a tiny fraction of fair value (or sell token1 at an inflated price), draining LP reserves.
5. Call `proposePoolPriceProvider(pool, legitimateProvider)` + `executePoolPriceProviderUpdate(pool)` — restores the legitimate oracle, concealing the attack.

The pool's swap path reads the active price provider at swap time: [6](#0-5) 

LP principal (token0 and token1 balances held in bins) is directly at risk. The loss is bounded only by the pool's total liquidity.

### Likelihood Explanation

The trigger requires the pool admin to have set `priceProviderTimelock == 0` at creation. This is a valid, non-rejected parameter value. A pool admin who controls the pool creation (e.g., a protocol deploying its own pool) can deliberately or inadvertently choose `0`. The attack requires no external cooperation, no special on-chain conditions, and no multi-block setup — it is a single atomic transaction.

### Recommendation

Enforce a minimum timelock for mutable-oracle pools in `_validatePoolParameters`:

```solidity
uint256 internal constant MIN_PRICE_PROVIDER_TIMELOCK = 1 days; // or protocol-chosen value

if (params.priceProviderTimelock != type(uint256).max &&
    params.priceProviderTimelock < MIN_PRICE_PROVIDER_TIMELOCK) {
    revert PriceProviderTimelockTooShort();
}
```

Alternatively, change the guard in `executePoolPriceProviderUpdate` to `<=` so that same-block execution is always rejected:

```solidity
if (block.timestamp <= execAfter) revert PriceProviderTimelockNotElapsed(execAfter, block.timestamp);
```

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

contract MaliciousProvider {
    address public immutable token0;
    address public immutable token1;
    constructor(address t0, address t1) { token0 = t0; token1 = t1; }
    // Returns 1 wei bid / 2 wei ask — effectively zero price for token0
    function getBidAndAskPrice() external returns (uint128, uint128) {
        return (1, 2);
    }
}

// Attack sequence (single tx via a multicall or attack contract):
// 1. factory.proposePoolPriceProvider(pool, address(maliciousProvider));
//    → pendingPriceProviderExecuteAfter[pool] = block.timestamp (timelock == 0)
// 2. factory.executePoolPriceProviderUpdate(pool);
//    → block.timestamp < block.timestamp == false → succeeds immediately
//    → pool.priceProvider = maliciousProvider
// 3. pool.swap(zeroForOne=false, amountSpecified=largeAmount, priceLimitX64=type(uint128).max, ...);
//    → pool reads bid=1, ask=2 from maliciousProvider
//    → attacker receives token0 at near-zero cost, draining LP token0 reserves
// 4. factory.proposePoolPriceProvider(pool, address(legitimateProvider));
// 5. factory.executePoolPriceProviderUpdate(pool);
//    → legitimate oracle restored; attack concealed
```

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L213-213)
```text
    priceProviderTimelock[pool] = params.priceProviderTimelock;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L487-489)
```text
    uint256 executeAfter = block.timestamp + timelock;
    pendingPriceProvider[pool] = newPriceProvider;
    pendingPriceProviderExecuteAfter[pool] = executeAfter;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L498-499)
```text
    // forge-lint: disable-next-line(block-timestamp) -- timelock enforcement legitimately relies on `block.timestamp`.
    if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(execAfter, block.timestamp);
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L541-546)
```text
  function _validatePriceProvider(address token0, address token1, address priceProvider) internal view {
    if (priceProvider == address(0)) revert InvalidPriceProvider();
    if (IPriceProvider(priceProvider).token0() != token0 || IPriceProvider(priceProvider).token1() != token1) {
      revert PriceProviderTokenMismatch();
    }
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L548-563)
```text
  function _validatePoolParameters(PoolParameters calldata params) internal view {
    if (params.token0 == address(0) || params.token1 == address(0) || params.token0 == params.token1) {
      revert InvalidTokenConfig();
    }
    if (params.admin == address(0)) revert InvalidAdmin();
    _validatePriceProvider(params.token0, params.token1, params.priceProvider);
    if (params.adminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    if (spreadProtocolFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (protocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();
    if (params.adminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (params.adminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
    if (params.initialAmount0PerShareE18 == 0 || params.initialAmount1PerShareE18 == 0) {
      revert InvalidInitialAmount();
    }
    if (params.minimalMintableLiquidity == 0) revert InvalidMinimalMintableLiquidity();
  }
```

**File:** metric-core/contracts/interfaces/IPriceProvider/IPriceProvider.sol (L14-15)
```text
  /// @notice Bid and ask in Q64.64 fixed-point as `uint128` pair (canonical for pool mid/spread math when applicable).
  function getBidAndAskPrice() external returns (uint128 bidPrice, uint128 askPrice);
```
