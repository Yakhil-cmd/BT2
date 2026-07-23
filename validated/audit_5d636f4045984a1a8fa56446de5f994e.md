### Title
`SwapAllowlistExtension` checks the router's address instead of the actual user, enabling complete allowlist bypass via `MetricOmmSimpleRouter` — (`metric-periphery/contracts/extensions/SwapAllowlistExtension.sol`)

### Summary

`SwapAllowlistExtension.beforeSwap` gates swaps by checking `allowedSwapper[pool][sender]`, where `sender` is the `msg.sender` of `pool.swap()`. When a user routes through `MetricOmmSimpleRouter`, the router is the direct caller of `pool.swap()`, so `sender` equals the router's address — not the actual end-user. If the pool admin allowlists the router (a natural operational step so users can use the periphery), every non-allowlisted address can bypass the swap gate by routing through the router.

### Finding Description

**Call chain:**

```
User → MetricOmmSimpleRouter.exactInputSingle()
         → pool.swap(recipient, ..., msg.sender = router)
              → _beforeSwap(sender = router, ...)
                   → SwapAllowlistExtension.beforeSwap(sender = router, ...)
                        → allowedSwapper[pool][router]  ← checked, NOT the user
```

In `MetricOmmPool.swap`, the pool passes `msg.sender` (the router) as `sender` to the extension dispatcher: [1](#0-0) 

`ExtensionCalling._beforeSwap` forwards that `sender` value verbatim to every configured extension: [2](#0-1) 

`SwapAllowlistExtension.beforeSwap` then checks `allowedSwapper[msg.sender][sender]`, where `msg.sender` is the pool and `sender` is the router: [3](#0-2) 

`MetricOmmSimpleRouter.exactInputSingle` calls `pool.swap` directly, making the router the pool's `msg.sender`: [4](#0-3) 

**Two exploitable outcomes arise from this identity confusion:**

1. **Allowlist bypass (primary impact):** The pool admin allowlists the router address so that users can access the pool through the periphery. Any non-allowlisted user then calls `router.exactInputSingle()`. The extension sees `sender = router`, which is allowlisted, and the check passes. The allowlist is completely defeated.

2. **DoS of allowlisted users (secondary impact):** If the admin does not allowlist the router, every allowlisted user who tries to swap through the router is blocked because `allowedSwapper[pool][router] == false`, even though their own address is individually permitted.

Note that `DepositAllowlistExtension` does **not** share this flaw — it ignores the `sender` argument and gates by `owner`, which the liquidity adder passes correctly. [5](#0-4) 

### Impact Explanation

A pool deploying `SwapAllowlistExtension` to restrict trading to KYC'd or otherwise vetted addresses loses that guarantee entirely once the router is allowlisted. Any address — including sanctioned or unvetted ones — can execute swaps against the pool by routing through `MetricOmmSimpleRouter`. This breaks the core pool invariant that only approved swappers may trade, constitutes an admin-boundary break (the allowlist cap is bypassed by an unprivileged path), and can cause direct loss of LP assets if the allowlist was intended to prevent toxic-flow or regulatory exposure.

### Likelihood Explanation

The router is the canonical periphery entry point for end-users. A pool admin who configures `SwapAllowlistExtension` and also wants users to access the pool through the router will naturally allowlist the router address. The bypass is then reachable by any unprivileged address with a single standard router call. No special permissions, flash loans, or multi-step setup are required.

### Recommendation

The extension must gate on the **actual end-user**, not the intermediary. Two complementary fixes:

1. **In `SwapAllowlistExtension`:** Check `sender` only when `sender` is not a known trusted router; otherwise fall back to checking the `recipient` or require the router to forward the real user identity via `extensionData`.

2. **Preferred — pass real user through `extensionData`:** Have `MetricOmmSimpleRouter` encode `msg.sender` into `extensionData` and have `SwapAllowlistExtension` decode and check that value when the direct `sender` is a registered router. This mirrors the pattern used in Uniswap v4's hook architecture.

3. **Alternatively:** Maintain a registry of trusted routers in the extension; when `sender` is a trusted router, extract and verify the real user from `extensionData`; otherwise check `sender` directly.

### Proof of Concept

```
Setup:
  - Deploy pool with SwapAllowlistExtension.
  - Admin calls setAllowedToSwap(pool, router, true)   // allowlist the router
  - Admin does NOT allowlist attacker's EOA.

Attack:
  - attacker calls router.exactInputSingle({pool, tokenIn, tokenOut, ...})
  - router calls pool.swap(recipient=attacker, ...) → msg.sender = router
  - pool calls _beforeSwap(sender=router, ...)
  - SwapAllowlistExtension checks allowedSwapper[pool][router] == true → PASSES
  - Swap executes; attacker receives output tokens.

Result:
  - Non-allowlisted attacker successfully swaps against a pool that was
    supposed to restrict trading to approved addresses only.
```

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L230-240)
```text
    _beforeSwap(
      msg.sender,
      recipient,
      zeroForOne,
      amountSpecified,
      priceLimitX64,
      packedSlot0Initial,
      bidPriceX64,
      askPriceX64,
      extensionData
    );
```

**File:** metric-core/contracts/ExtensionCalling.sol (L88-99)
```text
  function _beforeAddLiquidity(
    address sender,
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    bytes calldata extensionData
  ) internal {
    _callExtensionsInOrder(
      BEFORE_ADD_LIQUIDITY_ORDER,
      abi.encodeCall(IMetricOmmExtensions.beforeAddLiquidity, (sender, owner, salt, deltas, extensionData))
    );
  }
```

**File:** metric-periphery/contracts/extensions/SwapAllowlistExtension.sol (L31-41)
```text
  function beforeSwap(address sender, address, bool, int128, uint128, uint256, uint128, uint128, bytes calldata)
    external
    view
    override
    returns (bytes4)
  {
    if (!allowAllSwappers[msg.sender] && !allowedSwapper[msg.sender][sender]) {
      revert IMetricOmmPoolActions.NotAllowedToSwap();
    }
    return IMetricOmmExtensions.beforeSwap.selector;
  }
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L71-86)
```text
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

**File:** metric-periphery/contracts/extensions/DepositAllowlistExtension.sol (L32-42)
```text
  function beforeAddLiquidity(address, address owner, uint80, LiquidityDelta calldata, bytes calldata)
    external
    view
    override
    returns (bytes4)
  {
    if (!allowAllDepositors[msg.sender] && !allowedDepositor[msg.sender][owner]) {
      revert IMetricOmmPoolActions.NotAllowedToDeposit();
    }
    return IMetricOmmExtensions.beforeAddLiquidity.selector;
  }
```
