### Title
`SwapAllowlistExtension` gates the router address instead of the actual swapper, enabling allowlist bypass via `MetricOmmSimpleRouter` — (`metric-periphery/contracts/extensions/SwapAllowlistExtension.sol`)

---

### Summary

When a user swaps through `MetricOmmSimpleRouter`, the router is `msg.sender` to `MetricOmmPool.swap()`. The pool passes that `msg.sender` as the `sender` argument to every configured extension. `SwapAllowlistExtension.beforeSwap` checks `allowedSwapper[pool][sender]`, so it checks whether the **router** is allowlisted, not the actual end user. If the pool admin allowlists the router to enable router-mediated swaps, every unprivileged user can bypass the swap allowlist by routing through the router.

---

### Finding Description

**Call chain:**

1. User calls `MetricOmmSimpleRouter.exactInputSingle()` (or `exactInput` / `exactOutput`).
2. The router calls `IMetricOmmPoolActions(pool).swap(recipient, zeroForOne, amount, priceLimit, "", extensionData)`.
3. Inside `MetricOmmPool.swap()`, `msg.sender` is the router address.
4. The pool calls `_beforeSwap(msg.sender, recipient, ...)`, forwarding the router address as `sender`.
5. `ExtensionCalling._beforeSwap` encodes `abi.encodeCall(IMetricOmmExtensions.beforeSwap, (sender=router, ...))` and dispatches to `SwapAllowlistExtension`.
6. `SwapAllowlistExtension.beforeSwap` checks `allowedSwapper[msg.sender][sender]` = `allowedSwapper[pool][router]`.

The check is on the router's address, not the actual user's address.

**Relevant code:**

`MetricOmmPool.swap` passes `msg.sender` (= router) as `sender`: [1](#0-0) 

`ExtensionCalling._beforeSwap` forwards that `sender` verbatim to the extension: [2](#0-1) 

`SwapAllowlistExtension.beforeSwap` checks `allowedSwapper[pool][sender]` where `sender` is the router: [3](#0-2) 

`MetricOmmSimpleRouter.exactInputSingle` calls `pool.swap()` directly, making the router `msg.sender` to the pool: [4](#0-3) 

---

### Impact Explanation

**Scenario A — Allowlist bypass (High):**
The pool admin deploys a curated pool (e.g., KYC-only) with `SwapAllowlistExtension`. To allow allowlisted users to use the router, the admin adds the router to `allowedSwapper[pool][router] = true`. From that moment, **any** unprivileged user can call `router.exactInputSingle()` and the extension passes, because it only checks whether the router is allowlisted. The entire swap allowlist is bypassed for all router-mediated swaps.

**Scenario B — Router DoS (Medium):**
If the admin allowlists individual users but does not add the router, those users cannot use the router at all — the extension sees `sender = router` and reverts `NotAllowedToSwap`. Core swap functionality through the supported periphery path is broken for all allowlisted users.

Both impacts are reachable by any unprivileged caller with no special setup beyond using the public router.

---

### Likelihood Explanation

Any pool that deploys `SwapAllowlistExtension` and expects users to interact via `MetricOmmSimpleRouter` is affected. The router is the primary public swap entrypoint in `metric-periphery`. The pool admin has no way to simultaneously (a) restrict swaps to specific users and (b) allow those users to use the router, because the extension cannot distinguish the actual user from the router.

---

### Recommendation

Pass the actual end user's address through the router to the extension. Two approaches:

1. **Preferred — use `extensionData` for user identity:** The router encodes `msg.sender` into `extensionData` and the extension decodes it. This requires the extension to trust the router, which can be enforced by checking `sender == trustedRouter` before accepting the decoded identity.

2. **Alternative — check `sender` only when not a trusted router:** In `SwapAllowlistExtension.beforeSwap`, if `sender` is a known trusted router, decode the real user from `extensionData`; otherwise check `sender` directly.

The deposit path already handles this correctly: `DepositAllowlistExtension.beforeAddLiquidity` ignores the `sender` (operator/adder) and checks `owner` instead, which is the economically relevant identity. [5](#0-4) 

The swap path needs an equivalent separation between the intermediary (`sender` = router) and the actual swapper.

---

### Proof of Concept

```
Setup:
  - Deploy pool with SwapAllowlistExtension configured on beforeSwap
  - Pool admin calls setAllowedToSwap(pool, router, true)  // to enable router usage
  - Pool admin does NOT allowlist attacker (attacker is not KYC'd)

Attack:
  - attacker calls MetricOmmSimpleRouter.exactInputSingle({pool, ...})
  - Router calls pool.swap(...) with msg.sender = router
  - Pool calls _beforeSwap(sender=router, ...)
  - SwapAllowlistExtension checks allowedSwapper[pool][router] == true → passes
  - Attacker's swap executes on the curated pool despite not being allowlisted

Result:
  - Swap allowlist is fully bypassed for any user routing through MetricOmmSimpleRouter
  - Curated pool policy is violated; unauthorized users trade against LP funds
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
