The call chain is fully traceable. Let me confirm the exact values at each step.

**Call chain:**

1. User calls `MetricOmmSimpleRouter.exactInput` / `exactInputSingle`
2. Router calls `pool.swap(recipient, ...)` — so `msg.sender` inside `pool.swap` = **router address**
3. `MetricOmmPool.swap` calls `_beforeSwap(msg.sender, ...)` — passes `sender = router`
4. `ExtensionCalling._beforeSwap` encodes and calls `extension.beforeSwap(sender=router, ...)`
5. `SwapAllowlistExtension.beforeSwap` checks: `allowedSwapper[msg.sender][sender]` = `allowedSwapper[pool][router]`

**Exact code evidence:**

`MetricOmmPool.swap` passes `msg.sender` as `sender`: [1](#0-0) 

`SwapAllowlistExtension.beforeSwap` checks `allowedSwapper[msg.sender][sender]` where `msg.sender=pool`, `sender=router`: [2](#0-1) 

**The invariant break:** The extension gates on `allowedSwapper[pool][router]`, not `allowedSwapper[pool][user]`. This creates two mutually exclusive failure modes:

- If the pool admin does **not** allowlist the router: allowlisted users cannot swap through the router at all (their swaps revert because `allowedSwapper[pool][router] = false`)
- If the pool admin **does** allowlist the router (to enable router-mediated swaps for their allowlisted users): **every** public user can bypass the per-user allowlist by routing through `MetricOmmSimpleRouter`

The pool admin has no way to achieve the intended invariant — "only allowlisted users may swap, including via the router" — because the extension receives the router's address as `sender`, not the originating user's address.

The bypass path is fully unprivileged: any user calls `MetricOmmSimpleRouter.exactInputSingle` or `exactInput` on a pool where the router has been allowlisted.

---

### Title
SwapAllowlistExtension gates the router address instead of the economic actor, allowing any user to bypass per-user swap restrictions via MetricOmmSimpleRouter — (`metric-periphery/contracts/extensions/SwapAllowlistExtension.sol`)

### Summary
`SwapAllowlistExtension.beforeSwap` receives `sender = msg.sender` of `pool.swap`. When a swap is routed through `MetricOmmSimpleRouter`, `msg.sender` of `pool.swap` is the router contract, not the originating user. The allowlist check therefore evaluates `allowedSwapper[pool][router]` rather than `allowedSwapper[pool][user]`, making it impossible to enforce per-user swap restrictions for router-mediated swaps.

### Finding Description
`MetricOmmPool.swap` passes `msg.sender` as the `sender` argument to `_beforeSwap`:

```solidity
// MetricOmmPool.sol:230
_beforeSwap(msg.sender, recipient, ...);
```

When `MetricOmmSimpleRouter.exactInputSingle` (or `exactInput`) calls `pool.swap`, `msg.sender` inside the pool is the router. The extension therefore receives `sender = router`:

```solidity
// SwapAllowlistExtension.sol:37
if (!allowAllSwappers[msg.sender] && !allowedSwapper[msg.sender][sender]) {
    revert IMetricOmmPoolActions.NotAllowedToSwap();
}
```

Here `msg.sender = pool` and `sender = router`. The check is `allowedSwapper[pool][router]`.

A pool admin who wants to allow router-mediated swaps for their allowlisted users must set `allowedSwapper[pool][router] = true`. Once that entry is set, **any** caller of `MetricOmmSimpleRouter` passes the check, regardless of whether they are individually allowlisted.

### Impact Explanation
The `SwapAllowlistExtension` is rendered ineffective for router-mediated swaps. Any user can bypass a per-user swap allowlist by routing through the public `MetricOmmSimpleRouter`. Pools that rely on this extension to restrict swap access (e.g., institutional or permissioned pools) have their access control silently broken. Unauthorized swaps can drain pool liquidity at oracle-quoted prices, constituting direct loss of LP assets.

### Likelihood Explanation
`MetricOmmSimpleRouter` is the canonical public swap interface. Pool admins who configure `SwapAllowlistExtension` and also want to support router-mediated swaps for their allowlisted users will naturally allowlist the router, unknowingly opening the bypass to all users. The attacker needs no special privileges — only knowledge of the router address and a standard ERC-20 approval.

### Recommendation
Pass the originating user identity through the swap path. Options:
1. Have `MetricOmmPool.swap` accept an explicit `swapper` parameter (separate from `msg.sender`) that periphery contracts populate with `msg.sender` before calling the pool, and pass that value to `_beforeSwap`.
2. Alternatively, `SwapAllowlistExtension.beforeSwap` could check both `sender` (the direct caller) and a user-supplied identity embedded in `extensionData`, with the router forwarding `msg.sender` there.

### Proof of Concept
```
1. Deploy pool with SwapAllowlistExtension configured.
2. Pool admin calls setAllowedToSwap(pool, router, true)  // to enable router swaps
3. Non-allowlisted user Bob calls MetricOmmSimpleRouter.exactInputSingle(pool, ...)
4. pool.swap is called with msg.sender = router
5. _beforeSwap(sender=router, ...) → allowedSwapper[pool][router] = true → no revert
6. Bob's swap executes despite not being individually allowlisted.
``` [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L217-240)
```text
  function swap(
    address recipient,
    bool zeroForOne,
    int128 amountSpecified,
    uint128 priceLimitX64,
    bytes calldata callbackData,
    bytes calldata extensionData
  ) external whenNotPaused nonReentrant(PoolActions.SWAP) returns (int128, int128) {
    require(amountSpecified != 0, InvalidAmount());

    uint256 packedSlot0Initial = Slot0Library.loadPackedSlot0();
    (uint128 bidPriceX64, uint128 askPriceX64) = _getBidAndAskPriceX64();

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
