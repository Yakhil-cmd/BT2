The code is clear enough to render a verdict. Let me confirm the exact lines in the key files.

The call chain is fully traceable from the code. Here is the verdict:

---

### Title
SwapAllowlistExtension Checks Router Address Instead of End-User, Allowing Any User to Bypass Per-User Allowlist via MetricOmmSimpleRouter — (`metric-periphery/contracts/extensions/SwapAllowlistExtension.sol`)

---

### Summary

`SwapAllowlistExtension.beforeSwap` gates swaps by checking the `sender` argument it receives. That argument is `msg.sender` of `pool.swap()`. When a user routes through `MetricOmmSimpleRouter`, the caller of `pool.swap()` is the router contract, not the end user. Therefore, if the router is allowlisted, every user — regardless of their individual allowlist status — can trade in the gated pool.

---

### Finding Description

**Step 1 — Pool passes `msg.sender` of `swap()` to the extension.**

`MetricOmmPool.swap` calls `_beforeSwap(msg.sender, ...)`: [1](#0-0) 

`_beforeSwap` forwards that value as the `sender` argument to every configured extension: [2](#0-1) 

**Step 2 — Extension checks `allowedSwapper[pool][sender]`.**

`SwapAllowlistExtension.beforeSwap` uses `msg.sender` (the pool) as the pool key and the `sender` argument as the swapper key: [3](#0-2) 

**Step 3 — Router is `msg.sender` of `pool.swap()`, not the end user.**

`MetricOmmSimpleRouter.exactInputSingle` calls `pool.swap()` directly. At that call site, `msg.sender` inside the pool is the router address: [4](#0-3) 

The router records the original caller only in transient storage for the payment callback (`_setNextCallbackContext(..., msg.sender, ...)`), but that value is never forwarded to the pool or to any extension. [5](#0-4) 

**Result:** `allowedSwapper[pool][router] = true` satisfies the guard for every user who calls through the router, regardless of whether `allowedSwapper[pool][user]` is `false`.

---

### Impact Explanation

The `SwapAllowlistExtension` is the sole on-chain mechanism for restricting which addresses may trade in a gated pool. A pool admin who allowlists the router (a natural configuration for a pool that is meant to be accessible via the standard periphery) inadvertently opens the pool to every user of that router. The invariant that the allowlist gates individual traders is silently broken. Any non-allowlisted address can execute real swaps, receiving output tokens and draining pool liquidity, in a pool the admin intended to restrict.

This is an admin-boundary break: an unprivileged path (the public router) bypasses the pool admin's per-user access control.

---

### Likelihood Explanation

The router is the canonical public swap interface for the protocol. A pool admin who wants to allow router-based swaps while still gating individual users will naturally allowlist the router address. The `setAllowedToSwap` admin function gives no indication that allowlisting the router grants access to all router callers. The misconfiguration is easy to make and the bypass requires no special privileges — any EOA can call `exactInputSingle`.

---

### Recommendation

The extension must gate the **originating user**, not the immediate caller of `pool.swap()`. Two sound approaches:

1. **Pass the original caller through `extensionData`**: The router encodes `msg.sender` into `extensionData`; the extension decodes and verifies it. This requires a trust assumption that the router is the only allowed intermediary, which must be enforced separately.
2. **Check `tx.origin` as a fallback** (generally discouraged but sometimes used for allowlists in DeFi): replace the `sender` check with `tx.origin` when `sender` is a known router. This is fragile and not recommended.
3. **Preferred — document that the router must never be allowlisted as a swapper**: add an explicit guard in `setAllowedToSwap` that rejects known router addresses, or emit a clear warning. Pool admins must allowlist individual EOAs only.

The cleanest fix is option 1 combined with a router-level commitment that it always encodes the true originator.

---

### Proof of Concept

```
State:
  allowedSwapper[pool][router] = true
  allowedSwapper[pool][attacker] = false   // attacker is NOT individually allowlisted

Attack:
  attacker calls router.exactInputSingle({pool: pool, ...})
  → router calls pool.swap(...)            // msg.sender inside pool = router
  → pool calls _beforeSwap(router, ...)
  → SwapAllowlistExtension.beforeSwap(sender=router, ...)
  → allowedSwapper[pool][router] == true   // check passes
  → swap executes, attacker receives output tokens

Assert: swap succeeds despite attacker not being individually allowlisted.
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

**File:** metric-core/contracts/ExtensionCalling.sol (L149-177)
```text
  function _beforeSwap(
    address sender,
    address recipient,
    bool zeroForOne,
    int128 amountSpecified,
    uint128 priceLimitX64,
    uint256 packedSlot0Initial,
    uint128 bidPriceX64,
    uint128 askPriceX64,
    bytes calldata extensionData
  ) internal {
    _callExtensionsInOrder(
      BEFORE_SWAP_ORDER,
      abi.encodeCall(
        IMetricOmmExtensions.beforeSwap,
        (
          sender,
          recipient,
          zeroForOne,
          amountSpecified,
          priceLimitX64,
          packedSlot0Initial,
          bidPriceX64,
          askPriceX64,
          extensionData
        )
      )
    );
  }
```

**File:** metric-periphery/contracts/extensions/SwapAllowlistExtension.sol (L37-39)
```text
    if (!allowAllSwappers[msg.sender] && !allowedSwapper[msg.sender][sender]) {
      revert IMetricOmmPoolActions.NotAllowedToSwap();
    }
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L71-71)
```text
    _setNextCallbackContext(params.pool, CALLBACK_MODE_JUST_PAY, msg.sender, params.tokenIn);
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L72-80)
```text
    (int128 amount0Delta, int128 amount1Delta) = IMetricOmmPoolActions(params.pool)
      .swap(
        params.recipient,
        params.zeroForOne,
        MetricOmmSwapInputs.asAmountSpecifiedIn(params.amountIn),
        priceLimitX64,
        "",
        params.extensionData
      );
```
