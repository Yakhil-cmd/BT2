The call chain is fully traceable and the vulnerability is real. Here is the complete analysis:

---

### Title
SwapAllowlistExtension Checks Router Address Instead of Original EOA, Allowing Any User to Bypass Curated-Pool Swap Gate — (`metric-periphery/contracts/extensions/SwapAllowlistExtension.sol`)

### Summary

`SwapAllowlistExtension.beforeSwap` gates swaps by checking `allowedSwapper[pool][sender]`, where `sender` is the `msg.sender` of the `pool.swap()` call. When a user routes through `MetricOmmSimpleRouter`, the pool's `msg.sender` is the **router address**, not the original EOA. If the pool admin allowlists the router (the natural configuration for router-mediated swaps), every non-allowlisted user can bypass the gate by routing through the router.

### Finding Description

The call chain is:

```
EOA (non-allowlisted)
  → MetricOmmSimpleRouter.exactInputSingle()
      → pool.swap(recipient, ...) [msg.sender = router]
          → _beforeSwap(msg.sender=router, ...)
              → SwapAllowlistExtension.beforeSwap(sender=router, ...)
                  → allowedSwapper[pool][router] == true  ✓  (bypass)
```

**Step 1 — Router calls pool with itself as `msg.sender`:**

In `MetricOmmSimpleRouter.exactInputSingle()`, the router calls `pool.swap()` directly. The pool sees `msg.sender = router`. [1](#0-0) 

**Step 2 — Pool passes `msg.sender` (router) as `sender` to `_beforeSwap`:**

`MetricOmmPool.swap()` passes `msg.sender` — the router — as the `sender` argument to `_beforeSwap`. The original EOA identity is never forwarded. [2](#0-1) 

**Step 3 — `_beforeSwap` encodes `sender=router` and calls the extension:**

`ExtensionCalling._beforeSwap` encodes the `sender` argument (router address) into the call to the extension. [3](#0-2) 

**Step 4 — Extension checks `allowedSwapper[pool][router]`, not the original EOA:**

`SwapAllowlistExtension.beforeSwap` checks `allowedSwapper[msg.sender][sender]` where `msg.sender` is the pool and `sender` is the router. If the router is allowlisted, the check passes for any caller. [4](#0-3) 

### Impact Explanation

A pool admin deploying a curated pool with `SwapAllowlistExtension` intends to restrict swaps to specific counterparties (e.g., KYC'd addresses, protocol-controlled addresses). If the router is allowlisted to enable normal router-mediated swaps, the allowlist is completely nullified: any non-allowlisted EOA can call `exactInputSingle` through the router and execute swaps on the restricted pool. This directly violates the swap policy and exposes LP principal to unauthorized counterparties, which is the core purpose of the extension.

**Impact: High** — complete bypass of the curated-pool swap policy; LP principal is exposed to unrestricted counterparties.

### Likelihood Explanation

**Likelihood: High** — The router is a public, permissionless contract. Allowlisting the router is the expected and natural configuration for any pool that wants to support router-mediated swaps while still restricting direct callers. The bypass requires no special knowledge or privilege: any EOA simply calls `exactInputSingle` on the router pointing at the restricted pool.

### Recommendation

The extension must gate on the **original initiator**, not the intermediate caller. Two options:

1. **Pass the original `msg.sender` through `extensionData`**: The router encodes `msg.sender` into `extensionData` and the extension decodes and checks it. This requires a convention between router and extension.
2. **Check `recipient` instead of `sender`**: If the pool's intent is to restrict who receives output, check the `recipient` argument. However, this does not cover the case where the attacker sets themselves as recipient.
3. **Preferred — extension reads `tx.origin` or a trusted forwarder pattern**: The extension could check `tx.origin` when `sender` is a known trusted router, falling back to `sender` otherwise. This is the most robust fix without changing the pool interface.

### Proof of Concept

```solidity
// Foundry integration test
function test_routerBypassesSwapAllowlist() public {
    // Deploy pool with SwapAllowlistExtension
    SwapAllowlistExtension ext = new SwapAllowlistExtension(address(factory));
    // ... deploy pool with ext as beforeSwap extension ...

    // Admin allowlists only the router (natural config)
    vm.prank(poolAdmin);
    ext.setAllowedToSwap(address(pool), address(router), true);

    // Attacker is NOT allowlisted
    assertFalse(ext.isAllowedToSwap(address(pool), attacker));

    // Attacker routes through the router — swap succeeds, bypassing the gate
    vm.prank(attacker);
    router.exactInputSingle(IMetricOmmSimpleRouter.ExactInputSingleParams({
        pool: address(pool),
        tokenIn: token0,
        tokenOut: token1,
        zeroForOne: true,
        amountIn: 1000,
        amountOutMinimum: 0,
        recipient: attacker,
        deadline: block.timestamp + 1,
        priceLimitX64: 0,
        extensionData: ""
    }));
    // Assert: swap succeeded despite attacker not being allowlisted
}
```

### Citations

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L71-80)
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
```

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
