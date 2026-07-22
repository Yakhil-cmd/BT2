The call chain is fully traceable. Here is the exact flow:

1. `MetricOmmSimpleRouter.exactInputSingle` (called by trader EOA) calls `IMetricOmmPoolActions(params.pool).swap(params.recipient, ...)` — the router is `msg.sender` from the pool's perspective. [1](#0-0) 

2. `MetricOmmPool.swap` calls `_beforeSwap(msg.sender, ...)` — `msg.sender` here is the **router**, not the trader EOA. [2](#0-1) 

3. `SwapAllowlistExtension.beforeSwap` receives `sender = router` and checks `allowedSwapper[msg.sender][sender]` — i.e., `allowedSwapper[pool][router]`. If the router is allowlisted, the check passes for **any** trader who routes through it. [3](#0-2) 

The trader's EOA is never surfaced to the extension. The extension's `sender` parameter is always the immediate `msg.sender` of `pool.swap`, which is the router contract.

---

### Title
`SwapAllowlistExtension` allowlist bypassed via `MetricOmmSimpleRouter` — (`metric-periphery/contracts/extensions/SwapAllowlistExtension.sol`)

### Summary
`SwapAllowlistExtension.beforeSwap` gates swaps on `allowedSwapper[pool][sender]`, where `sender` is the `msg.sender` of `MetricOmmPool.swap`. When a trader routes through `MetricOmmSimpleRouter`, `sender` is the router address, not the trader's EOA. Allowlisting the router therefore grants unrestricted swap access to every user of the router, defeating the extension's purpose.

### Finding Description
`MetricOmmPool.swap` passes `msg.sender` as the `sender` argument to `_beforeSwap`:

```solidity
// MetricOmmPool.sol:230-231
_beforeSwap(
  msg.sender,   // ← router address when called via router
  ...
```

`SwapAllowlistExtension.beforeSwap` then checks:

```solidity
// SwapAllowlistExtension.sol:37
if (!allowAllSwappers[msg.sender] && !allowedSwapper[msg.sender][sender]) {
```

Here `msg.sender` is the pool and `sender` is the router. The trader's EOA is never visible to the extension. A pool admin who allowlists the router address (a natural operational choice to enable router-based trading) inadvertently allowlists every user of that router.

### Impact Explanation
Any trader can execute swaps on a curated pool whose `SwapAllowlistExtension` was configured to restrict access to specific addresses. The swap policy is completely bypassed: the pool receives and settles real token flows from unauthorized counterparties, violating the invariant the extension was deployed to enforce. Depending on the pool's purpose (e.g., institutional-only, KYC-gated, whitelist-only market-making), this constitutes broken core functionality and potential direct economic harm to LPs who deposited under the assumption that only approved counterparties could trade.

### Likelihood Explanation
The router is a first-party periphery contract. Pool admins who want to support router-based trading while restricting direct EOA access will naturally allowlist the router. The bypass requires no special privileges — any EOA can call `exactInputSingle`.

### Recommendation
The router should forward the originating trader's identity to the pool, and the pool should pass it to extensions as a separate `originator` parameter distinct from `sender`. Alternatively, `SwapAllowlistExtension` should check `tx.origin` (with appropriate caveats) or require the router to pass the trader address in `extensionData` and have the extension decode it. The cleanest fix is to add an `originator` field to the swap extension interface so the pool can pass both `msg.sender` (the immediate caller) and the economic initiator.

### Proof of Concept
1. Deploy pool with `SwapAllowlistExtension` configured in `beforeSwap` order.
2. Call `swapExtension.setAllowedToSwap(pool, router, true)` — allowlist only the router.
3. Assert `swapExtension.isAllowedToSwap(pool, traderEOA)` returns `false`.
4. Have `traderEOA` call `router.exactInputSingle(...)` targeting the pool.
5. Observe the swap succeeds: `SwapAllowlistExtension.beforeSwap` receives `sender = router`, finds it allowlisted, and returns the success selector — the trader's EOA was never checked.
6. Confirm that `traderEOA` calling `pool.swap(...)` directly reverts with `NotAllowedToSwap`.

### Citations

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
