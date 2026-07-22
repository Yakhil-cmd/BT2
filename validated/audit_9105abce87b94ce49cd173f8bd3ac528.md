The code trace is clear. Let me walk through the exact mechanics:

**`pay()` in `PeripheryPayments.sol` lines 74-77:**
When `nativeBalance >= value`, it deposits only `value` (amountIn) as WETH — not the full `msg.value`. The surplus `msg.value - amountIn` stays on the router after `exactInputSingle` returns.

**`refundETH()` lines 58-63:**
No access control. Sends `address(this).balance` — the entire router ETH balance — to `msg.sender`.

**Attack path:**
1. User A calls `exactInputSingle{value: 2 ETH}(amountIn: 1000 wei, tokenIn: WETH, ...)` directly (not via multicall)
2. `pay()` deposits 1000 wei as WETH → pool; `2 ETH - 1000 wei` remains on router
3. User B calls `refundETH()` in a separate tx → receives `2 ETH - 1000 wei`
4. User A's subsequent `refundETH()` returns 0

The `receive()` guard [1](#0-0)  blocks direct ETH pushes but does not prevent ETH arriving via `msg.value` on payable entry points. The surplus accumulates silently.

The intended safe pattern is `multicall([exactInputSingle, refundETH])` — demonstrated in `test_multicall_ethInput_exactInputSingle_refundsUnusedEth` — but `exactInputSingle` is a standalone `external payable` function with no enforcement of that pattern. Any user calling it directly with excess ETH is exposed.

---

### Title
Unguarded `refundETH()` allows any caller to drain residual ETH left by a prior user's excess-ETH swap — (`metric-periphery/contracts/base/PeripheryPayments.sol`)

### Summary
`refundETH()` sends the router's entire ETH balance to `msg.sender` with no ownership check. Because `pay()` deposits only the exact `amountIn` when `msg.value >= amountIn`, any surplus ETH from a standalone `exactInputSingle` (or `exactInput`, `exactOutputSingle`, `exactOutput`) call persists on the router after the transaction ends. A subsequent caller — including an MEV bot — can immediately drain it.

### Finding Description
`PeripheryPayments.pay()` handles native-ETH-as-WETH payment by branching on `nativeBalance`:

```solidity
if (nativeBalance >= value) {
    IWETH9(WETH).deposit{value: value}();   // only `value` consumed
    IERC20(WETH).safeTransfer(recipient, value);
    // surplus msg.value - value stays on router
}
``` [2](#0-1) 

After the swap callback settles, `exactInputSingle` returns without sweeping the surplus: [3](#0-2) 

`refundETH()` then unconditionally transfers the full balance to whoever calls it next:

```solidity
function refundETH() external payable override {
    uint256 balance = address(this).balance;
    if (balance > 0) {
        _transferETH(msg.sender, balance);   // no caller check
    }
}
``` [4](#0-3) 

### Impact Explanation
Direct loss of user principal. A user who sends `2 ETH` for a `1000 wei` swap loses `~2 ETH - 1000 wei` to the first caller of `refundETH()` after their transaction. The amount is bounded only by what the victim sends; large-value swaps with ETH overpayment (common for slippage headroom) are fully drained.

### Likelihood Explanation
MEV bots routinely monitor for profitable `refundETH()` opportunities on Uniswap-style routers. Any user who calls a payable swap function directly (not via multicall) with excess ETH is immediately at risk. No special permissions or setup required.

### Recommendation
Track the per-call ETH contribution in transient storage at the start of each payable entry point and restrict `refundETH()` to return only that amount to the original `msg.sender`. Alternatively, enforce that all ETH-paying swaps go through `multicall` and auto-refund surplus inside each swap function before returning.

### Proof of Concept
```solidity
// User A: sends 2 ETH, swaps only 1000 wei worth
router.exactInputSingle{value: 2 ether}(ExactInputSingleParams({
    tokenIn: WETH, amountIn: 1000, ...
}));
// router.balance == 2 ether - 1000 wei after tx

// User B (attacker): drains it
router.refundETH();  // receives 2 ether - 1000 wei

// User A tries to recover:
router.refundETH();  // receives 0
```

### Citations

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L32-34)
```text
  receive() external payable {
    if (msg.sender != WETH) revert NotWETH();
  }
```

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L58-63)
```text
  function refundETH() external payable override {
    uint256 balance = address(this).balance;
    if (balance > 0) {
      _transferETH(msg.sender, balance);
    }
  }
```

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L75-77)
```text
      if (nativeBalance >= value) {
        IWETH9(WETH).deposit{value: value}();
        IERC20(WETH).safeTransfer(recipient, value);
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
