### Title
Excess native ETH stranded in router after `exactOutputSingle`/`exactOutput` is claimable by any back-runner via `refundETH` — (`metric-periphery/contracts/MetricOmmSimpleRouter.sol`, `metric-periphery/contracts/base/PeripheryPayments.sol`)

---

### Summary

`exactOutputSingle` and `exactOutput` are `payable` functions that accept `msg.value` up to `amountInMaximum` as a slippage cap for native-ETH swaps. The internal `pay()` helper in `PeripheryPayments` consumes only the exact `amountIn` the pool requests, leaving `msg.value − amountIn` ETH stranded in the router. Because `refundETH()` has no access control and sends the entire ETH balance to `msg.sender`, any back-runner can immediately claim the leftover ETH.

---

### Finding Description

`exactOutputSingle` is declared `payable` and stores `msg.sender` as the payer in transient storage. [1](#0-0) 

During the swap callback, `_justPayCallback` calls `pay()` with `value = amountIn` — the exact amount the pool requested, not `msg.value`. [2](#0-1) 

Inside `pay()`, when `token == WETH` and `nativeBalance >= value`, only `value` wei is wrapped and forwarded; the remainder stays in the contract:

```solidity
uint256 nativeBalance = address(this).balance;
if (nativeBalance >= value) {
    IWETH9(WETH).deposit{value: value}();
    IERC20(WETH).safeTransfer(recipient, value);
}
``` [3](#0-2) 

`refundETH()` has no access control — it sends the entire ETH balance of the router to whoever calls it:

```solidity
function refundETH() external payable override {
    uint256 balance = address(this).balance;
    if (balance > 0) {
        _transferETH(msg.sender, balance);
    }
}
``` [4](#0-3) 

The same stranding applies to `exactOutput` (multi-hop exact-output), which is also `payable` and uses the same `pay()` path. [5](#0-4) 

The intended safe pattern — `multicall{value}([exactOutputSingle, refundETH])` — is demonstrated in tests but is **not enforced** at the contract level. [6](#0-5) 

---

### Impact Explanation

Any ETH sent as `msg.value` beyond the actual `amountIn` consumed by the pool is permanently accessible to any caller of `refundETH()` until claimed. A back-runner observing the victim's `exactOutputSingle` transaction in the mempool can submit a `refundETH()` call immediately after, stealing the full surplus. This is a direct, irreversible loss of user principal with no protocol-level guard preventing it.

---

### Likelihood Explanation

The pattern is triggered whenever a user calls `exactOutputSingle` or `exactOutput` directly with `msg.value > 0` without bundling a `refundETH` call in the same `multicall`. This is a natural mistake: the function signature accepts `amountInMaximum` as a slippage cap, and users unfamiliar with the Uniswap v3 multicall idiom will send `msg.value = amountInMaximum`. Any integrator or wallet that constructs a single-call transaction is vulnerable. The surplus is predictable from the public mempool, making back-running straightforward.

---

### Recommendation

Auto-refund the caller at the end of `exactOutputSingle` and `exactOutput` when `tokenIn == WETH` and `address(this).balance > 0`:

```solidity
// at the end of exactOutputSingle / exactOutput, after _clearExpectedCallbackPool():
uint256 surplus = address(this).balance;
if (surplus > 0) _transferETH(msg.sender, surplus);
```

Alternatively, document prominently that these functions **must** be called via `multicall` with a trailing `refundETH()` whenever native ETH is supplied, and consider adding a revert guard if `msg.value > 0` is detected outside a multicall context.

---

### Proof of Concept

1. Alice wants to buy exactly 1 000 token1 for WETH/ETH. She calls:
   ```
   router.exactOutputSingle{value: 2 ether}(
       amountOut: 1_000,
       amountInMaximum: 2 ether,
       tokenIn: WETH,
       ...
   )
   ```
2. The pool requires only `1.2 ether` of WETH input. `pay()` wraps and forwards exactly `1.2 ether`; `0.8 ether` remains in the router. [3](#0-2) 
3. Bob observes Alice's transaction in the mempool and immediately submits:
   ```
   router.refundETH()   // msg.sender = Bob
   ```
4. `refundETH()` sends `address(router).balance` (= `0.8 ether`) to Bob. [4](#0-3) 
5. Alice loses `0.8 ether` with no recourse. The same attack applies to `exactOutput` (multi-hop) and to any `exactInputSingle` call where `msg.value > amountIn`. [7](#0-6)

### Citations

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L130-147)
```text
  function exactOutputSingle(ExactOutputSingleParams calldata params) external payable returns (uint256 amountIn) {
    _checkDeadline(params.deadline);
    uint128 priceLimitX64 = MetricOmmSwapPath.normalizePriceLimit(params.zeroForOne, params.priceLimitX64);

    int128 expectedAmountOut = MetricOmmSwapInputs.asAmountSpecifiedIn(params.amountOut);
    _setNextCallbackContext(params.pool, CALLBACK_MODE_JUST_PAY, msg.sender, params.tokenIn);
    (int128 amount0Delta, int128 amount1Delta) = IMetricOmmPoolActions(params.pool)
      .swap(params.recipient, params.zeroForOne, -expectedAmountOut, priceLimitX64, "", params.extensionData);
    int128 amountOut = MetricOmmSwapResults.extractAmountOut(params.zeroForOne, amount0Delta, amount1Delta);
    if (amountOut != expectedAmountOut) revert InvalidOutputAmount(amountOut, params.amountOut);

    amountIn = MetricOmmSwapInputs.int128ToUint128(
      MetricOmmSwapResults.extractAmountIn(params.zeroForOne, amount0Delta, amount1Delta)
    );

    if (amountIn > params.amountInMaximum) revert InputTooHigh(amountIn, params.amountInMaximum);
    _clearExpectedCallbackPool();
  }
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L154-188)
```text
  function exactOutput(ExactOutputParams calldata params) external payable returns (uint256 amountIn) {
    _checkDeadline(params.deadline);
    _validatePath(params.tokens, params.pools, params.extensionDatas);

    uint8 tradesLeftAfterThis = uint8(params.pools.length - 1);
    address pool = params.pools[tradesLeftAfterThis];
    bool zeroForOne = MetricOmmSwapPath.resolveZeroForOneBitmap(params.zeroForOneBitMap, tradesLeftAfterThis);
    int128 expectedAmountOut = MetricOmmSwapInputs.asAmountSpecifiedIn(params.amountOut);
    _initCallbackContextforRecursiveOutput(
      pool, CALLBACK_MODE_EXACT_OUTPUT_ITERATE, tradesLeftAfterThis, msg.sender, params.tokens[0]
    );
    (int128 amount0Delta, int128 amount1Delta) = IMetricOmmPoolActions(pool)
      .swap(
        params.recipient,
        zeroForOne,
        -expectedAmountOut,
        MetricOmmSwapPath.openLimit(zeroForOne),
        abi.encode(
          ExactOutputIterateCallbackData({
          tokens: params.tokens,
          pools: params.pools,
          extensionDatas: params.extensionDatas,
          zeroForOneBitMap: params.zeroForOneBitMap,
          amountInMax: params.amountInMaximum
        })
        ),
        params.extensionDatas[tradesLeftAfterThis]
      );

    int128 amountOut = MetricOmmSwapResults.extractAmountOut(zeroForOne, amount0Delta, amount1Delta);
    if (amountOut != expectedAmountOut) revert InvalidOutputAmount(amountOut, params.amountOut);

    amountIn = _getExactOutputAmountIn();
    _clearExpectedCallbackPool();
  }
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

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L58-63)
```text
  function refundETH() external payable override {
    uint256 balance = address(this).balance;
    if (balance > 0) {
      _transferETH(msg.sender, balance);
    }
  }
```

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L74-77)
```text
      uint256 nativeBalance = address(this).balance;
      if (nativeBalance >= value) {
        IWETH9(WETH).deposit{value: value}();
        IERC20(WETH).safeTransfer(recipient, value);
```

**File:** metric-periphery/test/MetricOmmSimpleRouter.native.t.sol (L106-133)
```text
  function test_multicall_ethInput_exactInputSingle_refundsUnusedEth() public {
    uint128 amountIn = 1_000;
    uint256 msgValue = 2 ether;
    uint256 swapperEthBefore = swapper.balance;

    vm.prank(swapper);
    bytes[] memory calls = new bytes[](2);
    calls[0] = abi.encodeWithSelector(
      router.exactInputSingle.selector,
      IMetricOmmSimpleRouter.ExactInputSingleParams({
        pool: address(pool),
        tokenIn: address(weth),
        tokenOut: address(token1),
        zeroForOne: true,
        amountIn: amountIn,
        amountOutMinimum: 0,
        recipient: recipient,
        deadline: _deadline(),
        priceLimitX64: 0,
        extensionData: ""
      })
    );
    calls[1] = abi.encodeWithSelector(router.refundETH.selector);
    router.multicall{value: msgValue}(calls);

    assertEq(swapper.balance, swapperEthBefore - amountIn, "unused eth refunded");
    _assertRouterEmpty();
  }
```
