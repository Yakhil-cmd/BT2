The vulnerability is real. Let me trace it precisely.

**`pay()` uses `address(this).balance` globally** — it reads the router's entire native ETH balance, not just the ETH sent in the current transaction: [1](#0-0) 

**ETH accumulates on the router** when a user sends `msg.value > amountIn` to a payable swap function and does not call `refundETH()` in the same multicall. The `receive()` guard only blocks bare ETH transfers; `msg.value` in a payable function call bypasses it entirely: [2](#0-1) 

The intended safe pattern (multicall + `refundETH()`) is shown in tests but is **not enforced**: [3](#0-2) 

Neither `exactInputSingle` nor `exactInput` calls `refundETH()` automatically: [4](#0-3) 

---

### Title
Residual ETH on Router Stolen via `PeripheryPayments.pay()` WETH Branch — (`metric-periphery/contracts/base/PeripheryPayments.sol`)

### Summary
`PeripheryPayments.pay()` uses `address(this).balance` to determine how much native ETH to wrap toward a WETH payment. Because the router is stateless between transactions and `refundETH()` is never called automatically, any ETH left on the router from a prior user's overpayment is silently consumed by the next caller who swaps with WETH as `tokenIn`.

### Finding Description
In `pay()`, when `token == WETH` and `payer != address(this)`, the function reads `nativeBalance = address(this).balance`. If `nativeBalance > 0` but `< value`, it wraps the full native balance and only calls `transferFrom(payer, …, value - nativeBalance)` for the remainder. There is no per-transaction ETH accounting; the balance check is global across all callers.

ETH accumulates on the router whenever a user calls `exactInputSingle{value: V}(amountIn: X)` with `V > X` and does not atomically call `refundETH()`. The excess `V - X` ETH remains on the router indefinitely.

An attacker observing this residual balance calls `exactInputSingle{value: 0}(tokenIn: WETH, amountIn: R)` where `R ≤ residual`. The `pay()` WETH branch wraps the router's `R` ETH and sends it to the pool. The attacker's `transferFrom` is called for `0` (or a reduced amount), so the attacker receives the full swap output while paying nothing (or less than owed) in WETH.

### Impact Explanation
Direct loss of user principal: the ETH left on the router by User A is consumed to fund Attacker's swap. User A loses their residual ETH; Attacker receives a subsidized or free swap. The pool itself is made whole (it receives the correct WETH amount), so pool solvency is unaffected, but the victim loses their ETH.

### Likelihood Explanation
Any user who calls a payable swap function with `msg.value > amountIn` and omits `refundETH()` — a natural mistake when not using multicall — creates an exploitable residual. The attacker needs only to monitor the router's ETH balance and call `exactInputSingle` with WETH as `tokenIn`.

### Recommendation
In `pay()`, only use `msg.value` (passed as a parameter) rather than `address(this).balance`, so only ETH explicitly sent in the current call can be applied. Alternatively, track per-call ETH consumed in transient storage and zero it out at the end of each top-level entry point, or enforce that `refundETH()` is called at the end of every payable entry point.

### Proof of Concept
1. User A calls `router.exactInputSingle{value: 2 ether}(ExactInputSingleParams{tokenIn: WETH, amountIn: 1000, …})` without a subsequent `refundETH()`. The router wraps 1000 wei; `2 ether - 1000 wei` remains on the router.
2. Attacker calls `router.exactInputSingle{value: 0}(ExactInputSingleParams{tokenIn: WETH, amountIn: 1000, …})`.
3. Inside `pay()`: `nativeBalance = 2 ether - 1000 wei ≥ 1000`, so the router wraps 1000 wei from its balance and transfers WETH to the pool. `transferFrom(attacker, …)` is never called.
4. Attacker receives the full swap output; User A's 1000 wei (and the rest of the residual) is consumed. User A's `2 ether - 1000 wei` is permanently lost.

### Citations

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L32-34)
```text
  receive() external payable {
    if (msg.sender != WETH) revert NotWETH();
  }
```

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L73-84)
```text
    } else if (token == WETH) {
      uint256 nativeBalance = address(this).balance;
      if (nativeBalance >= value) {
        IWETH9(WETH).deposit{value: value}();
        IERC20(WETH).safeTransfer(recipient, value);
      } else if (nativeBalance > 0) {
        IWETH9(WETH).deposit{value: nativeBalance}();
        IERC20(WETH).safeTransfer(recipient, nativeBalance);
        IERC20(WETH).safeTransferFrom(payer, recipient, value - nativeBalance);
      } else {
        IERC20(WETH).safeTransferFrom(payer, recipient, value);
      }
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
