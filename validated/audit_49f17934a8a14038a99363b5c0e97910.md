### Title
Excess `msg.value` Sent to Non-WETH Swap or Liquidity Functions Is Permanently Stranded and Stealable via Unguarded `refundETH()` — (`metric-periphery/contracts/base/PeripheryPayments.sol`, `metric-periphery/contracts/MetricOmmSimpleRouter.sol`, `metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol`)

---

### Summary

Every swap and liquidity entry-point in `MetricOmmSimpleRouter` and `MetricOmmPoolLiquidityAdder` is declared `payable`, yet the internal `pay()` helper only consumes native ETH when the token being paid is exactly `WETH`. When a caller sends `msg.value > 0` alongside a non-WETH token swap or liquidity deposit, the ETH is silently left in the router/adder contract. Because `refundETH()` is an unguarded `external payable` function that sweeps the entire contract balance to `msg.sender`, any third party can immediately steal the stranded ETH in the same block.

---

### Finding Description

**Step 1 – All entry-points are `payable` with no `msg.value` guard.**

`exactInputSingle`, `exactInput`, `exactOutputSingle`, `exactOutput`, and `multicall` in `MetricOmmSimpleRouter` are all declared `external payable`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

The same applies to `addLiquidityExactShares` and `addLiquidityWeighted` in `MetricOmmPoolLiquidityAdder`. [5](#0-4) 

None of these functions check `msg.value == 0` when the input token is not `WETH`.

**Step 2 – `pay()` only consumes native ETH for `token == WETH`.**

The entire payment logic is in `PeripheryPayments.pay()`. The three branches are:

```
payer == address(this)  →  ERC-20 safeTransfer
token == WETH           →  wrap native ETH, then safeTransfer WETH
else                    →  ERC-20 safeTransferFrom (native ETH untouched)
``` [6](#0-5) 

When `tokenIn` is any ERC-20 other than WETH, the `else` branch fires: `safeTransferFrom` pulls the ERC-20 from the payer, and any ETH that arrived with the call remains in the contract's balance untouched.

**Step 3 – `refundETH()` has no access control and sweeps to `msg.sender`.**

```solidity
function refundETH() external payable override {
    uint256 balance = address(this).balance;
    if (balance > 0) {
        _transferETH(msg.sender, balance);
    }
}
``` [7](#0-6) 

There is no check that `msg.sender` is the original depositor. Any caller receives the full ETH balance of the contract.

**Step 4 – `receive()` does not protect against payable function calls.**

The `receive()` guard that reverts non-WETH senders only applies to plain ETH transfers (no calldata). It does not intercept ETH sent alongside a function call, so the `payable` entry-points freely accept ETH from any caller. [8](#0-7) 

**Step 5 – The interface itself documents the scope mismatch.**

The `IMetricOmmSimpleRouter` NatSpec explicitly states: *"Scope: ERC-20 routes only. No native ETH, WETH wrap/unwrap…"*, yet the functions are `payable` and inherit `IPeripheryPayments` (which includes `refundETH`). This confirms the design intent is ERC-20-only, but the missing `msg.value == 0` guard creates the gap. [9](#0-8) 

---

### Impact Explanation

A user who sends ETH alongside a non-WETH swap (e.g., swapping USDC→DAI while accidentally attaching `msg.value`) loses that ETH permanently to the first caller of `refundETH()`. The loss is direct and immediate: the ETH is not locked in a recoverable position — it is freely claimable by any address in the same block via a simple MEV/frontrun. This constitutes a direct loss of user principal above Sherlock thresholds for any non-trivial ETH amount.

The same impact applies to `MetricOmmPoolLiquidityAdder` for non-WETH liquidity deposits.

---

### Likelihood Explanation

- The functions are `payable`, which signals to wallets, SDKs, and integrators that ETH is a valid input.
- Users who intend to swap native ETH for a token naturally send `msg.value`; if they misconfigure `tokenIn` (e.g., set it to USDC instead of WETH), the ETH is lost.
- The `multicall` pattern encourages batching `exactInputSingle` + `refundETH` in one transaction, but a standalone call to `exactInputSingle` with a non-WETH token and `msg.value > 0` leaves ETH stranded between transactions.
- MEV bots routinely monitor for stranded ETH in known router contracts and will extract it within the same block.

---

### Recommendation

Add a `msg.value == 0` guard in every swap and liquidity entry-point when the input token is not `WETH`:

```solidity
function exactInputSingle(ExactInputSingleParams calldata params)
    external payable returns (uint256 amountOut)
{
    if (params.tokenIn != WETH) {
        require(msg.value == 0, "msg.value with non-WETH token");
    }
    // ...
}
```

Alternatively, add a single internal helper called at the top of every payable entry-point:

```solidity
function _requireNoValueForNonWETH(address token) internal view {
    if (token != WETH && msg.value != 0) revert MsgValueWithNonWETHToken();
}
```

Apply the same fix to `addLiquidityExactShares` and `addLiquidityWeighted` in `MetricOmmPoolLiquidityAdder`.

---

### Proof of Concept

```
1. Alice calls:
   router.exactInputSingle{value: 1 ether}(ExactInputSingleParams({
       tokenIn: USDC,   // non-WETH ERC-20
       amountIn: 1000e6,
       ...
   }));

2. Inside the swap callback, pay() fires with token=USDC:
   → else branch: IERC20(USDC).safeTransferFrom(Alice, pool, 1000e6)
   → 1 ETH remains in router.balance

3. Bob (MEV bot) observes the pending tx in the mempool and submits:
   router.refundETH()   // no access control
   → _transferETH(Bob, 1 ether)   // Bob receives Alice's 1 ETH

4. Alice's swap succeeds (USDC was pulled correctly), but her 1 ETH is gone.
```

The same sequence applies to `MetricOmmPoolLiquidityAdder` with any non-WETH token pair.

### Citations

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L67-67)
```text
  function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut) {
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L92-92)
```text
  function exactInput(ExactInputParams calldata params) external payable returns (uint256 amountOut) {
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L130-130)
```text
  function exactOutputSingle(ExactOutputSingleParams calldata params) external payable returns (uint256 amountIn) {
```

**File:** metric-periphery/contracts/MetricOmmSimpleRouter.sol (L154-154)
```text
  function exactOutput(ExactOutputParams calldata params) external payable returns (uint256 amountIn) {
```

**File:** metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol (L56-64)
```text
  function addLiquidityExactShares(
    address pool,
    address owner,
    uint80 salt,
    LiquidityDelta calldata deltas,
    uint256 maxAmountToken0,
    uint256 maxAmountToken1,
    bytes calldata extensionData
  ) external payable override returns (uint256 amount0Added, uint256 amount1Added) {
```

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

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L69-88)
```text
  function pay(address token, address payer, address recipient, uint256 value) internal {
    // If the payer is contract it means we are in the middle of a path. In the middle of a path we operate on ERC20 only.
    if (payer == address(this)) {
      IERC20(token).safeTransfer(recipient, value);
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
    } else {
      IERC20(token).safeTransferFrom(payer, recipient, value);
    }
  }
```

**File:** metric-periphery/contracts/interfaces/IMetricOmmSimpleRouter.sol (L11-12)
```text
/// @dev Scope: ERC-20 routes only. No native ETH, WETH wrap/unwrap, on-chain quotes, sweep, or refund helpers.
///      Only pools registered on the configured factory may be used. Path token connectivity and single-hop
```
