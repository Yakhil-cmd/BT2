### Title
`_transferETH` Reverts for Contract Recipients Unable to Receive ETH, Permanently Locking Excess ETH in the Router — (`metric-periphery/contracts/base/PeripheryPayments.sol`)

---

### Summary

`PeripheryPayments._transferETH` performs a raw `call{value:}` to the recipient. If the recipient is a contract without a working `receive` or `fallback`, the call reverts and the entire function reverts. Two public entry points are affected: `refundETH()` (sends to `msg.sender`) and `unwrapWETH9()` (sends to a caller-supplied `recipient`). For `refundETH()`, this creates a direct fund-loss path: excess ETH already deposited into the router by a prior swap call is permanently inaccessible to the contract caller and can be drained by any third party.

---

### Finding Description

`PeripheryPayments._transferETH` is the sole ETH-delivery primitive: [1](#0-0) 

```solidity
function _transferETH(address to, uint256 value) internal {
    (bool ok,) = to.call{value: value}("");
    if (!ok) revert ETHTransferFailed();
}
```

It is called unconditionally by both public helpers: [2](#0-1) 

```solidity
function refundETH() external payable override {
    uint256 balance = address(this).balance;
    if (balance > 0) {
        _transferETH(msg.sender, balance);   // ← reverts if msg.sender cannot receive ETH
    }
}
``` [3](#0-2) 

```solidity
function unwrapWETH9(uint256 amountMinimum, address recipient) public payable override {
    ...
    if (balanceWETH > 0) {
        IWETH9(WETH).withdraw(balanceWETH);
        _transferETH(recipient, balanceWETH);  // ← reverts if recipient cannot receive ETH
    }
}
```

**Fund-loss path via `refundETH()`:**

The `pay()` helper, invoked inside every swap callback, wraps only the exact amount of ETH needed and leaves any surplus in the router: [4](#0-3) 

```solidity
} else if (token == WETH) {
    uint256 nativeBalance = address(this).balance;
    if (nativeBalance >= value) {
        IWETH9(WETH).deposit{value: value}();
        IERC20(WETH).safeTransfer(recipient, value);
    }
```

A contract integrator that calls `exactInputSingle` (or any swap entry point) with `msg.value > amountIn` will have the surplus ETH sitting in the router after the swap settles. When it subsequently calls `refundETH()`, `_transferETH(msg.sender, balance)` reverts because the integrator contract has no `receive`/`fallback`. The ETH remains in the router.

Because `refundETH()` sends **all** ETH held by the router to whoever calls it next, any third party can immediately drain the stuck balance: [2](#0-1) 

**DoS path via `unwrapWETH9()`:**

If a caller supplies a `recipient` that cannot receive ETH, `IWETH9.withdraw()` executes first (ETH lands in the router), then `_transferETH` reverts, rolling back the entire transaction. No ETH is permanently lost here (the revert restores state), but the operation is completely unusable for that recipient.

---

### Impact Explanation

**`refundETH()` path — Medium, direct fund loss.** A contract caller that overpays ETH on a swap and cannot receive ETH through its `receive`/`fallback` loses the surplus permanently. The router holds all users' ETH in a single shared balance; `refundETH()` sends the entire balance to whoever calls it, so the stuck ETH is immediately stealable by any third party.

**`unwrapWETH9()` path — Medium, broken core withdraw flow.** Any multicall sequence that ends with `unwrapWETH9(minAmount, contractRecipient)` is permanently broken for contract recipients that cannot receive ETH, making the ETH-output leg of swaps unusable for those callers.

---

### Likelihood Explanation

Smart-contract wallets, aggregators, and protocol vaults are common callers of periphery routers. Many such contracts intentionally omit `receive`/`fallback` or restrict ETH acceptance (e.g., the router itself does this: `if (msg.sender != WETH) revert NotWETH()`). Sending a slightly over-estimated `msg.value` is standard practice when the exact swap cost is unknown at call time. The combination is realistic and requires no privileged access.

---

### Recommendation

Mirror the mitigation used in the PartyDAO fix and in Uniswap V3's `SwapRouter02`: when a raw ETH transfer fails, fall back to wrapping the ETH as WETH and transferring the WETH token instead.

```solidity
function _transferETH(address to, uint256 value) internal {
    (bool ok,) = to.call{value: value}("");
    if (!ok) {
        // Fallback: wrap and send WETH so the recipient can unwrap later
        IWETH9(WETH).deposit{value: value}();
        IERC20(WETH).safeTransfer(to, value);
    }
}
```

This ensures that even if the recipient cannot accept native ETH, it receives an equivalent WETH balance it can unwrap at a time of its choosing, eliminating both the fund-loss and the DoS.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {MetricOmmSimpleRouter} from "metric-periphery/contracts/MetricOmmSimpleRouter.sol";
import {PeripheryPayments} from "metric-periphery/contracts/base/PeripheryPayments.sol";
import {MockWETH9} from "metric-periphery/test/mocks/MockWETH9.sol";

/// @dev A contract that intentionally cannot receive ETH (no receive/fallback).
contract NoEthReceiver {
    MetricOmmSimpleRouter public router;

    constructor(address _router) {
        router = MetricOmmSimpleRouter(payable(_router));
    }

    /// Simulate: swap was called with excess msg.value; now try to refund.
    function tryRefund() external {
        router.refundETH();  // will revert → ETH stuck in router
    }
}

contract EthTransferFailPoC is Test {
    MockWETH9 weth;
    MetricOmmSimpleRouter router;
    NoEthReceiver noEthContract;
    address thief = address(0xBEEF);

    function setUp() public {
        weth = new MockWETH9();
        // factory stub address irrelevant for payment tests
        router = new MetricOmmSimpleRouter(address(weth), address(this));
        noEthContract = new NoEthReceiver(address(router));
    }

    function test_refundETH_revertsForContractWithNoReceive_ethStuckAndStealable() public {
        // Simulate excess ETH left in router after a swap (e.g. msg.value > amountIn).
        // Only WETH can push ETH into the router via withdraw(); we mimic that here.
        vm.deal(address(weth), 1 ether);
        vm.prank(address(weth));
        (bool ok,) = address(router).call{value: 1 ether}("");
        assertTrue(ok, "setup: weth deposit accepted");
        assertEq(address(router).balance, 1 ether);

        // noEthContract tries to reclaim its ETH — reverts because it has no receive().
        vm.expectRevert(PeripheryPayments.ETHTransferFailed.selector);
        noEthContract.tryRefund();

        // ETH is still in the router — any third party can steal it.
        vm.prank(thief);
        router.refundETH();
        assertEq(thief.balance, 1 ether, "thief drained stuck ETH");
        assertEq(address(router).balance, 0);
    }
}
```

### Citations

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L37-45)
```text
  function unwrapWETH9(uint256 amountMinimum, address recipient) public payable override {
    uint256 balanceWETH = IERC20(WETH).balanceOf(address(this));
    if (balanceWETH < amountMinimum) revert InsufficientWETH(amountMinimum, balanceWETH);

    if (balanceWETH > 0) {
      IWETH9(WETH).withdraw(balanceWETH);
      _transferETH(recipient, balanceWETH);
    }
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

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L73-78)
```text
    } else if (token == WETH) {
      uint256 nativeBalance = address(this).balance;
      if (nativeBalance >= value) {
        IWETH9(WETH).deposit{value: value}();
        IERC20(WETH).safeTransfer(recipient, value);
      } else if (nativeBalance > 0) {
```

**File:** metric-periphery/contracts/base/PeripheryPayments.sol (L90-93)
```text
  function _transferETH(address to, uint256 value) internal {
    (bool ok,) = to.call{value: value}("");
    if (!ok) revert ETHTransferFailed();
  }
```
