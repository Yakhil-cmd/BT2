### Title
`_transferETH` reverts when recipient cannot receive ETH, permanently stranding excess native ETH in the router — (File: `metric-periphery/contracts/base/PeripheryPayments.sol`)

---

### Summary

`_transferETH` uses a raw `.call{value}("")` and reverts on failure. When a contract caller that has no `receive()` or `fallback()` overpays native ETH for a WETH-input swap and later calls `refundETH()` in a separate transaction, the excess ETH is permanently stranded in the router and becomes freely claimable by any subsequent caller.

---

### Finding Description

`_transferETH` is the sole ETH-delivery primitive in `PeripheryPayments`: [1](#0-0) 

```solidity
function _transferETH(address to, uint256 value) internal {
    (bool ok,) = to.call{value: value}("");
    if (!ok) revert ETHTransferFailed();
}
```

It is called by two public entry points:

- `refundETH()` — sends the router's **entire** ETH balance to `msg.sender`
- `unwrapWETH9(uint256, address)` — unwraps WETH and sends ETH to a caller-supplied `recipient` [2](#0-1) [3](#0-2) 

**Stranded-ETH path via `refundETH()`:**

The `pay()` function, when `token == WETH` and `nativeBalance >= value`, deposits **exactly** `value` ETH into WETH and transfers it to the pool — leaving any excess native ETH sitting in the router: [4](#0-3) 

```solidity
} else if (token == WETH) {
    uint256 nativeBalance = address(this).balance;
    if (nativeBalance >= value) {
        IWETH9(WETH).deposit{value: value}();
        IERC20(WETH).safeTransfer(recipient, value);
    }
```

Attack path (two separate transactions):

1. **Tx 1** — Contract `C` (no `receive()`) calls `exactInputSingle` with `msg.value = 1 ETH`, `params.amountIn = 0.5 ETH`, `params.tokenIn = WETH`. The callback fires `pay(WETH, C, pool, 0.5 ETH)`. The router deposits 0.5 ETH into WETH and transfers it to the pool. The remaining **0.5 ETH stays in the router**. The swap succeeds.

2. **Tx 2** — Contract `C` calls `refundETH()`. `_transferETH(C, 0.5 ETH)` reverts because `C` has no `receive()`. The 0.5 ETH is **permanently stranded** in the router.

3. **Tx 3** — Any third party calls `refundETH()` and receives the 0.5 ETH that belonged to `C`.

**`unwrapWETH9` path:** If `recipient` cannot receive ETH, `_transferETH` reverts and the entire transaction reverts (WETH is restored by the EVM). No permanent fund loss occurs on this path.

---

### Impact Explanation

A contract integrator (vault, aggregator, smart wallet) that overpays native ETH for a WETH-input swap and cannot receive ETH loses the excess permanently. The stranded ETH is not locked — it is freely claimable by any address that calls `refundETH()` next, constituting a **direct loss of user principal**. The amount lost equals `msg.value − amountIn` per affected transaction, which is unbounded.

---

### Likelihood Explanation

Contract integrators commonly overpay native ETH to guarantee swap execution and rely on `refundETH()` for the remainder. Many such contracts (e.g., vaults, multisigs, proxy wallets) do not implement `receive()`. The trigger requires no privileged access and no malicious setup — only a standard overpay pattern from a contract without an ETH receiver, across two separate transactions (swap then refund). The pattern is common enough in production integrations to make this a realistic medium-severity risk.

---

### Recommendation

In `_transferETH`, fall back to wrapping the ETH into WETH and transferring WETH to the recipient if the native transfer fails:

```solidity
function _transferETH(address to, uint256 value) internal {
    (bool ok,) = to.call{value: value}("");
    if (!ok) {
        // Recipient cannot receive ETH; wrap and send WETH instead.
        IWETH9(WETH).deposit{value: value}();
        IERC20(WETH).safeTransfer(to, value);
    }
}
```

This mirrors the mitigation recommended by the PartyDAO team for the analogous bug: escrow the owed amount in a form the recipient can always accept.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

/// @dev Contract with no receive() — cannot accept native ETH.
contract NoReceiveVault {
    /// Tx 1: swap with excess ETH; 0.5 ETH strands in the router.
    function doSwap(address router, ExactInputSingleParams calldata p)
        external payable
    {
        // msg.value = 1 ETH, p.amountIn = 0.5 ETH, p.tokenIn = WETH
        IMetricOmmSimpleRouter(router).exactInputSingle{value: msg.value}(p);
        // Swap succeeds; 0.5 ETH is now sitting in the router.
    }

    /// Tx 2: attempt refund — reverts because this contract has no receive().
    function tryRefund(address router) external {
        IPeripheryPayments(router).refundETH(); // <-- ETHTransferFailed
    }
}

/// @dev Any address can steal the stranded ETH.
contract Thief {
    function steal(address router) external {
        IPeripheryPayments(router).refundETH(); // receives 0.5 ETH
    }
}
```

**Steps:**
1. Deploy `NoReceiveVault`; fund with 1 ETH.
2. Call `doSwap` — swap succeeds, 0.5 ETH stranded in router.
3. Call `tryRefund` — reverts with `ETHTransferFailed`.
4. Deploy `Thief`; call `steal(router)` — receives the 0.5 ETH that belonged to `NoReceiveVault`.

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
