### Title
`BridgeTransferERC20::requestERC20Transfer` uses caller-supplied `_value` instead of actual received balance for fee-on-transfer tokens, causing DoS in mint/burn mode and bridge undercollateralization in lock mode — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.requestERC20Transfer` pulls `_value + _feeLimit` tokens from the caller via `safeTransferFrom`, then immediately passes the original `_value` and `_feeLimit` parameters to `_requestERC20Transfer` without verifying the actual amount received. For fee-on-transfer ERC20 tokens, the bridge receives `_value + _feeLimit - delta` (where `delta` is the transfer fee). The subsequent `burn(_value)` call in mint/burn mode reverts because the bridge holds only `_value - delta`, and in lock mode the `RequestValueTransfer` event is emitted with the inflated `_value`, causing the counterpart bridge to overpay the recipient.

---

### Finding Description

In `requestERC20Transfer`:

```solidity
// BridgeTransferERC20.sol L133-134
IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
_requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
```

The bridge pulls `_value + _feeLimit` from the user. For a fee-on-transfer token with fee rate `r`, the bridge actually receives `(_value + _feeLimit) * (1 - r)`. The shortfall is `delta = (_value + _feeLimit) * r`.

Inside `_requestERC20Transfer`:

```solidity
// BridgeTransferERC20.sol L91-107
uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);

if (modeMintBurn) {
    ERC20Burnable(_tokenAddress).burn(_value);   // ← uses original _value
}

emit RequestValueTransfer(..., _value, ...);     // ← uses original _value
```

`_payERC20FeeAndRefundChange` transfers `fee` to `feeReceiver` and `feeRefund = _feeLimit - fee` back to the user, consuming exactly `_feeLimit` tokens from the bridge. After this, the bridge holds `(_value + _feeLimit - delta) - _feeLimit = _value - delta` tokens.

**Mint/burn mode**: `burn(_value)` is called but the bridge only holds `_value - delta` → transaction reverts → complete DoS for every `requestERC20Transfer` call with a fee-on-transfer token.

**Lock mode**: The `RequestValueTransfer` event is emitted with `_value`. The counterpart bridge's `handleERC20Transfer` will transfer `_value` to the recipient, but the source bridge only locked `_value - delta`. Each bridging operation creates a `delta`-sized deficit in the counterpart bridge's reserves, draining it over time.

The same flaw exists in the `onERC20Received` (1-step) path at line 120, which calls `_requestERC20Transfer` with the caller-supplied `_value` and `_feeLimit` without any balance check.

---

### Impact Explanation

- **Mint/burn mode**: Every `requestERC20Transfer` call with a fee-on-transfer token reverts. The bridge is permanently non-functional for that token class — a complete DoS on the cross-chain transfer path.
- **Lock mode**: The counterpart bridge is undercollateralized by `delta` per transaction. An attacker can repeatedly bridge fee-on-transfer tokens to drain the counterpart bridge's ERC20 reserves, stealing `delta` tokens per call from the bridge's liquidity pool. This is an unauthorized transfer of bridged assets.

---

### Likelihood Explanation

Fee-on-transfer ERC20 tokens are a well-known token class (e.g., USDT in some configurations, STA, REFLECT-style tokens). The bridge's `registerToken` function imposes no restriction on token type — any owner can register a fee-on-transfer token. Once registered, any user can call `requestERC20Transfer` to trigger the bug. No special privilege is required beyond holding the token.

---

### Recommendation

Measure the actual received balance using a before/after balance check, and use that amount for all downstream operations:

```diff
function requestERC20Transfer(
    address _tokenAddress,
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
) public {
+   uint256 balanceBefore = IERC20(_tokenAddress).balanceOf(address(this));
    IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
+   uint256 actualReceived = IERC20(_tokenAddress).balanceOf(address(this)).sub(balanceBefore);
+   // Recompute _value and _feeLimit proportionally, or require exact receipt:
+   require(actualReceived >= _value.add(_feeLimit), "fee-on-transfer token not supported");
    _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
}
```

Alternatively, document that fee-on-transfer tokens are unsupported and add a guard in `registerToken` to reject them.

---

### Proof of Concept

1. Deploy a fee-on-transfer ERC20 token that deducts 1% on every `transfer`/`transferFrom`.
2. Register it on both the source and counterpart bridge (lock mode).
3. Alice calls `requestERC20Transfer(tokenAddr, bob, 1000e18, 100e18, "0x")`.
4. `safeTransferFrom` pulls `1100e18` from Alice; bridge receives `1100e18 * 0.99 = 1089e18` (delta = 11e18).
5. `_payERC20FeeAndRefundChange` pays `fee` to feeReceiver and refunds `feeRefund` to Alice, consuming `100e18` from the bridge. Bridge now holds `989e18`.
6. `RequestValueTransfer` is emitted with `valueOrTokenId = 1000e18`.
7. Counterpart bridge operators call `handleERC20Transfer(..., 1000e18, ...)` → counterpart bridge transfers `1000e18` to Bob.
8. Net: source bridge locked `989e18`, counterpart bridge paid out `1000e18` → **11e18 deficit per transaction**.
9. In mint/burn mode: step 5 is followed by `burn(1000e18)` → reverts because bridge holds only `989e18` → **transaction reverts, DoS**. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-108)
```text
    function _requestERC20Transfer(
        address _tokenAddress,
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
        require(_value > 0, "zero ERC20 token amount");

        uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);

        if (modeMintBurn) {
            ERC20Burnable(_tokenAddress).burn(_value);
        }

        emit RequestValueTransfer(
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            requestNonce,
            fee,
            _extraData
        );
        requestNonce++;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L110-121)
```text
    // onERC20Received function of ERC20 token for 1-step deposits to the Bridge.
    function onERC20Received(
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        public
    {
        _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L123-135)
```text
    // requestERC20Transfer requests transfer ERC20 to _to on relative chain.
    function requestERC20Transfer(
        address _tokenAddress,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        public
    {
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L68-88)
```text
    function _payERC20FeeAndRefundChange(address from, address _token, uint256 _feeLimit) internal returns(uint256) {
        uint256 fee = feeOfERC20[_token];

        if (feeReceiver != address(0) && fee > 0) {
            require(_feeLimit >= fee, "insufficient feeLimit");

            IERC20(_token).safeTransfer(feeReceiver, fee);

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                IERC20(_token).safeTransfer(from, feeRefund);
            }

            return fee;
        }

        if (_feeLimit > 0) {
            IERC20(_token).safeTransfer(from, _feeLimit);
        }
        return 0;
    }
```
