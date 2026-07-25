### Title
Fee-on-Transfer ERC20 Token Causes Bridge Insolvency (Lock/Unlock Mode) or Permanent DoS (Mint/Burn Mode) — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.requestERC20Transfer` and the 1-step `onERC20Received` path both record and emit the caller-supplied `_value` as the canonical bridged amount without measuring the actual tokens received. When the registered ERC20 token charges a fee on every transfer, the bridge locks fewer tokens than it commits to release on the counterpart chain, producing silent insolvency in lock/unlock mode and a hard revert in mint/burn mode.

---

### Finding Description

`requestERC20Transfer` pulls `_value + _feeLimit` from the caller and immediately passes the raw `_value` to `_requestERC20Transfer`:

```solidity
// BridgeTransferERC20.sol line 133-134
IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
_requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
``` [1](#0-0) 

If the token deducts an internal transfer fee `X`, the bridge actually receives `_value + _feeLimit - X`. `_payERC20FeeAndRefundChange` then disperses exactly `_feeLimit` worth of tokens (bridge fee to `feeReceiver`, remainder refunded to caller):

```solidity
// BridgeFee.sol lines 74-78
IERC20(_token).safeTransfer(feeReceiver, fee);
uint256 feeRefund = _feeLimit.sub(fee);
if (feeRefund > 0) {
    IERC20(_token).safeTransfer(from, feeRefund);
}
``` [2](#0-1) 

After fee dispersal the bridge holds `_value - X` tokens, but `_requestERC20Transfer` emits `RequestValueTransfer` with the original `_value`:

```solidity
// BridgeTransferERC20.sol lines 97-106
emit RequestValueTransfer(
    TokenType.ERC20,
    _from, _to, _tokenAddress,
    _value,          // ← caller-supplied, not actual received amount
    requestNonce, fee, _extraData
);
``` [3](#0-2) 

The counterpart bridge's `handleERC20Transfer` trusts this event value and releases `_value` tokens to the recipient:

```solidity
// BridgeTransferERC20.sol line 71
IERC20(_tokenAddress).safeTransfer(_to, _value);
``` [4](#0-3) 

The same mismatch exists in the 1-step path: `ERC20ServiceChain.requestValueTransfer` calls `transfer(bridge, _amount + _feeLimit)` (bridge receives `_amount + _feeLimit - X`) and then calls `onERC20Received` with the original `_amount`:

```solidity
// ERC20ServiceChain.sol lines 45-46
require(transfer(bridge, _amount.add(_feeLimit)), "requestValueTransfer: transfer failed");
IERC20BridgeReceiver(bridge).onERC20Received(msg.sender, _to, _amount, _feeLimit, _extraData);
``` [5](#0-4) 

In **mint/burn mode**, `_requestERC20Transfer` additionally calls `ERC20Burnable(_tokenAddress).burn(_value)` after fee dispersal, but the bridge only holds `_value - X` tokens at that point, causing an unconditional revert:

```solidity
// BridgeTransferERC20.sol lines 93-95
if (modeMintBurn) {
    ERC20Burnable(_tokenAddress).burn(_value);
}
``` [6](#0-5) 

---

### Impact Explanation

**Lock/unlock mode (modeMintBurn = false):** Every successful cross-chain transfer with a fee-on-transfer token silently undercollateralizes the source-side bridge by `X` tokens. The counterpart bridge releases the full `_value` while the source bridge only locked `_value - X`. Repeated transfers drain the bridge's token reserves, eventually causing legitimate withdrawals to fail and constituting an unauthorized effective transfer of bridged assets.

**Mint/burn mode (modeMintBurn = true):** Every deposit attempt reverts at `burn(_value)` because the bridge holds only `_value - X`. The bridge is permanently unable to process ERC20 deposits for any fee-on-transfer token registered in this mode.

---

### Likelihood Explanation

Any user can trigger this with a registered ERC20 token that charges transfer fees. No special role or privilege is required — `requestERC20Transfer` is a public function with no access control. Tokens such as USDT have the ability to enable transfer fees at any time, meaning a token that was safe at registration time can become exploitable later. The trigger is a normal user action (calling `requestERC20Transfer` or `requestValueTransfer` on the token contract).

---

### Recommendation

Measure the actual received amount using a balance-before/balance-after pattern and use that as the canonical bridged value:

```solidity
function requestERC20Transfer(...) public {
    uint256 balanceBefore = IERC20(_tokenAddress).balanceOf(address(this));
    IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
    uint256 actualReceived = IERC20(_tokenAddress).balanceOf(address(this)).sub(balanceBefore);
    // derive actual _value and _feeLimit from actualReceived, then proceed
    _requestERC20Transfer(_tokenAddress, msg.sender, _to, actualValue, actualFeeLimit, _extraData);
}
```

Alternatively, explicitly disallow registration of fee-on-transfer tokens in `registerToken`.

---

### Proof of Concept

1. Deploy a fee-on-transfer ERC20 token that deducts 1% on every `transfer`/`transferFrom`. Register it on both the source and counterpart bridges in **lock/unlock mode**.
2. Alice calls `requestERC20Transfer(token, Bob, 1000e18, 0, "0x")`.
3. Bridge calls `safeTransferFrom(Alice, bridge, 1000e18)` → bridge receives `990e18` (1% fee taken by token).
4. `_payERC20FeeAndRefundChange` disperses 0 (no bridge fee configured), bridge retains `990e18`.
5. `RequestValueTransfer` event emits `valueOrTokenId = 1000e18`.
6. Counterpart bridge operators call `handleERC20Transfer(..., 1000e18, ...)` → `safeTransfer(Bob, 1000e18)`.
7. Bob receives `1000e18` on the counterpart chain; source bridge locked only `990e18`.
8. Deficit of `10e18` per transfer accumulates. After 100 such transfers the bridge is short `1000e18` tokens, and the next legitimate withdrawal fails. [7](#0-6) [4](#0-3)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L93-95)
```text
        if (modeMintBurn) {
            ERC20Burnable(_tokenAddress).burn(_value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L97-107)
```text
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L124-135)
```text
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

**File:** contracts/service_chain/bridge/BridgeFee.sol (L74-79)
```text
            IERC20(_token).safeTransfer(feeReceiver, fee);

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                IERC20(_token).safeTransfer(from, feeRefund);
            }
```

**File:** contracts/testing/sc_erc20/ERC20ServiceChain.sol (L44-47)
```text
    function requestValueTransfer(uint256 _amount, address _to, uint256 _feeLimit, bytes calldata _extraData) external {
        require(transfer(bridge, _amount.add(_feeLimit)), "requestValueTransfer: transfer failed");
        IERC20BridgeReceiver(bridge).onERC20Received(msg.sender, _to, _amount, _feeLimit, _extraData);
    }
```
