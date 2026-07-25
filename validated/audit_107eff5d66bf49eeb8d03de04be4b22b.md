### Title
`requestERC20Transfer` Uses Caller-Supplied `_value`/`_feeLimit` Without Verifying Actual Balance Increase, Enabling Bridge Reserve Drain With Fee-On-Transfer Tokens — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.requestERC20Transfer` calls `safeTransferFrom` for `_value + _feeLimit` tokens and then immediately uses the original caller-supplied `_value` and `_feeLimit` for all downstream accounting — fee payment, refund, burn, and the `RequestValueTransfer` event — without ever measuring the actual balance increase. For any fee-on-transfer ERC20 token registered on the bridge, the counterpart bridge is instructed to release `_value` tokens while the source bridge only received `_value + _feeLimit − transfer_fee`. This drains the bridge's locked reserves one transfer at a time.

---

### Finding Description

In `requestERC20Transfer`:

```solidity
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
``` [1](#0-0) 

After the `safeTransferFrom` on line 133, the bridge's actual token balance increase is `(_value + _feeLimit) × (1 − transfer_fee_rate)`, not `_value + _feeLimit`. The code never reads `balanceOf(address(this))` before and after the transfer to compute the real received amount.

`_requestERC20Transfer` then:
1. Calls `_payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit)` — pays `feeOfERC20[_token]` to `feeReceiver` and refunds `_feeLimit − fee` to the user, both from the bridge's balance, using the original `_feeLimit`.
2. In lock mode (`modeMintBurn = false`), retains `_value` tokens in the bridge.
3. Emits `RequestValueTransfer(..., _value, ...)` — the event that instructs the counterpart bridge to release exactly `_value` tokens. [2](#0-1) 

The fee payment and refund in `_payERC20FeeAndRefundChange` also use the original `_feeLimit`: [3](#0-2) 

---

### Impact Explanation

**Lock mode (`modeMintBurn = false`):**

Let `T` = token transfer fee rate (e.g. 1%), `_value = 100`, `_feeLimit = 10`, `feeOfERC20 = 3`.

- Bridge receives: `(100 + 10) × 0.99 = 108.9` tokens.
- Bridge pays `3` to `feeReceiver` → bridge holds `105.9`.
- Bridge refunds `10 − 3 = 7` to user → bridge holds `98.9`.
- Bridge retains `98.9` tokens but emits `RequestValueTransfer` with `_value = 100`.
- Counterpart bridge releases `100` tokens to recipient.
- **Net loss per transfer: `1.1` tokens from bridge reserves.**

The `RequestValueTransfer` event is the authoritative signal consumed by the counterpart bridge's operators to call `handleERC20Transfer`, which releases `_value` tokens unconditionally. [4](#0-3) 

**Burn mode (`modeMintBurn = true`):**

After fee/refund, the bridge holds `98.9` tokens but calls `ERC20Burnable(_tokenAddress).burn(100)`. This reverts because the bridge only holds `98.9`. So burn mode is self-protecting via revert, but lock mode is not. [5](#0-4) 

---

### Likelihood Explanation

- **Trigger**: Any unprivileged user can call `requestERC20Transfer` with any token that has been registered by operators via `registerToken`.
- **Precondition**: A fee-on-transfer ERC20 token must be registered on the bridge. The bridge contract has no guard preventing registration of such tokens.
- **Repeatability**: Each call leaks a small amount; repeated calls drain the bridge's locked reserves proportionally to the token's transfer fee rate.
- **No special role required**: The attacker is the ordinary `msg.sender` of `requestERC20Transfer`.

---

### Recommendation

Measure the actual balance increase after `safeTransferFrom` and use that as the effective deposited amount:

```solidity
function requestERC20Transfer(
    address _tokenAddress,
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
) public {
    uint256 balanceBefore = IERC20(_tokenAddress).balanceOf(address(this));
    IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
    uint256 actualReceived = IERC20(_tokenAddress).balanceOf(address(this)).sub(balanceBefore);
    require(actualReceived == _value.add(_feeLimit), "fee-on-transfer token not supported");
    _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
}
```

Alternatively, explicitly document and enforce that only non-fee-on-transfer tokens may be registered, and add a validation check in `registerToken`.

---

### Proof of Concept

1. Deploy a fee-on-transfer ERC20 token (e.g. 1% fee on every transfer).
2. Register it on the source bridge via `registerToken`.
3. Approve the bridge for `110` tokens and call:
   ```
   bridge.requestERC20Transfer(feeToken, recipient, 100, 10, "0x")
   ```
4. Bridge receives `108.9` tokens (1% fee deducted by token contract).
5. Bridge pays `3` to `feeReceiver`, refunds `7` to caller → bridge holds `98.9`.
6. `RequestValueTransfer` event emitted with `_value = 100`.
7. Counterpart bridge operators call `handleERC20Transfer(..., 100, ...)`.
8. Counterpart bridge releases `100` tokens to `recipient`.
9. Source bridge is short `1.1` tokens per transfer; repeated calls drain its reserves. [6](#0-5) [3](#0-2)

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
