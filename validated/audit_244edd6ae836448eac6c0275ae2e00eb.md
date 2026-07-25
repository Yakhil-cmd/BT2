### Title
Bridge ERC20 Transfer Trusts Caller-Supplied `_value` Instead of Actual Received Balance — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.requestERC20Transfer` pulls ERC20 tokens from the user via `safeTransferFrom` but then emits `RequestValueTransfer` using the caller-supplied `_value` parameter rather than the actual balance change. For fee-on-transfer (deflationary) ERC20 tokens, the bridge receives fewer tokens than `_value`, yet the counterpart bridge is instructed to release the full `_value` to the recipient — draining the counterpart bridge's reserves.

---

### Finding Description

In `requestERC20Transfer`:

```solidity
// BridgeTransferERC20.sol line 133-134
IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
_requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
```

`safeTransferFrom` only guarantees the call did not revert; it does not verify the actual balance delta. [1](#0-0) 

`_requestERC20Transfer` then emits the cross-chain event with the unverified `_value`:

```solidity
// BridgeTransferERC20.sol line 97-106
emit RequestValueTransfer(
    TokenType.ERC20,
    _from,
    _to,
    _tokenAddress,
    _value,          // ← caller-supplied, not actual received amount
    requestNonce,
    fee,
    _extraData
);
``` [2](#0-1) 

Bridge operators on the counterpart chain observe this event and call `handleERC20Transfer` with the same `_value`, releasing that full amount to the recipient:

```solidity
// BridgeTransferERC20.sol line 68-72
if (modeMintBurn) {
    require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
} else {
    IERC20(_tokenAddress).safeTransfer(_to, _value);
}
``` [3](#0-2) 

The same pattern exists in the 1-step `onERC20Received` path, where `_value` is passed by the token contract itself and accepted without balance verification. [4](#0-3) 

---

### Impact Explanation

For any registered fee-on-transfer ERC20 token, the source bridge receives `_value × (1 − fee_rate)` tokens but the counterpart bridge releases `_value` tokens. The difference is extracted from the counterpart bridge's liquidity pool. Repeated calls drain the counterpart bridge of bridged assets — an unauthorized unlock of system-managed funds. This matches the allowed impact: *"Unauthorized transfer, mint, unlock, burn … affecting … bridged assets."*

---

### Likelihood Explanation

Exploitation requires a fee-on-transfer ERC20 token to be registered in the bridge (a privileged operator action). However:
- The code contains no guard preventing such tokens from being registered.
- Upgradeable token proxies can add fee logic after registration.
- Operators may not audit every token for fee-on-transfer behavior.

Once such a token is registered, any unprivileged user can call `requestERC20Transfer` to trigger the imbalance.

---

### Recommendation

Measure the actual balance delta around the `safeTransferFrom` call and use that as the canonical transfer amount:

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
    uint256 actualValue = actualReceived > _feeLimit ? actualReceived.sub(_feeLimit) : 0;
    require(actualValue > 0, "zero actual ERC20 amount after fees");
    _requestERC20Transfer(_tokenAddress, msg.sender, _to, actualValue, _feeLimit, _extraData);
}
```

---

### Proof of Concept

1. Deploy a fee-on-transfer ERC20 token that deducts 10% on every transfer.
2. Register it in the source bridge (operator action).
3. User calls `requestERC20Transfer(token, recipient, 1000, 0, "0x")`.
4. Bridge receives 900 tokens (10% fee deducted by the token).
5. `RequestValueTransfer` event is emitted with `valueOrTokenId = 1000`.
6. Counterpart bridge operators call `handleERC20Transfer(..., 1000, ...)`.
7. Counterpart bridge releases 1000 tokens to the recipient.
8. Net loss to counterpart bridge: 100 tokens per call. Repeat to drain reserves.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L111-121)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L133-134)
```text
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
```
