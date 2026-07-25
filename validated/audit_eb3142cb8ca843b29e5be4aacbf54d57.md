### Title
`BridgeTransferERC20.onERC20Received` Accepts Caller-Supplied `_from` With No Validation, Sending ERC20 Fee Refunds to the Wrong Address — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.onERC20Received` is a `public` function with no access control that accepts `_from` as a fully caller-controlled parameter. When a registered ERC20 token is invoked through an intermediary contract, the intermediary's address is passed as `_from`, causing the ERC20 fee refund to be transferred to the intermediary instead of the actual user. This is a direct analog of the ZetaChain M-21 bug class: the "emitting contract" (the token contract's `msg.sender`) is used as the requester identity rather than the true transaction originator.

---

### Finding Description

`BridgeTransferERC20.onERC20Received` is the 1-step bridge entry point for ERC20 tokens:

```solidity
// contracts/service_chain/bridge/BridgeTransferERC20.sol L111-121
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
``` [1](#0-0) 

`msg.sender` becomes `_tokenAddress` (validated against the registered-token list), while `_from` is passed through unchecked as the fee-refund recipient and the `from` field of the `RequestValueTransfer` event.

Inside `_requestERC20Transfer`, the fee refund is dispatched to `_from`:

```solidity
// contracts/service_chain/bridge/BridgeTransferERC20.sol L91
uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);
``` [2](#0-1) 

And in `BridgeFee._payERC20FeeAndRefundChange`:

```solidity
// contracts/service_chain/bridge/BridgeFee.sol L77-79
uint256 feeRefund = _feeLimit.sub(fee);
if (feeRefund > 0) {
    IERC20(_token).safeTransfer(from, feeRefund);
}
``` [3](#0-2) 

The reference 1-step token contract (`ERC20ServiceChain`) passes `msg.sender` as `_from`:

```solidity
// contracts/testing/sc_erc20/ERC20ServiceChain.sol L44-47
function requestValueTransfer(uint256 _amount, address _to, uint256 _feeLimit, bytes calldata _extraData) external {
    require(transfer(bridge, _amount.add(_feeLimit)), "requestValueTransfer: transfer failed");
    IERC20BridgeReceiver(bridge).onERC20Received(msg.sender, _to, _amount, _feeLimit, _extraData);
}
``` [4](#0-3) 

When a user calls `requestValueTransfer` directly, `msg.sender` is the user — correct. But when an intermediary contract (router, aggregator, DeFi wrapper) calls `requestValueTransfer`, `msg.sender` is the intermediary, so `_from` = intermediary address is passed to the bridge. The fee refund is then sent to the intermediary, not the user.

The same wrong address is emitted as `from` in `RequestValueTransfer`:

```solidity
// contracts/service_chain/bridge/BridgeTransferERC20.sol L97-106
emit RequestValueTransfer(
    TokenType.ERC20,
    _from,   // ← intermediary address, not actual user
    _to,
    ...
);
``` [5](#0-4) 

---

### Impact Explanation

- **ERC20 fee refund (`feeLimit − fee` tokens) is permanently transferred to the intermediary contract** instead of the actual user. If the intermediary has no recovery mechanism, the tokens are stuck.
- The `RequestValueTransfer` event records the wrong `from` address, which is consumed by the bridge operator's Go-side handler (`handleRequestValueTransferEvent`) and forwarded to the counterpart chain's `HandleValueTransfer` event — corrupting the audit trail and any on-chain logic that keys on the `from` field. [6](#0-5) 

---

### Likelihood Explanation

Any user who interacts with the Kaia service-chain bridge through an intermediary contract (a common DeFi pattern: aggregators, vaults, routers) triggers this bug. No special privilege is required beyond holding the registered ERC20 token. The trigger is a normal, valid transaction.

---

### Recommendation

`onERC20Received` should not accept `_from` as a caller-supplied parameter. Instead, it should derive the true sender from the token transfer itself — for example, by requiring the token contract to pass only the actual `transferFrom` originator, or by restricting `onERC20Received` to only registered token contracts and verifying `_from` against the token's own transfer records. At minimum, add a check that `_from != address(0)` and document that `_from` must equal the address that approved/transferred the tokens.

---

### Proof of Concept

1. Deploy a registered ERC20 token (`Token`) on the service chain bridge.
2. Deploy an `IntermediaryContract` that calls `Token.requestValueTransfer(amount, to, feeLimit, extraData)`.
3. User calls `IntermediaryContract.bridge(amount, to, feeLimit)`.
4. Inside `Token.requestValueTransfer`, `msg.sender` = `IntermediaryContract`, so `bridge.onERC20Received(IntermediaryContract, to, amount, feeLimit, extraData)` is called.
5. Bridge calls `_payERC20FeeAndRefundChange(IntermediaryContract, Token, feeLimit)`.
6. `Token.safeTransfer(IntermediaryContract, feeLimit - fee)` executes — the user's fee refund is sent to `IntermediaryContract`, not the user.
7. `RequestValueTransfer` event emits `from = IntermediaryContract`. [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L91-91)
```text
        uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);
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

**File:** contracts/testing/sc_erc20/ERC20ServiceChain.sol (L44-47)
```text
    function requestValueTransfer(uint256 _amount, address _to, uint256 _feeLimit, bytes calldata _extraData) external {
        require(transfer(bridge, _amount.add(_feeLimit)), "requestValueTransfer: transfer failed");
        IERC20BridgeReceiver(bridge).onERC20Received(msg.sender, _to, _amount, _feeLimit, _extraData);
    }
```

**File:** node/sc/bridge_manager.go (L292-301)
```go
// handleRequestValueTransferEvent handles the given request value transfer event.
func (bi *BridgeInfo) handleRequestValueTransferEvent(ev IRequestValueTransferEvent) error {
	var (
		tokenType                         = ev.GetTokenType()
		tokenAddr, from, to, contractAddr = ev.GetTokenAddress(), ev.GetFrom(), ev.GetTo(), ev.GetRaw().Address
		txHash                            = ev.GetRaw().TxHash
		valueOrTokenId                    = ev.GetValueOrTokenId()
		requestNonce, blkNumber           = ev.GetRequestNonce(), ev.GetRaw().BlockNumber
		extraData                         = ev.GetExtraData()
	)
```
