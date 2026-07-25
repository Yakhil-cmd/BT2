### Title
Missing `_to` Zero-Address Validation in Bridge KLAY Transfer Allows Permanent Fund Loss — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary

`BridgeTransferKLAY.requestKLAYTransfer` and its internal helper `_requestKLAYTransfer` accept a caller-supplied `_to` address without validating it is non-zero. When `_to = address(0)` is passed, the cross-chain request is committed on the source chain (KLAY locked, `requestNonce` consumed), and the bridge operator faithfully relays it to `handleKLAYTransfer` on the destination chain, which executes `_to.call.value(_value)("")` — sending KLAY to `address(0)` and permanently burning it. No guard exists at any point in the pipeline to reject or revert this.

### Finding Description

`requestKLAYTransfer` is a public, payable function callable by any user:

```solidity
// BridgeTransferKLAY.sol line 132
function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
    uint256 feeLimit = msg.value.sub(_value);
    _requestKLAYTransfer(_to, feeLimit, _extraData);
}
```

`_requestKLAYTransfer` performs no zero-address check on `_to`:

```solidity
// BridgeTransferKLAY.sol lines 103–124
function _requestKLAYTransfer(address _to, uint256 _feeLimit, bytes memory _extraData)
    internal unlockedKLAY nonReentrant
{
    require(isRunning, "stopped bridge");
    require(msg.value > _feeLimit, "insufficient amount");
    uint256 fee = _payKLAYFeeAndRefundChange(_feeLimit);
    emit RequestValueTransfer(TokenType.KLAY, msg.sender, _to, address(0),
        msg.value.sub(_feeLimit), requestNonce, fee, _extraData);
    requestNonce++;
}
```

The emitted `RequestValueTransfer` event is picked up by the bridge manager (`node/sc/bridge_manager.go`) which calls `handleKLAYTransfer` on the counterpart chain with the `_to` value taken verbatim from the event:

```go
// bridge_manager.go line 333
handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
```

`handleKLAYTransfer` then executes the transfer without any zero-address check:

```solidity
// BridgeTransferKLAY.sol line 98
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
```

In Solidity 0.5.6, `address(0).call.value(v)("")` succeeds (returns `true`) because there is no code at `address(0)` to revert. The `require(ok, ...)` passes, the KLAY is credited to `address(0)`, and the handle nonce is permanently consumed.

By contrast, `BridgeTransferERC20.handleERC20Transfer` is incidentally protected: OpenZeppelin's `ERC20._transfer` and `ERC20Mintable.mint` both `require(recipient != address(0))`, so ERC20 transfers to `address(0)` revert. No equivalent guard exists for native KLAY.

### Impact Explanation

- **Asset loss**: KLAY sent by the user on the source chain is permanently burned on the destination chain (sent to `address(0)`).
- **Nonce consumption**: `requestNonce` on the source bridge and `lowerHandleNonce`/`handleNoncesToBlockNums` on the destination bridge are both consumed and cannot be reused, matching the allowed impact of "key/nonce consumption affecting KAIA, bridged assets."
- The loss is irreversible; there is no recovery path once `handleKLAYTransfer` executes.

### Likelihood Explanation

Any user can trigger this by calling `requestKLAYTransfer(address(0), value, extraData)`. No special privilege is required. The most likely scenario is accidental user error (e.g., a dApp passing an uninitialized address), but a malicious actor could also deliberately burn another party's bridged KLAY if they control the `_to` parameter in a wrapper contract.

### Recommendation

Add a zero-address guard in `_requestKLAYTransfer` (which covers both the public `requestKLAYTransfer` and the fallback path):

```solidity
function _requestKLAYTransfer(address _to, uint256 _feeLimit, bytes memory _extraData)
    internal unlockedKLAY nonReentrant
{
    require(_to != address(0), "zero recipient address");
    require(isRunning, "stopped bridge");
    require(msg.value > _feeLimit, "insufficient amount");
    ...
}
```

Optionally add the same guard in `handleKLAYTransfer` as a defence-in-depth measure:

```solidity
require(_to != address(0), "zero recipient address");
```

### Proof of Concept

1. Deploy `BridgeTransferKLAY` on source chain (child chain) and destination chain (parent chain), pair them, register an operator.
2. Call `requestKLAYTransfer(address(0), 1 ether, "0x")` with `msg.value = 1 ether` on the source bridge.
3. The `RequestValueTransfer` event is emitted with `to = address(0)`.
4. The bridge manager relays the event and calls `handleKLAYTransfer(txHash, caller, address(0), 1 ether, 0, blockNum, "0x")` on the destination bridge.
5. `address(0).call.value(1 ether)("")` returns `(true, "")`.
6. `require(ok, ...)` passes; `lowerHandleNonce` advances.
7. 1 KAIA is permanently burned; the user's funds are unrecoverable.

---

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-99)
```text
    function handleKLAYTransfer(
        bytes32 _requestTxHash,
        address _from,
        address payable _to,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
        nonReentrant
    {
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.KLAY,
            _from,
            _to,
            address(0),
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-124)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
        require(isRunning, "stopped bridge");
        require(msg.value > _feeLimit, "insufficient amount");

        uint256 fee = _payKLAYFeeAndRefundChange(_feeLimit);

        emit RequestValueTransfer(
            TokenType.KLAY,
            msg.sender,
            _to,
            address(0),
            msg.value.sub(_feeLimit),
            requestNonce,
            fee,
            _extraData
        );
        requestNonce++;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-135)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```

**File:** node/sc/bridge_manager.go (L331-337)
```go
	switch tokenType {
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
```
