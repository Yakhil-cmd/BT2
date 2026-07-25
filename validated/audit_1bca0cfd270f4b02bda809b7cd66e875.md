### Title
Recipient-controlled revert in `handleKLAYTransfer` permanently locks bridged KLAY and stalls `lowerHandleNonce` — (File: `contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary
`handleKLAYTransfer` writes all bridge state (handled-tx hash, nonce mappings) before making an uncapped low-level call to the user-supplied `_to` address. If `_to` is a contract that reverts, `require(ok)` on line 99 rolls back every state write in the same transaction. The nonce is never marked handled, the bridged KLAY is permanently locked in the bridge contract, and `lowerHandleNonce` never advances past the stuck nonce.

### Finding Description
`handleKLAYTransfer` in `BridgeTransferKLAY.sol` follows this execution order:

1. `_setHandledRequestTxHash(_requestTxHash)` — marks the request as handled in `handledRequestTx`
2. `handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber` — records the block number
3. `_updateHandleNonce(_requestedNonce)` — advances `lowerHandleNonce` / `upperHandleNonce`
4. `emit HandleValueTransfer(...)` — emits the event
5. `(bool ok, ) = _to.call.value(_value)("")` — low-level call to user-controlled address
6. `require(ok, "handleKLAYTransfer: transfer failed")` — reverts the entire transaction if the call failed [1](#0-0) 

Because step 6 issues an unconditional revert when `ok == false`, all state writes from steps 1–3 are rolled back by the EVM. The `handledRequestTx[_requestTxHash]` mapping is reset to `false`, `handleNoncesToBlockNums[_requestedNonce]` is reset to 0, and `lowerHandleNonce` is not advanced.

The `_to` address originates from the user's `requestKLAYTransfer` call on the source chain: [2](#0-1) 

The bridge operator faithfully relays this address to `handleKLAYTransfer` on the destination chain: [3](#0-2) 

`_updateHandleNonce` advances `lowerHandleNonce` only while consecutive nonces have `handleNoncesToBlockNums[i] > 0`. A stuck nonce permanently halts this advancement: [4](#0-3) 

There is no operator-accessible skip or cancel function in the bridge contract. The `nonReentrant` guard prevents reentrancy but does not address the stuck-nonce scenario.

### Impact Explanation
- **Permanent KLAY lock**: The `_value` KLAY is held in the bridge contract indefinitely. The destination-chain recipient never receives it, and the source-chain user has already surrendered their KLAY.
- **`lowerHandleNonce` stall**: `recoveryBlockNumber` never advances past the stuck nonce's block, degrading the value-transfer recovery mechanism (`VTRecovery`) for all subsequent transfers.
- **Corrupted bridge accounting**: `handledRequestTx[_requestTxHash]` remains `false` even though the source-chain event was consumed, creating a permanent inconsistency between source and destination bridge state.

### Likelihood Explanation
Any user on the source chain can set `_to` to a contract that always reverts on KLAY receipt (e.g., a contract with no payable fallback, or one that explicitly `revert()`s). No privileged access is required. The attack is cheap to execute and requires only a single source-chain transaction.

### Recommendation
Apply the checks-effects-interactions pattern correctly: perform the low-level KLAY transfer **before** writing `handledRequestTx` and updating nonce state, or — better — add a pull-payment mechanism so the recipient claims KLAY separately, decoupling the state commit from the external call. At minimum, cap the gas forwarded to `_to` (e.g., `_to.call.gas(2300).value(_value)("")`) to prevent the callee from consuming all available gas and to limit the attack surface.

### Proof of Concept
1. Deploy `MaliciousReceiver` on the destination chain:
   ```solidity
   contract MaliciousReceiver {
       receive() external payable { revert("no KLAY"); }
   }
   ```
2. On the source chain, call `requestKLAYTransfer(address(MaliciousReceiver), value, "")` with `msg.value = value + fee`.
3. The bridge operator observes the `RequestValueTransfer` event and calls `handleKLAYTransfer(txHash, from, address(MaliciousReceiver), value, nonce, blockNum, "")`.
4. Inside `handleKLAYTransfer`, steps 1–4 execute (state written, event emitted), then `_to.call.value(value)("")` returns `ok = false`.
5. `require(ok)` reverts the transaction; all state writes are rolled back.
6. `handledRequestTx[txHash]` remains `false`; `lowerHandleNonce` is not advanced.
7. Every subsequent retry by the operator produces the same result. The `value` KLAY is permanently locked in the bridge contract. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-100)
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
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L131-135)
```text
    // requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```

**File:** node/sc/bridge_manager.go (L332-337)
```go
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L138-156)
```text
    // _updateHandleNonce increases lower and upper handle nonce after the _requestedNonce is handled.
    function _updateHandleNonce(uint64 _requestedNonce) internal {
        if (_requestedNonce > upperHandleNonce) {
            upperHandleNonce = _requestedNonce;
        }

        uint64 limit = lowerHandleNonce + 200;
        if (limit > upperHandleNonce) {
            limit = upperHandleNonce;
        }

        uint64 i;
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
    }
```

**File:** contracts/service_chain/bridge/BridgeHandledRequests.sol (L19-25)
```text
contract BridgeHandledRequests {
    // TODO-Klaytn-Servicechain handleTxHash can be saved after Klaytn supports it.
    mapping(bytes32 => bool) public handledRequestTx;

    function _setHandledRequestTxHash(bytes32 _requestTxHash) internal {
        handledRequestTx[_requestTxHash] = true;
    }
```
