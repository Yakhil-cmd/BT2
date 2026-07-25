### Title
Malicious Recipient Contract Can Permanently Lock KLAY in Service-Chain Bridge by Reverting on Receipt in `handleKLAYTransfer` — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`BridgeTransferKLAY.handleKLAYTransfer` delivers bridged KLAY to the destination address `_to` via a low-level `_to.call.value(_value)("")`. If `_to` is a contract whose fallback reverts, the operator transaction reverts entirely. Because the source-chain user's KLAY is already locked in the source bridge with no refund path, the funds are permanently frozen. Additionally, `lowerHandleNonce` cannot advance past the stuck nonce, degrading the bridge's value-transfer recovery mechanism for all subsequent transfers.

---

### Finding Description

In `handleKLAYTransfer`, the execution order is:

1. Nonce and vote state are updated (lines 81–84): `_setHandledRequestTxHash`, `handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber`, `_updateHandleNonce`.
2. `HandleValueTransfer` event is emitted (line 86).
3. KLAY is pushed to `_to` via `_to.call.value(_value)("")` (line 98).
4. `require(ok, "handleKLAYTransfer: transfer failed")` (line 99). [1](#0-0) 

If `_to` is a contract whose fallback reverts, step 4 causes the entire transaction to revert, rolling back all state changes from steps 1–2 (including `closedValueTransferVotes[_requestedNonce]`, `handledRequestTx[_requestTxHash]`, and `handleNoncesToBlockNums`). Operators must retry, but if `_to` always reverts, no retry can ever succeed.

On the source chain, the user's KLAY was already locked in the source bridge when `requestKLAYTransfer` was called — the KLAY was sent as `msg.value` and `requestNonce` was incremented. [2](#0-1) 

There is no mechanism to refund the user's KLAY on the source chain if the destination transfer permanently fails. The KLAY is irrecoverably frozen in the source bridge.

Furthermore, `_updateHandleNonce` advances `lowerHandleNonce` only when `handleNoncesToBlockNums[i] > 0` for consecutive nonces. Since the failed transaction reverts `handleNoncesToBlockNums[_requestedNonce]` to 0, `lowerHandleNonce` is permanently stuck at the failed nonce. [3](#0-2) 

The value-transfer recovery module uses `RecoveryBlockNumber` (derived from `lowerHandleNonce`) to scan for missed events; a permanently stuck nonce degrades this recovery path for all subsequent transfers. [4](#0-3) 

The same push-payment vulnerability exists in `_payKLAYFeeAndRefundChange` where `feeReceiver.call.value(fee)("")` is called — if `feeReceiver` is a reverting contract, all KLAY bridge requests are blocked. However, `feeReceiver` is set only by the bridge owner (privileged), so that path is out of scope. [5](#0-4) 

---

### Impact Explanation

- **Unauthorized lock of KLAY**: A user's bridged KLAY is permanently frozen in the source bridge with no recovery path. The exact corrupted value is the full `msg.value - feeLimit` KLAY sent by the user in `requestKLAYTransfer`.
- **Bridge nonce state corruption**: `lowerHandleNonce` is stuck, impairing the bridge's recovery mechanism for all subsequent transfers at and above the stuck nonce.

---

### Likelihood Explanation

- Any user who sends KLAY to a contract address on the destination chain that reverts on receipt triggers this condition.
- A malicious party can deploy a reverting contract at a predictable address (e.g., via CREATE2) before a victim sends KLAY to that address, deliberately trapping the victim's funds — a direct analog to the Astaria vault-owner refusing repayment.
- The `nonReentrant` guard on `handleKLAYTransfer` does not protect against a reverting recipient; it only prevents recursive re-entry.
- No existing guard in the bridge validates that `_to` is capable of receiving KLAY before committing the transfer.

---

### Recommendation

Replace the push-payment pattern with a pull-payment pattern for KLAY delivery:

- Store the KLAY in the bridge contract mapped to the recipient address upon a successful vote.
- Allow the recipient to claim their KLAY via a separate `claimKLAY(uint64 nonce)` function.
- This eliminates the dependency on the recipient's ability to receive KLAY and decouples nonce advancement from asset delivery.

Alternatively, add a fallback mechanism that allows bridge operators to redirect a permanently failed transfer to a designated recovery address after a configurable timeout, with the original `_to` address recorded on-chain for auditability.

---

### Proof of Concept

1. Alice calls `requestKLAYTransfer(bobContract, value, extraData)` on chain A, sending `value + feeLimit` KLAY. Alice's KLAY is locked in the source bridge; `requestNonce` is incremented.
2. Bob deploys `bobContract` on chain B with a fallback that always reverts (e.g., `revert("no KLAY")`).
3. Bridge operators observe the `RequestValueTransfer` event and call `handleKLAYTransfer(txHash, alice, bobContract, value, nonce, blockNum, extraData)` on chain B.
4. `bobContract`'s fallback reverts; `require(ok, "handleKLAYTransfer: transfer failed")` causes the entire transaction to revert, rolling back all nonce state.
5. Operators retry indefinitely but always fail.
6. Alice's KLAY is permanently locked in the source bridge with no refund mechanism.
7. `lowerHandleNonce` on chain B is stuck at `nonce`, impairing recovery for all subsequent transfers. [6](#0-5) [7](#0-6)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L102-124)
```text
    // _requestKLAYTransfer requests transfer KLAY to _to on relative chain.
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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L139-156)
```text
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

**File:** node/sc/vt_recovery.go (L211-228)
```go
	hint.blockNumber, err = to.bridge.RecoveryBlockNumber(nil)
	if err != nil {
		return nil, err
	}

	requestNonce, err := from.bridge.RequestNonce(nil)
	if err != nil {
		return nil, err
	}
	from.SetRequestNonce(requestNonce)
	to.SetRequestNonceFromCounterpart(requestNonce)
	hint.requestNonce = requestNonce

	handleNonce, err := to.bridge.LowerHandleNonce(nil)
	if err != nil {
		return nil, err
	}
	to.UpdateLowerHandleNonce(handleNonce)
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L43-66)
```text
    function _payKLAYFeeAndRefundChange(uint256 _feeLimit) internal returns(uint256) {
        uint256 fee = feeOfKLAY;

        if (feeReceiver != address(0) && fee > 0) {
            require(_feeLimit >= fee, "insufficient feeLimit");

            (bool ok, ) = feeReceiver.call.value(fee)("");
            require(ok, "transfer fee failed");

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                (bool ok, ) = msg.sender.call.value(feeRefund)("");
                require(ok, "refund fee failed");
            }

            return fee;
        }

        if (_feeLimit > 0) {
            (bool ok, ) = msg.sender.call.value(_feeLimit)("");
            require(ok, "refund fee failed");
        }
        return 0;
    }
```

**File:** node/sc/bridge_manager.go (L292-360)
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

	ctpartTokenAddr := bi.GetCounterPartToken(tokenAddr)
	// TODO-Kaia-Servicechain Add counterpart token address in requestValueTransferEvent
	if tokenType != KAIA && ctpartTokenAddr == (common.Address{}) {
		logger.Warn("Unregistered counter part token address.", "addr", ctpartTokenAddr.Hex())
		ctTokenAddr, err := bi.counterpartBridge.RegisteredTokens(nil, tokenAddr)
		if err != nil {
			return err
		}
		if ctTokenAddr == (common.Address{}) {
			return errors.New("can't get counterpart token from bridge")
		}
		if err := bi.RegisterToken(tokenAddr, ctTokenAddr); err != nil {
			return err
		}
		ctpartTokenAddr = ctTokenAddr
		logger.Info("Register counter part token address.", "addr", ctpartTokenAddr.Hex(), "cpAddr", ctTokenAddr.Hex())
	}

	bridgeAcc := bi.account

	bridgeAcc.Lock()
	defer bridgeAcc.UnLock()

	auth := bridgeAcc.GenerateTransactOpts()

	var handleTx *types.Transaction
	var err error

	switch tokenType {
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC20], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC721:
		uri := GetURI(ev)
		handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, uri, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC721], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	default:
		logger.Error("Got Unknown Token Type ReceivedEvent", "bridge", contractAddr, "nonce", requestNonce, "from", from)
		return nil
	}

	bridgeAcc.IncNonce()

	bi.bridgeDB.WriteHandleTxHashFromRequestTxHash(txHash, handleTx.Hash())
	return nil
}
```
