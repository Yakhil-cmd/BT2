### Title
`deregisterToken` Makes In-Flight ERC20/ERC721 Bridge Transfers Permanently Unrecoverable — (`contracts/service_chain/bridge/BridgeTokens.sol`)

### Summary

`deregisterToken` in the service-chain bridge immediately erases the on-chain token registration with no check for pending in-flight value-transfer requests. When the off-chain bridge operator subsequently tries to process a `RequestValueTransfer` event whose token has been deregistered, `handleRequestValueTransferEvent` in `bridge_manager.go` cannot resolve the counterpart token address, returns a hard error, and re-queues the same event forever. The tokens are permanently locked or burned on the source chain and never released on the destination chain. Because `processingPendingRequestEvents` aborts the entire batch on the first error, all subsequent bridge transfers for every token are also blocked.

### Finding Description

**Step 1 – User initiates a cross-chain ERC20 transfer.**

`_requestERC20Transfer` in `BridgeTransferERC20.sol` checks `onlyRegisteredToken` and `onlyUnlockedToken`, locks (or burns in mint-burn mode) the user's tokens, and emits `RequestValueTransfer` with `requestNonce = N`. [1](#0-0) 

**Step 2 – Bridge owner calls `deregisterToken` on the source bridge.**

`deregisterToken` is `onlyOwner` and immediately deletes `registeredTokens[_token]` and `lockedTokens[_token]` with no guard against pending nonces. [2](#0-1) 

**Step 3 – Off-chain operator tries to handle the pending event.**

`handleRequestValueTransferEvent` first checks the in-memory cache (`bi.GetCounterPartToken`). If the cache is empty (fresh start, or the API-level `DeregisterToken` was also called), it falls back to querying the source bridge on-chain:

```go
ctTokenAddr, err := bi.counterpartBridge.RegisteredTokens(nil, tokenAddr)
if ctTokenAddr == (common.Address{}) {
    return errors.New("can't get counterpart token from bridge")
}
```

Because the token was deregistered, `RegisteredTokens` returns `address(0)` and the function returns an error. [3](#0-2) 

**Step 4 – The event is re-queued and retried forever.**

`processingPendingRequestEvents` re-inserts the failing event and all subsequent events back into the pending queue, then returns. The ticker fires every second and the same failure repeats indefinitely. [4](#0-3) 

**Step 5 – All subsequent transfers are blocked.**

Because the loop aborts on the first error and re-queues `ReadyEvent[idx:]`, every event with a nonce ≥ N is also stuck. The `lowerHandleNonce` on the destination bridge never advances past N, so even transfers for other tokens are blocked. [5](#0-4) 

### Impact Explanation

Bridged ERC20 and ERC721 assets are permanently lost: locked or burned on the source chain, never minted or transferred on the destination chain. Additionally, the entire bridge pipeline is frozen — no further value transfers of any token can be processed until the stuck nonce is manually resolved (which requires re-registering the token and restarting the operator, a non-trivial operational recovery with no on-chain mechanism).

The exact corrupted state: `registeredTokens[tokenAddr] == address(0)` on the source bridge while `handleNoncesToBlockNums[N] == 0` on the destination bridge (nonce N was never handled), causing `lowerHandleNonce` to stall at N permanently.

### Likelihood Explanation

The bridge owner is a semi-trusted party (service-chain operator) who has a legitimate reason to deregister a token — for example, to replace a token contract, to stop supporting an asset, or to respond to a security incident. The operation appears safe in isolation; nothing in the contract or the API warns that in-flight requests will be permanently lost. The probability of this occurring during a token migration or deprecation event is non-trivial.

### Recommendation

1. **Guard `deregisterToken` against pending nonces.** Before removing the registration, verify that `requestNonce == upperHandleNonce` (all requests have been handled) on the source bridge, or that the destination bridge's `lowerHandleNonce` has caught up.

2. **Add a two-step deregistration with a delay.** Lock the token first (preventing new requests) and only allow full deregistration after a configurable delay that gives the operator time to drain the pending queue.

3. **Skip unresolvable events instead of blocking the pipeline.** In `handleRequestValueTransferEvent`, if the counterpart token cannot be resolved, log the error and skip that nonce rather than re-queuing it indefinitely, so that other tokens' transfers are not blocked.

### Proof of Concept

```
1. Deploy source bridge (S) and destination bridge (D).
2. Register token T on both bridges (on-chain + in-memory).
3. User calls S.requestERC20Transfer(T, alice, 100, ...).
   → T locked on S, RequestValueTransfer(nonce=0) emitted.
4. Bridge owner calls S.deregisterToken(T).
   → S.registeredTokens[T] = address(0).
5. Off-chain operator processes nonce=0:
   → bi.GetCounterPartToken(T) = address(0)  [cache miss]
   → bi.counterpartBridge.RegisteredTokens(nil, T) = address(0)  [deregistered]
   → returns error "can't get counterpart token from bridge"
6. processingPendingRequestEvents re-queues nonce=0 and returns.
7. Ticker fires every second → same failure, forever.
8. User's 100 T are permanently locked on S; alice never receives them on D.
9. Any subsequent transfer (nonce=1, 2, ...) is also blocked.
``` [6](#0-5) [2](#0-1) [7](#0-6)

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

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L74-92)
```text
    function deregisterToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
    {
        delete registeredTokens[_token];
        delete lockedTokens[_token];

        uint idx = indexOfTokens[_token];
        delete indexOfTokens[_token];

        if (idx < registeredTokenList.length-1) {
            registeredTokenList[idx] = registeredTokenList[registeredTokenList.length-1];
            indexOfTokens[registeredTokenList[idx]] = idx;
        }
        registeredTokenList.length--;

        emit TokenDeregistered(_token);
    }
```

**File:** node/sc/bridge_manager.go (L239-260)
```go
// processingPendingRequestEvents handles pending request value transfer events of the bridge.
func (bi *BridgeInfo) processingPendingRequestEvents() {
	ReadyEvent := bi.GetReadyRequestValueTransferEvents()
	if ReadyEvent == nil {
		return
	}

	logger.Trace("Get ready request value transfer event", "len(readyEvent)", len(ReadyEvent), "len(pendingEvent)", bi.pendingRequestEvent.Len())

	for idx, ev := range ReadyEvent {
		if ev.GetRequestNonce() < bi.lowerHandleNonce || bi.handledEvent.Exist(ev.GetRequestNonce()) {
			logger.Trace("handled requests can be ignored", "RequestNonce", ev.GetRequestNonce(), "lowerHandleNonce", bi.lowerHandleNonce)
			continue
		}

		if err := bi.handleRequestValueTransferEvent(ev); err != nil {
			bi.AddRequestValueTransferEvents(ReadyEvent[idx:])
			logger.Error("Failed handle request value transfer event", "err", err, "len(RePutEvent)", len(ReadyEvent[idx:]))
			return
		}
	}
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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L138-160)
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

    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
    }
```
