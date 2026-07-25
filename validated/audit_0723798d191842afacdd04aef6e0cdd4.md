### Title
Service Chain Bridge DoS via Unhandled Permanent Transfer Failure Blocking All Subsequent Value Transfers — (`node/sc/bridge_manager.go`)

---

### Summary

`processingPendingRequestEvents()` in `node/sc/bridge_manager.go` processes bridge value-transfer events sequentially. When `handleRequestValueTransferEvent` returns any error, the failing event **and every subsequent event** are re-queued and the function returns. Because `handleKLAYTransfer` / `handleERC20Transfer` in the bridge contracts revert when the on-chain asset delivery fails (e.g., recipient is a non-payable contract, or the bridge has insufficient ERC-20 liquidity), the abigen `Transact` wrapper returns an error at gas-estimation time. The same event is then retried forever, permanently blocking all higher-nonce bridge transfers. No privileged actor is required; any user who pays the bridge fee and specifies a non-payable `_to` address is sufficient.

---

### Finding Description

**Go-level event processor — `node/sc/bridge_manager.go` lines 239–259**

```go
func (bi *BridgeInfo) processingPendingRequestEvents() {
    ReadyEvent := bi.GetReadyRequestValueTransferEvents()
    ...
    for idx, ev := range ReadyEvent {
        if ev.GetRequestNonce() < bi.lowerHandleNonce || bi.handledEvent.Exist(ev.GetRequestNonce()) {
            continue
        }
        if err := bi.handleRequestValueTransferEvent(ev); err != nil {
            bi.AddRequestValueTransferEvents(ReadyEvent[idx:])   // ← re-queues failing + all later events
            logger.Error("Failed handle request value transfer event", ...)
            return                                               // ← stops processing
        }
    }
}
```

When `handleRequestValueTransferEvent` fails, `ReadyEvent[idx:]` (the failing event plus every event after it) is pushed back into `pendingRequestEvent`. The next invocation of `processingPendingRequestEvents` pops the same batch and hits the same error again. There is no skip, no retry-count limit, and no distinction between transient and permanent failures.

**On-chain failure points — `contracts/service_chain/bridge/BridgeTransferKLAY.sol` lines 81–99**

```solidity
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);          // nonce state written here
emit HandleValueTransfer(...);

(bool ok, ) = _to.call.value(_value)("");     // ← can fail if _to is non-payable
require(ok, "handleKLAYTransfer: transfer failed");  // ← reverts entire tx
```

The nonce state is written before the asset delivery. If the low-level call fails, the `require` reverts the entire transaction, rolling back the nonce update. The abigen `Transact` wrapper calls `EstimateGas` first; because the simulation reverts, it returns an error to the Go caller before any transaction is submitted.

**On-chain failure points — `contracts/service_chain/bridge/BridgeTransferERC20.sol` lines 51–72**

```solidity
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);          // nonce state written here
emit HandleValueTransfer(...);

if (modeMintBurn) {
    require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
} else {
    IERC20(_tokenAddress).safeTransfer(_to, _value);  // ← reverts on failure
}
```

The same pattern applies: nonce written, then asset delivery, then revert on failure.

**`handleRequestValueTransferEvent` propagates the error — `node/sc/bridge_manager.go` lines 332–336**

```go
case KAIA:
    handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
    if err != nil {
        return err   // ← returned to processingPendingRequestEvents
    }
```

---

### Impact Explanation

- **`lowerHandleNonce` on the destination bridge contract never advances** past the stuck nonce. The `_updateHandleNonce` loop in `BridgeTransfer.sol` (lines 149–155) only advances `lowerHandleNonce` when consecutive `handleNoncesToBlockNums[i]` entries are non-zero; because the stuck nonce's entry is never written (the tx reverts), the counter is frozen.
- **All subsequent bridge transfers are permanently blocked.** Every event with a nonce greater than the stuck nonce is re-queued behind it and never processed.
- **`recoveryBlockNumber` is frozen**, so the value-transfer recovery subsystem (`vt_recovery.go`) re-fetches and re-queues the same stuck event, compounding the loop.
- **Bridged assets (KAIA, ERC-20, ERC-721) are locked** on the source chain for all users who submitted requests after the stuck one.

---

### Likelihood Explanation

The trigger is a normal, permissionless user action: calling `requestKLAYTransfer` (or `requestERC20Transfer`) with a `_to` address that is a contract without a payable fallback. This is a realistic accident (e.g., a user specifying a multisig or DAO contract that does not accept direct KLAY). The user pays only the bridge fee. A single such request permanently DoS-es the entire bridge pipeline for all subsequent users. No validator collusion, no compromised key, and no privileged role is required.

---

### Recommendation

1. **In `processingPendingRequestEvents`**: distinguish permanent failures from transient ones. After a configurable number of consecutive retries for the same nonce, log the event as permanently undeliverable, skip it (do not re-queue it at the front), and continue processing subsequent events.

2. **In `handleKLAYTransfer` / `handleERC20Transfer`**: consider separating the nonce-advance step from the asset-delivery step. If delivery fails, record the failure on-chain (e.g., a `FailedValueTransfer` event) and advance the nonce anyway, so the bridge pipeline is not blocked. Alternatively, refund the sender on the source chain.

3. **In `handleRequestValueTransferEvent`**: before submitting the transaction, perform a dry-run (`eth_call`) to detect permanent reverts and handle them without blocking the queue.

---

### Proof of Concept

1. Deploy a bridge pair (child ↔ parent) with a single operator.
2. Deploy a non-payable contract `Sink` on the destination chain (no `receive`/`fallback`).
3. On the source chain, call `requestKLAYTransfer(Sink, value, "")`. This emits `RequestValueTransfer` with `requestNonce = N`.
4. Submit two more legitimate requests to EOA addresses, producing nonces `N+1` and `N+2`.
5. The operator node picks up all three events and calls `processingPendingRequestEvents`.
6. For nonce `N`: `bi.bridge.HandleKLAYTransfer(...)` calls `EstimateGas`; the simulation reverts at `require(ok, "handleKLAYTransfer: transfer failed")`; the function returns an error.
7. `processingPendingRequestEvents` calls `bi.AddRequestValueTransferEvents(ReadyEvent[0:])` — re-queuing nonces `N`, `N+1`, `N+2` — and returns.
8. On the next tick, the same three events are dequeued; step 6–7 repeats indefinitely.
9. Nonces `N+1` and `N+2` are never delivered. `lowerHandleNonce` on the destination contract remains at `N`. The bridge is permanently stuck. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** node/sc/bridge_manager.go (L239-259)
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
```

**File:** node/sc/bridge_manager.go (L292-359)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L75-99)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L44-72)
```text
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
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
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
