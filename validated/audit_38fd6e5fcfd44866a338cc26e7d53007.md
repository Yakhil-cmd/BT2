### Title
Bridge Batch Value-Transfer Processing Halts Entirely on Any Single Event Failure — (`File: node/sc/bridge_manager.go`)

---

### Summary

`processingPendingRequestEvents` in `node/sc/bridge_manager.go` iterates over a batch of ready cross-chain value-transfer events and, on the first error from any single event, re-queues **that event and all remaining events** back into the pending pool and returns immediately. Because the failing event is always re-queued at the front of the batch, every subsequent processing cycle will hit the same error, permanently stalling all cross-chain value transfers (KAIA, ERC-20, ERC-721) that follow the poisoned event in nonce order.

---

### Finding Description

`processingPendingRequestEvents` pops a batch of ready events sorted by request nonce and processes them sequentially:

```go
for idx, ev := range ReadyEvent {
    if ev.GetRequestNonce() < bi.lowerHandleNonce || bi.handledEvent.Exist(ev.GetRequestNonce()) {
        continue
    }
    if err := bi.handleRequestValueTransferEvent(ev); err != nil {
        bi.AddRequestValueTransferEvents(ReadyEvent[idx:])   // re-queues failing + all later events
        logger.Error(...)
        return
    }
}
``` [1](#0-0) 

`handleRequestValueTransferEvent` can return a non-nil error in several ways:

1. **Unregistered counterpart token** — if `bi.counterpartBridge.RegisteredTokens(nil, tokenAddr)` returns `(address(0), nil)`, the function returns `errors.New("can't get counterpart token from bridge")`.
2. **Duplicate token registration** — if `bi.RegisterToken` returns `ErrDuplicatedToken` (race between two goroutines or a recovery re-injection).
3. **RPC/network error** — any transient error from `bi.bridge.HandleKLAYTransfer / HandleERC20Transfer / HandleERC721Transfer`. [2](#0-1) [3](#0-2) 

When any of these errors occurs at event index `idx`, `ReadyEvent[idx:]` (the failing event **plus** all higher-nonce events) is re-inserted into `pendingRequestEvent` via `AddRequestValueTransferEvents`. On the next tick of the `loop()` goroutine (every second, or on `newEvent`), `GetReadyRequestValueTransferEvents` pops the same batch again, the same event fails again, and the cycle repeats indefinitely. [4](#0-3) 

There is no mechanism to skip the failing event and continue processing higher-nonce events. The bridge operator account nonce (`bridgeAcc.IncNonce()`) is only incremented on success, so no nonce drift occurs — but all subsequent transfers are blocked for as long as the root cause persists.

The `valueTransferRecovery` subsystem (`vt_recovery.go`) re-injects the same pending events via `AddRequestValueTransferEvents`, which can amplify the problem by continuously re-adding the poisoned event. [5](#0-4) 

---

### Impact Explanation

- **Unauthorized asset lock / transfer denial**: All cross-chain value transfers (KAIA, ERC-20, ERC-721) with request nonces ≥ the failing nonce are permanently blocked. Funds locked in the source bridge contract cannot be released on the destination chain.
- **Bridge nonce accounting corruption**: `lowerHandleNonce` on the destination bridge contract never advances past the stuck nonce, so the on-chain `recoveryBlockNumber` also stalls, preventing the recovery subsystem from making progress.
- **Scope**: Affects the service-chain bridge path (`node/sc`), which manages real asset transfers between Kaia mainchain and service chains.

---

### Likelihood Explanation

The trigger requires one of:
- An ERC-20 or ERC-721 token that is registered on the source bridge but whose counterpart mapping is absent or deregistered on the destination bridge at the moment the event is processed. This is a normal operational state during token registration races or after a `deregisterToken` call.
- A transient RPC error to the counterpart bridge node.

Neither condition requires privileged access or majority-validator collusion. Any user who initiates a cross-chain transfer of a token that is momentarily unregistered on the destination side can trigger the stall. The `vt_recovery` loop then continuously re-injects the same event, making the stall self-reinforcing.

---

### Recommendation

**Short term**: In `processingPendingRequestEvents`, distinguish between permanent per-event errors (e.g., unregistered token, unknown token type) and transient errors (RPC failures). For permanent errors, skip the failing event (log it, do not re-queue it) and continue processing the remaining events. Only re-queue on transient errors.

**Long term**: Introduce a per-event error counter or a "skip list" so that a single permanently-failing event cannot block the entire nonce sequence. Consider emitting a metric or alert when an event is skipped, so operators can investigate and manually resolve the root cause (e.g., re-register the token).

---

### Proof of Concept

1. Deploy a paired bridge (child ↔ parent) with an ERC-20 token registered on both sides.
2. User A initiates `requestERC20Transfer` on the child bridge for token T at request nonce N. This emits a `RequestValueTransfer` event.
3. Before the bridge operator processes nonce N, the bridge owner calls `deregisterToken(T)` on the parent bridge (or the operator's in-memory `counterpartToken` map is cleared by a restart).
4. The bridge operator's `processingPendingRequestEvents` loop picks up nonce N. `handleRequestValueTransferEvent` calls `bi.counterpartBridge.RegisteredTokens(nil, tokenAddr)`, gets `address(0)`, and returns `errors.New("can't get counterpart token from bridge")`. [6](#0-5) 

5. `processingPendingRequestEvents` executes `bi.AddRequestValueTransferEvents(ReadyEvent[idx:])`, re-queuing nonce N and all higher nonces. [7](#0-6) 

6. On the next tick (≤1 second), the same batch is popped and the same error fires. All subsequent transfers — including KAIA transfers at nonces N+1, N+2, … — are permanently blocked.
7. User B's KAIA transfer at nonce N+1 (which would succeed) is never processed. Funds remain locked in the child bridge contract indefinitely.
8. The `valueTransferRecovery` goroutine periodically calls `recoverPendingEvents` → `AddRequestValueTransferEvents`, continuously re-injecting nonce N, ensuring the stall persists even after the token is re-registered (because the re-queued event is processed before the recovery can update `lowerHandleNonce`). [8](#0-7)

### Citations

**File:** node/sc/bridge_manager.go (L173-192)
```go
func (bi *BridgeInfo) loop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	logger.Info("start bridge loop", "addr", bi.address.String(), "onChildChain", bi.onChildChain)

	for {
		select {
		case <-bi.newEvent:
			bi.processingPendingRequestEvents()

		case <-ticker.C:
			bi.processingPendingRequestEvents()

		case <-bi.closed:
			logger.Info("stop bridge loop", "addr", bi.address.String(), "onChildChain", bi.onChildChain)
			return
		}
	}
}
```

**File:** node/sc/bridge_manager.go (L248-258)
```go
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
```

**File:** node/sc/bridge_manager.go (L303-318)
```go
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
```

**File:** node/sc/bridge_manager.go (L331-354)
```go
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
```

**File:** node/sc/vt_recovery.go (L381-413)
```go
// recoverPendingEvents recovers all pending events by resending them.
func (vtr *valueTransferRecovery) recoverPendingEvents() error {
	defer func() {
		vtr.childEvents = []IRequestValueTransferEvent{}
		vtr.parentEvents = []IRequestValueTransferEvent{}
	}()

	if len(vtr.childEvents) > 0 {
		logger.Warn("VT Recovery : Child -> Parent Chain", "cBridge", vtr.cBridgeInfo.address.String(), "events", len(vtr.childEvents))
	}

	vtRequestEventMeter.Mark(int64(len(vtr.childEvents)))
	vtRecoveredRequestEventMeter.Mark(int64(len(vtr.childEvents)))

	events := make([]IRequestValueTransferEvent, len(vtr.childEvents))
	for i, event := range vtr.childEvents {
		events[i] = event
	}
	vtr.pBridgeInfo.AddRequestValueTransferEvents(events)

	if len(vtr.parentEvents) > 0 {
		logger.Warn("VT Recovery : Parent -> Child Chain", "pBridge", vtr.pBridgeInfo.address.String(), "events", len(vtr.parentEvents))
	}

	vtHandleEventMeter.Mark(int64(len(vtr.parentEvents)))
	events = make([]IRequestValueTransferEvent, len(vtr.parentEvents))
	for i, event := range vtr.parentEvents {
		events[i] = event
	}
	vtr.cBridgeInfo.AddRequestValueTransferEvents(events)

	return nil
}
```
