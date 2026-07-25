### Title
Blocking Value-Transfer Queue in `processingPendingRequestEvents` Permanently Halts All Bridge Asset Transfers - (File: node/sc/bridge_manager.go)

### Summary

The Kaia service-chain bridge's off-chain relay loop (`processingPendingRequestEvents`) processes pending cross-chain value-transfer events strictly in nonce order. When any single event fails (e.g., unregistered counterpart token, insufficient bridge liquidity), the failing event and all higher-nonce events are re-queued and the loop returns immediately. There is no mechanism to skip or force-advance past a stuck event. This is the direct Kaia analog of the LayerZero "missing nonblocking receiver / missing `forceResumeReceive`" pattern: one bad message permanently blocks the entire bridge queue, freezing all subsequent KAIA, ERC20, and ERC721 transfers.

---

### Finding Description

`BridgeInfo.processingPendingRequestEvents` in `node/sc/bridge_manager.go` iterates over ready events in ascending nonce order:

```go
for idx, ev := range ReadyEvent {
    if ev.GetRequestNonce() < bi.lowerHandleNonce || bi.handledEvent.Exist(ev.GetRequestNonce()) {
        continue
    }
    if err := bi.handleRequestValueTransferEvent(ev); err != nil {
        bi.AddRequestValueTransferEvents(ReadyEvent[idx:])   // re-queue from failing event onward
        logger.Error("Failed handle request value transfer event", ...)
        return                                               // stop processing
    }
}
``` [1](#0-0) 

When `handleRequestValueTransferEvent` returns an error, `ReadyEvent[idx:]` — the failing event **and every higher-nonce event** — is re-inserted into `pendingRequestEvent` via `AddRequestValueTransferEvents`, and the function returns. On the next tick (1-second ticker or `newEvent` signal), the same failing event is at the front of the queue and the same error recurs. [2](#0-1) 

Two realistic, unprivileged-trigger failure modes exist inside `handleRequestValueTransferEvent`:

**Mode 1 — Unregistered counterpart ERC20 token:**

```go
if ctTokenAddr == (common.Address{}) {
    return errors.New("can't get counterpart token from bridge")
}
``` [3](#0-2) 

The source bridge enforces `onlyRegisteredToken` on `_requestERC20Transfer`, so a token must be registered on the source side before a user can request a transfer. [4](#0-3) 

However, counterpart-token registration on the **destination** bridge is a separate, independent step. If an operator registers a token on the source but omits the destination registration, any user who calls `requestERC20Transfer` for that token emits a `RequestValueTransfer` event that the relay will attempt — and permanently fail — to handle.

**Mode 2 — Insufficient KAIA balance in destination bridge:**

```go
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [5](#0-4) 

If the destination bridge contract holds less KAIA than the requested `_value`, `HandleKLAYTransfer` reverts. The relay's `bi.bridge.HandleKLAYTransfer(...)` call returns an error, triggering the same re-queue-and-halt path. [6](#0-5) 

**The `valueTransferRecovery` does not help:**

`recoverPendingEvents` calls `AddRequestValueTransferEvents` with the same stuck events, re-inserting them into the already-blocked queue. It does not skip nonces or advance `lowerHandleNonce`. [7](#0-6) 

There is no admin API equivalent to LayerZero's `forceResumeReceive` — no function to skip a specific nonce and allow the queue to drain.

---

### Impact Explanation

Once the queue is blocked at nonce N:
- All value-transfer requests with nonce ≥ N are frozen on the destination chain.
- Users who have already locked KAIA or ERC20/ERC721 tokens on the source chain cannot receive their assets on the destination chain.
- The bridge's `lowerHandleNonce` never advances past N, so the on-chain nonce window does not move.
- The `valueTransferRecovery` loop continuously re-submits the same failing events, wasting operator gas without making progress.

This constitutes a persistent denial of KAIA/bridged-asset withdrawals and transfers — a direct impact on bridged assets.

---

### Likelihood Explanation

- **Mode 1** requires only that a token is registered on the source bridge but not the destination — a realistic operator misconfiguration. Any user can then trigger the block with a single `requestERC20Transfer` call.
- **Mode 2** requires the destination bridge to be underfunded. Bridges can become underfunded through normal operation (many outbound transfers). Any user can then send a KAIA transfer request that exceeds the remaining balance.
- Neither mode requires privileged access. The source-chain transaction is a normal user action.

---

### Recommendation

1. **Skip-and-log pattern (nonblocking relay):** In `processingPendingRequestEvents`, catch errors per-event, log them, and continue to the next event rather than re-queuing and halting. Maintain a separate "failed nonces" set for operator inspection.
2. **Admin skip API:** Expose a `SubBridgeAPI` method that allows the bridge operator to explicitly mark a nonce as skipped (advancing `lowerHandleNonce` past it), analogous to LayerZero's `forceResumeReceive`.
3. **Pre-flight validation:** Before calling `handleRequestValueTransferEvent`, verify that the counterpart token is registered and that the destination bridge has sufficient balance. If not, emit a warning and skip rather than blocking.
4. **Separate error classes:** Distinguish transient errors (RPC timeout) from permanent errors (unregistered token) and only re-queue on transient failures.

---

### Proof of Concept

**Mode 1 — ERC20 token registered on source only:**

1. Operator deploys source bridge (child chain) and destination bridge (parent chain).
2. Operator registers `TokenA` on the source bridge via `registerToken`.
3. Operator **omits** registering `TokenA`'s counterpart on the destination bridge.
4. User calls `requestERC20Transfer(TokenA, recipient, amount, ...)` on the source bridge. The source bridge emits `RequestValueTransfer` with nonce N.
5. The relay's `processingPendingRequestEvents` picks up nonce N, calls `bi.counterpartBridge.RegisteredTokens(nil, tokenAddr)`, receives `address(0)`, and returns `errors.New("can't get counterpart token from bridge")`.
6. `ReadyEvent[N:]` is re-queued. All subsequent events (nonces N+1, N+2, …) are also blocked.
7. Every 1-second tick repeats step 5–6. The bridge queue is permanently halted.
8. Any KAIA or ERC20/ERC721 transfer requests submitted after nonce N are never processed on the destination chain, locking user funds. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** node/sc/bridge_manager.go (L303-313)
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
```

**File:** node/sc/bridge_manager.go (L333-336)
```go
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
```

**File:** node/sc/bridge_manager.go (L401-425)
```go
// AddRequestValueTransferEvents adds events into the pendingRequestEvent.
func (bi *BridgeInfo) AddRequestValueTransferEvents(evs []IRequestValueTransferEvent) {
	for _, ev := range evs {
		if bi.pendingRequestEvent.Len() > maxPendingNonceDiff {
			flatten := bi.pendingRequestEvent.Flatten()
			maxNonce := flatten[len(flatten)-1].Nonce()
			if ev.Nonce() >= maxNonce || bi.pendingRequestEvent.Exist(ev.Nonce()) {
				continue
			}
			bi.pendingRequestEvent.Remove(maxNonce)
			vtPendingRequestEventCounter.Dec(1)
			logger.Trace("List is full but add requestValueTransfer ", "newNonce", ev.Nonce(), "removedNonce", maxNonce)
		}

		bi.SetRequestNonceFromCounterpart(ev.GetRequestNonce() + 1)
		bi.pendingRequestEvent.Put(ev)
		vtPendingRequestEventCounter.Inc(1)
	}
	logger.Trace("added pending request events to the bridge info:", "bi.pendingRequestEvent", bi.pendingRequestEvent.Len())

	select {
	case bi.newEvent <- struct{}{}:
	default:
	}
}
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L83-88)
```text
    )
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L98-99)
```text
        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
```

**File:** node/sc/vt_recovery.go (L382-412)
```go
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
```
