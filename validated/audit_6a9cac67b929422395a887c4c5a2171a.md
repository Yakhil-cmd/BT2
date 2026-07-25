### Title
Attacker-Controlled Eviction of Legitimate Bridge Transfer Events from `pendingRequestEvent` Queue Permanently Locks Bridged Assets — (File: `node/sc/bridge_manager.go`)

---

### Summary

`BridgeInfo.AddRequestValueTransferEvents` in `node/sc/bridge_manager.go` contains a flawed eviction policy: when the in-memory `pendingRequestEvent` queue exceeds `maxPendingNonceDiff` (1000) entries, any incoming event whose nonce is **≥ the current maximum nonce** in the queue is **silently dropped** with a bare `continue`. An attacker who fills the queue with sequential low-nonce requests causes every subsequent legitimate high-nonce transfer event to be discarded. If VT recovery is disabled (the default for many deployments), those events are never re-queued and the corresponding bridged assets (KAIA, ERC20, ERC721) remain permanently locked in the source bridge contract.

---

### Finding Description

`BridgeInfo.pendingRequestEvent` is initialized with `bridgepool.UnlimitedItemSortedMap` (no hard data-structure limit): [1](#0-0) 

The only capacity enforcement is a soft-cap check inside `AddRequestValueTransferEvents`: [2](#0-1) 

The eviction branch at lines 404–413 reads:

```go
if bi.pendingRequestEvent.Len() > maxPendingNonceDiff {
    flatten := bi.pendingRequestEvent.Flatten()
    maxNonce := flatten[len(flatten)-1].Nonce()
    if ev.Nonce() >= maxNonce || bi.pendingRequestEvent.Exist(ev.Nonce()) {
        continue          // ← event is silently discarded
    }
    bi.pendingRequestEvent.Remove(maxNonce)
    ...
}
```

When the queue holds 1001 items and a new event arrives with a nonce **≥ maxNonce**, the event is dropped with no persistence, no error, and no retry. The event originated from a one-shot blockchain subscription (`WatchRequestValueTransfer`): [3](#0-2) 

Once dropped, the only recovery path is the optional `valueTransferRecovery` goroutine: [4](#0-3) 

VT recovery is gated on `vtr.config.VTRecovery` and is disabled by default in many configurations. Even when enabled, it is capped at `maxPendingTxs = 1000` events per cycle: [5](#0-4) 

The codebase itself acknowledges the missing size-management logic with a TODO comment at the call site in `ProcessRequestEvent`: [6](#0-5) 

---

### Impact Explanation

`handleRequestValueTransferEvent` is the function that calls `HandleKLAYTransfer` / `HandleERC20Transfer` / `HandleERC721Transfer` on the destination bridge contract, which releases or mints the bridged asset to the recipient: [7](#0-6) 

If a `RequestValueTransfer` event is evicted from `pendingRequestEvent` before it is processed, the bridge operator never submits the corresponding handle transaction. The user's KAIA or tokens remain locked inside the source bridge contract with no on-chain mechanism to force release. This satisfies the allowed impact: **unauthorized prevention of bridge asset transfer affecting KAIA and bridged assets**.

---

### Likelihood Explanation

The bridge contract imposes no per-sender rate limit. The only barrier is the fee check: [8](#0-7) 

On a low-fee child chain (the typical Service Chain deployment), an attacker can cheaply emit 1001+ `RequestValueTransfer` events in a single block, filling the queue before any legitimate event is processed. The `maxPendingNonceDiff` constant is hardcoded at 1000 with a TODO noting it is provisional: [9](#0-8) 

---

### Recommendation

1. **Short-term**: Replace the silent `continue` drop with a per-sender sub-queue or a FIFO eviction that removes the **oldest** event from the **most prolific sender**, not the globally highest-nonce event. Alternatively, enforce a per-sender cap inside `AddRequestValueTransferEvents` so a single address cannot monopolize the queue.

2. **Long-term**: Make VT recovery mandatory (not opt-in) and ensure `recoverPendingEvents` re-adds events through a path that cannot be starved by the same attacker-controlled queue. Consider persisting the pending event queue to disk so in-memory drops do not cause permanent loss.

---

### Proof of Concept

1. Attacker calls `requestKLAYTransfer` (or `requestERC20Transfer`) on the child-chain bridge contract 1001 times in rapid succession, generating events with `requestNonce` 0 through 1000.
2. The SubBridge's `subscribeEvent` goroutine delivers all 1001 events to `AddRequestValueTransferEvents`. The queue fills to 1001 entries (`Len() > maxPendingNonceDiff`).
3. Alice calls `requestKLAYTransfer`, generating an event with `requestNonce = 1001`.
4. Alice's event arrives at `AddRequestValueTransferEvents`. The check evaluates:
   - `bi.pendingRequestEvent.Len() > 1000` → **true**
   - `maxNonce = 1000`
   - `ev.Nonce() (1001) >= maxNonce (1000)` → **true**
   - → `continue` — Alice's event is **silently discarded**.
5. The bridge operator processes the attacker's 1001 events (calling `HandleKLAYTransfer` for each), draining the queue. Alice's event is never re-queued.
6. With VT recovery disabled, Alice's KAIA remains locked in the source bridge contract indefinitely. With VT recovery enabled, Alice must wait for the next recovery interval, during which the attacker can re-flood the queue to repeat the eviction.

### Citations

**File:** node/sc/bridge_manager.go (L43-43)
```go
	maxPendingNonceDiff = 1000 // TODO-Kaia-ServiceChain: update this limitation. Currently, 2 * 500 TPS.
```

**File:** node/sc/bridge_manager.go (L140-140)
```go
		pendingRequestEvent:         bridgepool.NewItemSortedMap(bridgepool.UnlimitedItemSortedMap),
```

**File:** node/sc/bridge_manager.go (L332-354)
```go
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

**File:** node/sc/bridge_manager.go (L402-418)
```go
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
```

**File:** node/sc/bridge_manager.go (L1017-1021)
```go
	chanReqVT := make(chan *bridgecontract.BridgeRequestValueTransfer, TokenEventChanSize)
	chanReqVTencoded := make(chan *bridgecontract.BridgeRequestValueTransferEncoded, TokenEventChanSize)
	chanHandleVT := make(chan *bridgecontract.BridgeHandleValueTransfer, TokenEventChanSize)

	vtEv, err := bridge.WatchRequestValueTransfer(nil, chanReqVT, nil, nil, nil)
```

**File:** node/sc/vt_recovery.go (L31-31)
```go
	maxPendingTxs    = 1000
```

**File:** node/sc/vt_recovery.go (L90-93)
```go
func (vtr *valueTransferRecovery) Start() error {
	if !vtr.config.VTRecovery {
		return ErrVtrDisabled
	}
```

**File:** node/sc/sub_event_handler.go (L84-85)
```go
	// TODO-Kaia need to manage the size limitation of pending event list.
	handleBridgeInfo.AddRequestValueTransferEvents([]IRequestValueTransferEvent{ev})
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L108-109)
```text
        require(isRunning, "stopped bridge");
        require(msg.value > _feeLimit, "insufficient amount");
```
