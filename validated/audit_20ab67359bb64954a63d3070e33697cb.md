### Title
Single Bridge Pair Failure Silently Blocks Restoration of All Subsequent Bridge Pairs — (`node/sc/bridge_manager.go`)

---

### Summary

`BridgeManager.RestoreBridges` iterates over all journaled bridge pairs and uses `break` (not `continue`) in every error path. A single bridge pair that fails to restore — for any reason — silently prevents every subsequent bridge pair in the journal from being restored. The affected bridges never start their event-processing loops or value-transfer-recovery goroutines, so all cross-chain value transfers for those bridges are permanently stuck until the node is restarted and the failing bridge is manually removed.

---

### Finding Description

`RestoreBridges` is called on sub-bridge startup to re-subscribe all previously registered bridge pairs from the on-disk journal. The loop body contains six independent `break` statements:

```go
for _, journal := range bm.journal.cache {
    cBridge, err := bridgecontract.NewBridge(cBridgeAddr, bm.subBridge.localBackend)
    if err != nil {
        logger.Error("local bridge creation is failed", ...)
        break          // ← stops the entire loop
    }
    pBridge, err := bridgecontract.NewBridge(pBridgeAddr, bm.subBridge.remoteBackend)
    if err != nil {
        logger.Error("remote bridge creation is failed", ...)
        break          // ← stops the entire loop
    }
    if !cOk {
        err = bm.SetBridgeInfo(cBridgeAddr, ...)
        if err != nil {
            ...
            break      // ← stops the entire loop
        }
    }
    if !pOk {
        err = bm.SetBridgeInfo(pBridgeAddr, ...)
        if err != nil {
            ...
            break      // ← stops the entire loop
        }
    }
    if journal.Subscribed {
        if err := bm.subscribeEvent(cBridgeAddr, ...); err != nil {
            ...
            break      // ← stops the entire loop
        }
        if err := bm.subscribeEvent(pBridgeAddr, ...); err != nil {
            ...
            break      // ← stops the entire loop
        }
        ...
    }
}
``` [1](#0-0) 

Because the journal is a map (`bm.journal.cache`) whose iteration order is non-deterministic, any bridge pair that happens to be processed before a failing one will be restored, while all pairs processed after it will silently be skipped. The function then returns `ErrBridgeRestore` but the caller logs this as a debug message and retries on a timer — it does not alert the operator that specific bridge pairs were never restored. [2](#0-1) 

Each unrestored bridge pair:
- Never starts its `BridgeInfo.loop()` goroutine, so incoming `RequestValueTransfer` events are never received.
- Never starts a `valueTransferRecovery` goroutine, so stuck nonces are never replayed.
- Never has `subscribed = true`, so the bridge operator's RPC calls will report it as unsubscribed. [3](#0-2) 

---

### Impact Explanation

Cross-chain value transfers (KAIA, ERC-20, ERC-721) for every bridge pair that was not restored are permanently stuck. The bridge contract on the counterpart chain holds the locked assets; the operator node never submits the `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` transactions needed to release them. This is a direct loss-of-liveness for bridged assets. [4](#0-3) 

---

### Likelihood Explanation

The trigger is any condition that causes one bridge pair to fail during restoration: a bridge contract that was deployed but whose counterpart RPC is temporarily unreachable, a contract whose `IsRunning` state is inconsistent, or a `SetBridgeInfo` call that returns `ErrDuplicatedBridgeInfo`. Because the journal is iterated in non-deterministic map order, the set of affected bridges changes across restarts, making the failure hard to reproduce and diagnose. Operators running multiple bridge pairs (a common production setup) are most exposed. [5](#0-4) 

---

### Recommendation

Replace every `break` inside the `RestoreBridges` loop with `continue` so that a single failing bridge pair is skipped and logged, but all remaining pairs are still processed:

```go
for _, journal := range bm.journal.cache {
    cBridge, err := bridgecontract.NewBridge(cBridgeAddr, bm.subBridge.localBackend)
    if err != nil {
        logger.Error("local bridge creation is failed", "err", err)
        continue   // ← was break
    }
    // ... all other error paths: continue instead of break
}
```

Additionally, the final success check `if len(bm.journal.cache) == counter` should be preserved so that `ErrBridgeRestore` is still returned when any pair failed, allowing the caller to retry or alert the operator.

---

### Proof of Concept

1. Register two bridge pairs A and B via `SubBridgeAPI.AddBridgePair`. Both are journaled.
2. Stop the sub-bridge node.
3. Make bridge pair A's local contract address point to a non-existent contract (or make the local RPC return an error for that address).
4. Restart the sub-bridge node. `RestoreBridges` is called.
5. Bridge pair A fails at `bridgecontract.NewBridge(cBridgeAddr, ...)` and hits `break`.
6. Bridge pair B is never processed. Its `BridgeInfo.loop()` and `valueTransferRecovery` goroutines are never started.
7. Send a `RequestValueTransfer` on bridge pair B's child-chain contract. The sub-bridge node never sees the event and never submits the handle transaction. The user's KAIA/tokens remain locked in the bridge contract indefinitely. [6](#0-5) [7](#0-6)

### Citations

**File:** node/sc/bridge_manager.go (L59-68)
```go
var (
	ErrInvalidTokenPair        = errors.New("invalid token pair")
	ErrNoBridgeInfo            = errors.New("bridge information does not exist")
	ErrDuplicatedBridgeInfo    = errors.New("bridge information is duplicated")
	ErrDuplicatedToken         = errors.New("token is duplicated")
	ErrNoRecovery              = errors.New("recovery does not exist")
	ErrAlreadySubscribed       = errors.New("already subscribed")
	ErrBridgeRestore           = errors.New("restoring bridges is failed")
	ErrBridgeAliasFormatDecode = errors.New("failed to decode alias-format bridge")
)
```

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

**File:** node/sc/bridge_manager.go (L704-791)
```go
func (bm *BridgeManager) RestoreBridges() error {
	if bm.subBridge.peers.Len() < 1 {
		logger.Debug("check peer connections to restore bridges")
		return ErrBridgeRestore
	}

	counter := 0
	bm.stopAllRecoveries()

	bm.journal.cacheMu.RLock()
	defer bm.journal.cacheMu.RUnlock()

	for _, journal := range bm.journal.cache {
		cBridgeAddr := journal.ChildAddress
		pBridgeAddr := journal.ParentAddress
		bacc := bm.subBridge.bridgeAccounts

		// Set bridge info
		cBridgeInfo, cOk := bm.GetBridgeInfo(cBridgeAddr)
		pBridgeInfo, pOk := bm.GetBridgeInfo(pBridgeAddr)

		cBridge, err := bridgecontract.NewBridge(cBridgeAddr, bm.subBridge.localBackend)
		if err != nil {
			logger.Error("local bridge creation is failed", "err", err, "bridge", cBridge)
			break
		}

		pBridge, err := bridgecontract.NewBridge(pBridgeAddr, bm.subBridge.remoteBackend)
		if err != nil {
			logger.Error("remote bridge creation is failed", "err", err, "bridge", pBridge)
			break
		}

		if !cOk {
			err = bm.SetBridgeInfo(cBridgeAddr, cBridge, pBridgeAddr, pBridge, bacc.cAccount, true, false)
			if err != nil {
				logger.Error("setting local bridge info is failed", "err", err)
				bm.DeleteBridgeInfo(cBridgeAddr)
				break
			}
			cBridgeInfo, _ = bm.GetBridgeInfo(cBridgeAddr)
		}

		if !pOk {
			err = bm.SetBridgeInfo(pBridgeAddr, pBridge, cBridgeAddr, cBridgeInfo.bridge, bacc.pAccount, false, false)
			if err != nil {
				logger.Error("setting remote bridge info is failed", "err", err)
				bm.DeleteBridgeInfo(pBridgeAddr)
				break
			}
			pBridgeInfo, _ = bm.GetBridgeInfo(pBridgeAddr)
		}

		// Subscribe bridge events
		if journal.Subscribed {
			bm.UnsubscribeEvent(cBridgeAddr)
			bm.UnsubscribeEvent(pBridgeAddr)

			if !cBridgeInfo.subscribed {
				logger.Info("automatic local bridge subscription", "info", cBridgeInfo, "address", cBridgeInfo.address.String())
				if err := bm.subscribeEvent(cBridgeAddr, cBridgeInfo.bridge); err != nil {
					logger.Error("local bridge subscription is failed", "err", err)
					break
				}
			}
			if !pBridgeInfo.subscribed {
				logger.Info("automatic remote bridge subscription", "info", pBridgeInfo, "address", pBridgeInfo.address.String())
				if err := bm.subscribeEvent(pBridgeAddr, pBridgeInfo.bridge); err != nil {
					logger.Error("remote bridge subscription is failed", "err", err)
					bm.DeleteBridgeInfo(pBridgeAddr)
					break
				}
			}
			recovery := bm.recoveries[cBridgeAddr]
			if recovery == nil {
				bm.AddRecovery(cBridgeAddr, pBridgeAddr)
			}
		}

		counter++
	}

	if len(bm.journal.cache) == counter {
		logger.Info("succeeded to restore bridges", "pairs", counter)
		return nil
	}
	return ErrBridgeRestore
}
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L61-100)
```text
    // handleKLAYTransfer sends the KLAY by the request.
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

**File:** node/sc/vt_recovery.go (L89-131)
```go
// Start implements starting all internal goroutines used by the value transfer recovery.
func (vtr *valueTransferRecovery) Start() error {
	if !vtr.config.VTRecovery {
		return ErrVtrDisabled
	}

	// TODO-Kaia-Servicechain If there is no user API to start recovery, remove isRunning in Start/Stop.
	if vtr.isRunning {
		return ErrVtrAlreadyStarted
	}

	vtr.wg.Add(1)

	go func() {
		ticker := time.NewTicker(time.Duration(vtr.config.VTRecoveryInterval) * time.Second)
		defer func() {
			ticker.Stop()
			vtr.wg.Done()
		}()

		if err := vtr.Recover(); err != nil {
			logger.Warn("initial value transfer recovery is failed", "err", err)
		}

		vtr.isRunning = true

		for {
			select {
			case <-vtr.stopCh:
				logger.Info("value transfer recovery is stopped")
				return
			case <-ticker.C:
				if vtr.isRunning {
					if err := vtr.Recover(); err != nil {
						logger.Trace("value transfer recovery is failed", "err", err)
					}
				}
			}
		}
	}()

	return nil
}
```
