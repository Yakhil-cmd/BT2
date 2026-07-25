### Title
Bridge Operator Can Selectively Skip Cross-Chain Value Transfer Requests, Permanently Freezing User Assets — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransfer.sol`, `BridgeOperator.sol`)

---

### Summary

Kaia's Service Chain bridge relies on a single privileged operator account to relay `RequestValueTransfer` events from the source chain to the destination chain by calling `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer`. There is no on-chain mechanism that enforces all request nonces must be handled, no timeout, and no user-initiated recovery path. A malicious or negligent operator can selectively skip specific request nonces, causing user assets to be locked in the source bridge contract indefinitely.

---

### Finding Description

When a user initiates a cross-chain transfer, the source bridge contract emits a `RequestValueTransfer` event and increments `requestNonce`. [1](#0-0) 

The destination bridge contract only releases funds when an operator calls `handleKLAYTransfer` (or the ERC20/ERC721 equivalents), which is gated by `onlyOperators`: [2](#0-1) 

The `BridgeOperator` contract initialises with `operatorThresholds[ValueTransfer] = 1`, meaning a single operator account is sufficient to execute any handle call: [3](#0-2) 

The `_lowerHandleNonceCheck` permanently rejects any handle call for a nonce that has already been swept past by `lowerHandleNonce`: [4](#0-3) 

`_updateHandleNonce` advances `lowerHandleNonce` only through a contiguous run of handled nonces (loop stops when `handleNoncesToBlockNums[i] == 0`), so a skipped nonce N keeps `lowerHandleNonce` pinned at N: [5](#0-4) 

The off-chain `valueTransferRecovery` in `vt_recovery.go` is the only mitigation, but it is **opt-in** (`VTRecovery` config flag, disabled by default), controlled by the same operator, and cannot force the operator to handle a specific nonce: [6](#0-5) 

The Go-side `processingPendingRequestEvents` also silently skips nonces below `lowerHandleNonce` or already in `handledEvent`, providing no independent enforcement: [7](#0-6) 

---

### Impact Explanation

A user who calls `requestKLAYTransfer` (or ERC20/ERC721 equivalents) on the source bridge has their assets locked in the bridge contract. If the operator never calls the corresponding `handleKLAYTransfer` for that request nonce, the assets remain locked with no on-chain recourse. Because `lowerHandleNonce` cannot advance past the skipped nonce, subsequent transfers are also stalled until the gap is filled. The corrupted protected value is the user's KAIA/ERC20/ERC721 balance locked in the bridge contract. [8](#0-7) 

---

### Likelihood Explanation

The default deployment uses a single operator account (threshold = 1). The SubBridge operator is the sole entity that can relay messages. Censorship requires only malice or negligence from this one account — the same trust model flagged in the Linea report. No external attacker capability is required; the operator itself is the trigger. [9](#0-8) 

---

### Recommendation

1. **Require sequential nonce handling on-chain**: Add a check in `handleXXXTransfer` that `_requestedNonce == lowerHandleNonce` (or enforce strict ordering), so operators cannot skip nonces.
2. **Add a timeout/expiry**: Allow users to reclaim locked assets from the source bridge if the corresponding handle has not been submitted within a configurable block window.
3. **Raise the default operator threshold** and require multiple independent operators to relay messages, mirroring the Linea recommendation to decentralize the prover.
4. **Enable VTRecovery by default** and make it independent of the operator account that may be censoring.

---

### Proof of Concept

```
1. Deploy Bridge on parent chain (lock mode, modeMintBurn=false).
2. User calls requestKLAYTransfer(to=Alice, value=1 KAIA) → emits RequestValueTransfer(nonce=5).
   Source bridge now holds 1 KAIA.
3. Operator handles nonces 6, 7, 8, … (skipping nonce 5).
   _updateHandleNonce loop stops at 5 because handleNoncesToBlockNums[5] == 0.
   lowerHandleNonce stays at 5.
4. Alice's 1 KAIA is locked in the source bridge indefinitely.
5. No on-chain function exists for Alice to reclaim her funds.
6. _lowerHandleNonceCheck(5) passes (lowerHandleNonce == 5 <= 5), so nonce 5
   could still be handled — but only by the operator who is censoring it.
7. If VTRecovery is disabled (default), there is no automatic retry.
``` [10](#0-9) [11](#0-10)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L113-124)
```text
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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-61)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }

        operators[msg.sender] = true;
        operatorList.push(msg.sender);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L30-34)
```text
    uint64 public requestNonce; // the number of value transfer request that this contract received.
    uint64 public lowerHandleNonce; // a minimum nonce of a value transfer request that will be handled.
    uint64 public upperHandleNonce; // a maximum nonce of the counterpart bridge's value transfer request that is handled.
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
    mapping(uint64 => uint64) public handleNoncesToBlockNums;  // <request nonce> => <request blockNum>
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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L158-160)
```text
    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
    }
```

**File:** node/sc/vt_recovery.go (L90-93)
```go
func (vtr *valueTransferRecovery) Start() error {
	if !vtr.config.VTRecovery {
		return ErrVtrDisabled
	}
```

**File:** node/sc/bridge_manager.go (L40-46)
```go
const (
	TokenEventChanSize  = 10000
	BridgeAddrJournal   = "bridge_addrs.rlp"
	maxPendingNonceDiff = 1000 // TODO-Kaia-ServiceChain: update this limitation. Currently, 2 * 500 TPS.

	maxHandledEventSize = 10000000
)
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
