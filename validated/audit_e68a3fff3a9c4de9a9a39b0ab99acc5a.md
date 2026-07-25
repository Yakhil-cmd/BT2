### Title
Service-Chain Bridge `closedValueTransferVotes` Keyed Only by `requestNonce` Allows Reorg to Permanently Lock Bridged Assets — (`contracts/service_chain/bridge/BridgeOperator.sol`, `contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

The Kaia service-chain bridge uses a monotonically incrementing `requestNonce` as the sole key for `closedValueTransferVotes`. After a source-chain reorg, a different transfer can be assigned the same nonce that was already consumed by a pre-reorg transfer. The destination bridge permanently rejects the post-reorg transfer with "closed vote," locking the user's bridged assets forever.

---

### Finding Description

When a user calls `requestKLAYTransfer` / `requestERC20Transfer` / `requestERC721Transfer` on the source bridge, the contract emits a `RequestValueTransfer` event carrying the current `requestNonce` and increments it: [1](#0-0) 

The bridge operator (`SubBridge`) watches these events and submits a corresponding `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` call to the destination bridge. The destination bridge's execution guard is: [2](#0-1) 

`closedValueTransferVotes` is a `mapping(uint64 => bool)` keyed **only** by `_requestNonce`: [3](#0-2) 

Once a nonce is closed, the check `require(!closedValueTransferVotes[_requestNonce], "closed vote")` fires unconditionally for any future call with that nonce, regardless of `_requestTxHash` or any other parameter.

The `handledRequestTx` mapping exists but provides **no protection** — it is written after voting succeeds and is never read as a guard: [4](#0-3) 

The bridge operator event loop does **not** check `ev.Raw.Removed` before forwarding events for processing: [5](#0-4) 

The `ProcessRequestEvent` path also performs no `Removed` check: [6](#0-5) 

The value-transfer recovery (`VTR`) system cannot rescue the stuck transfer either. `isHandledEvent` checks `HandleNoncesToBlockNums` for the nonce: [7](#0-6) 

After `_updateHandleNonce` advances `lowerHandleNonce` past the affected nonce, both `handleNoncesToBlockNums[nonce]` and `closedValueTransferVotes[nonce]` are deleted: [8](#0-7) 

At that point VTR would re-attempt the handle call, but `_lowerHandleNonceCheck` would then reject it with "removed vote" because `lowerHandleNonce > nonce`: [9](#0-8) 

---

### Impact Explanation

A user whose transfer is assigned a nonce that was already consumed by a pre-reorg transfer loses their bridged assets permanently:

- **KLAY**: locked in source bridge, never released on destination.
- **ERC20**: burned (in mint-burn mode) or locked in source bridge, never minted/released on destination.
- **ERC721**: burned or locked in source bridge, never minted/transferred on destination.

This satisfies the allowed impact gate: *unauthorized failure to unlock/mint bridged assets affecting KAIA and bridged tokens*.

---

### Likelihood Explanation

Kaia mainnet and service chains use Istanbul BFT, which provides single-block finality under normal conditions, making reorgs rare. However:

1. The code explicitly implements a `reorg` path in `blockchain.go`.
2. Network partitions or non-BFT parent chains (e.g., Ethereum as a parent) can produce reorgs.
3. The bridge operator code has no `log.Removed` guard, so any reorg that does occur is silently mishandled.

Likelihood is **Low**, matching the external report's assessment.

---

### Recommendation

1. **Add a `require(!handledRequestTx[_requestTxHash])` guard** at the top of each `handleXXXTransfer` function, before the nonce vote, so that a pre-reorg handle cannot block a post-reorg handle with a different `_requestTxHash`.

2. **Key `closedValueTransferVotes` by `keccak256(nonce, requestTxHash)`** instead of nonce alone, so that closing a vote for one (nonce, txHash) pair does not block a different (nonce, txHash) pair.

3. **Check `ev.Raw.Removed`** in the bridge operator event loop and discard removed logs rather than forwarding them for processing.

---

### Proof of Concept

**Setup**: Single operator, threshold = 1, source bridge on chain A, destination bridge on chain B.

1. Alice calls `requestKLAYTransfer` on chain A. Source bridge emits `RequestValueTransfer(nonce=5, from=Alice, to=Alice_dest, value=100)`, `txHash = 0xABC`.
2. Bridge operator receives the event and calls `handleKLAYTransfer(0xABC, Alice, Alice_dest, 100, 5, blockNum, ...)` on chain B.
3. Destination bridge executes: `closedValueTransferVotes[5] = true`, `handledRequestTx[0xABC] = true`, Alice receives 100 KLAY on chain B.
4. Chain A reorgs. Alice's transaction is dropped. Bob's transaction now occupies the same block position: `requestNonce=5`, `txHash=0xDEF`, `value=200`, `to=Bob_dest`.
5. Bridge operator (no `Removed` check) receives Bob's event and calls `handleKLAYTransfer(0xDEF, Bob, Bob_dest, 200, 5, blockNum, ...)` on chain B.
6. Destination bridge: `_lowerHandleNonceCheck(5)` passes → `_voteValueTransfer(5)` → `require(!closedValueTransferVotes[5])` → **REVERTS** with "closed vote".
7. Bob's 200 KLAY is permanently locked in the source bridge. No recovery path exists.

**Corrupted state**: `closedValueTransferVotes[5] = true` on the destination bridge, corresponding to a source transaction (`0xABC`) that no longer exists on the canonical source chain. Bob's canonical transfer (`0xDEF`, nonce 5) can never be executed. [10](#0-9) [2](#0-1)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L113-123)
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
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L35-35)
```text
    mapping(uint64 => bool) public closedValueTransferVotes; // <nonce, bool>
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L103-116)
```text
    function _voteValueTransfer(uint64 _requestNonce)
        internal
        returns(bool)
    {
        require(!closedValueTransferVotes[_requestNonce], "closed vote");

        bytes32 voteKey = keccak256(msg.data);
        if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
            closedValueTransferVotes[_requestNonce] = true;
            return true;
        }

        return false;
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

**File:** node/sc/bridge_manager.go (L1104-1113)
```go
	for {
		select {
		case <-bi.closed:
			return
		case ev := <-chanReqVT:
			bm.reqVTevFeeder.Send(RequestValueTransferEvent{ev})
		case ev := <-chanReqVTencoded:
			bm.reqVTevEncodedFeeder.Send(RequestValueTransferEncodedEvent{ev})
		case ev := <-chanHandleVT:
			bm.handleEventFeeder.Send(&HandleValueTransferEvent{ev})
```

**File:** node/sc/sub_event_handler.go (L71-86)
```go
func (cce *ChildChainEventHandler) ProcessRequestEvent(ev IRequestValueTransferEvent) error {
	addr := ev.GetRaw().Address

	handleBridgeAddr := cce.subbridge.bridgeManager.GetCounterPartBridgeAddr(addr)
	if handleBridgeAddr == (common.Address{}) {
		return fmt.Errorf("there is no counter part bridge of the bridge(%v)", addr.String())
	}

	handleBridgeInfo, ok := cce.subbridge.bridgeManager.GetBridgeInfo(handleBridgeAddr)
	if !ok {
		return fmt.Errorf("there is no counter part bridge info(%v) of the bridge(%v)", handleBridgeAddr.String(), addr.String())
	}

	// TODO-Kaia need to manage the size limitation of pending event list.
	handleBridgeInfo.AddRequestValueTransferEvents([]IRequestValueTransferEvent{ev})
	return nil
```

**File:** node/sc/vt_recovery.go (L64-71)
```go
func isHandledEvent(to *BridgeInfo, ev IRequestValueTransferEvent) bool {
	blk, err := to.bridge.HandleNoncesToBlockNums(nil, ev.GetRequestNonce())
	if err == nil && blk > 0 {
		logger.Trace("skip handled event", "nonce", ev.GetRequestNonce())
		return true
	}
	return false
}
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L149-155)
```text
        uint64 i;
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L158-160)
```text
    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
    }
```
