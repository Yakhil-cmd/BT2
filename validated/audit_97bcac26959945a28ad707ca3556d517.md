### Title
Unvalidated `_to` Recipient in Bridge Value Transfer Requests Causes Permanent Asset Lock and Handle-Nonce Freeze — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

Any user can call `requestERC20Transfer` or `requestKLAYTransfer` on the source-chain bridge, specifying an arbitrary `_to` address as the recipient on the destination chain. The source bridge takes tokens/KLAY from `msg.sender` and emits a `RequestValueTransfer` event, but performs no validation of `_to`. If `_to` is a blacklisted address in the bridged ERC20 token (or a non-payable/reverting contract for KLAY), every operator attempt to call `handleERC20Transfer` / `handleKLAYTransfer` on the destination chain will revert. Because the entire handle transaction reverts, `handleNoncesToBlockNums[N]` is never written, `lowerHandleNonce` is permanently frozen at nonce N, and there is no cancel or refund path. The user's assets are permanently locked in the source bridge contract.

---

### Finding Description

**Source-side request — no `_to` validation**

`requestERC20Transfer` pulls tokens from `msg.sender` and records `_to` as the destination-chain recipient without any check: [1](#0-0) 

`requestKLAYTransfer` has the same pattern — KLAY is taken from `msg.value`, `_to` is unchecked: [2](#0-1) 

**Destination-side handle — transfer to `_to` is the last step, after nonce accounting, but inside the same transaction**

In `handleERC20Transfer`, the nonce is recorded and `_updateHandleNonce` is called *before* the actual token transfer, but all of it is inside one transaction: [3](#0-2) 

If `_to` is blacklisted in the ERC20 token, `safeTransfer` reverts, rolling back `handleNoncesToBlockNums[_requestedNonce]`, the vote, and the nonce update entirely.

For KLAY, the same pattern applies — the low-level call to `_to` is the last step and a revert rolls back everything: [4](#0-3) 

**`lowerHandleNonce` is permanently frozen**

`_updateHandleNonce` advances `lowerHandleNonce` only while consecutive nonces starting from `lowerHandleNonce` have `handleNoncesToBlockNums[i] > 0`. Because nonce N's entry is always rolled back, the loop stops at N on every future call: [5](#0-4) 

All subsequent handled nonces (N+1, N+2, …) write their entries to `handleNoncesToBlockNums` but those entries are never deleted, causing unbounded storage growth. `recoveryBlockNumber` is also frozen at the block before nonce N.

**No cancel or refund mechanism exists.** The source bridge holds the user's tokens/KLAY with no escape path once the request is emitted.

---

### Impact Explanation

- **Permanent asset lock**: The user's ERC20 tokens or KLAY deposited into the source bridge for nonce N can never be delivered or refunded. They are irrecoverably locked in the source bridge contract.
- **`lowerHandleNonce` freeze**: The bridge's sequential nonce invariant is broken. `lowerHandleNonce` never advances past N, so `recoveryBlockNumber` is frozen and the VT recovery subsystem (`vt_recovery.go`) enters a permanent retry loop re-submitting the failing nonce, wasting operator gas indefinitely.
- **Unbounded storage leak**: Every successfully handled nonce above N writes to `handleNoncesToBlockNums` but is never cleaned up, growing contract storage without bound. [6](#0-5) 

---

### Likelihood Explanation

- **Unprivileged trigger**: Any user with a small amount of the bridged token (or KLAY) can call `requestERC20Transfer` / `requestKLAYTransfer`. No special role is required.
- **Realistic `_to` values**: A non-payable contract address (for KLAY) or a USDC/USDT-style blacklisted address (for ERC20) is sufficient. Both are easily obtainable on public networks.
- **No existing guard**: Neither `requestERC20Transfer` nor `requestKLAYTransfer` validates `_to`. There is no allowlist, no reachability check, and no cancel path.
- **Self-funded attack**: The attacker sacrifices only the minimum transfer amount (plus fee) to permanently freeze the bridge's nonce accounting.

---

### Recommendation

1. **Validate `_to` reachability at request time** where possible (e.g., reject the zero address, reject known non-payable contract addresses for KLAY).
2. **Add a skip/cancel mechanism for stuck nonces**: Allow the bridge owner or a quorum of operators to mark a nonce as "skipped" (writing a sentinel value to `handleNoncesToBlockNums[N]`) so `lowerHandleNonce` can advance past it and the locked assets can be refunded to the original `msg.sender` recorded in the `RequestValueTransfer` event.
3. **Separate the nonce-accounting commit from the asset transfer**: Record `handleNoncesToBlockNums[N]` in a separate transaction or use a two-phase pattern so a failed delivery does not roll back the nonce record.

---

### Proof of Concept

1. Deploy source and destination bridge contracts (ERC20 mode, non-mint-burn).
2. Obtain the address of a contract with no payable fallback (for KLAY) or a blacklisted address in the bridged ERC20 token.
3. Call `requestERC20Transfer(tokenAddress, blacklistedAddress, amount, feeLimit, "")` on the source bridge. Tokens are pulled from `msg.sender`; `RequestValueTransfer` is emitted with nonce N.
4. Operators call `handleERC20Transfer(..., blacklistedAddress, ..., N, ...)` on the destination bridge. `safeTransfer` reverts → entire transaction reverts → `handleNoncesToBlockNums[N]` remains 0.
5. Repeat step 4 any number of times — it always reverts.
6. Call `handleERC20Transfer` for nonce N+1 with a valid recipient. It succeeds, but `_updateHandleNonce(N+1)` loops from `lowerHandleNonce = N`, finds `handleNoncesToBlockNums[N] == 0`, stops immediately, and sets `lowerHandleNonce = N` (unchanged). The N+1 entry is written but never deleted.
7. Observe: `lowerHandleNonce` is permanently N; `recoveryBlockNumber` is frozen; the user's tokens for nonce N are irrecoverably locked in the source bridge. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L124-135)
```text
    function requestERC20Transfer(
        address _tokenAddress,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        public
    {
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
    }
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-135)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
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

**File:** node/sc/vt_recovery.go (L381-412)
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
```
