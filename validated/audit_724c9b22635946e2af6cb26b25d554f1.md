### Title
KLAY Bridge Transfer Permanently Blocked by Reverting Recipient — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` performs all nonce-state updates before the external KAIA transfer. If the recipient `_to` is a contract that reverts on receiving KAIA, the `require(ok, ...)` guard rolls back the entire transaction — including the nonce update — leaving the nonce permanently unhandled. Because there is no skip or emergency-bypass mechanism, the bridge's recovery system loops forever on the stuck nonce, `lowerHandleNonce` never advances, and the bridged KAIA is locked in the contract.

---

### Finding Description

`handleKLAYTransfer` executes in this order:

1. `_lowerHandleNonceCheck(_requestedNonce)` — validates nonce is in window
2. `_voteValueTransfer(_requestedNonce)` — sets `closedValueTransferVotes[nonce] = true`
3. `_setHandledRequestTxHash(_requestTxHash)` — sets `handledRequestTx[hash] = true`
4. `handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber`
5. `_updateHandleNonce(_requestedNonce)` — advances `lowerHandleNonce` if consecutive
6. `emit HandleValueTransfer(...)`
7. `(bool ok, ) = _to.call.value(_value)("");`
8. `require(ok, "handleKLAYTransfer: transfer failed");` [1](#0-0) 

If `_to` is a contract with no payable fallback or a reverting fallback, step 7 returns `ok = false`. Step 8 reverts the entire transaction, rolling back every state mutation from steps 2–5:

- `closedValueTransferVotes[nonce]` → `false` (vote re-opened)
- `handledRequestTx[hash]` → `false`
- `handleNoncesToBlockNums[nonce]` → `0`
- `lowerHandleNonce` → unchanged [2](#0-1) 

Because `handleNoncesToBlockNums[nonce]` stays `0`, the off-chain recovery system's `isHandledEvent` check always returns `false` for this nonce: [3](#0-2) 

The recovery loop in `retrievePendingEventsFrom` therefore keeps including the stuck nonce in `pendingEvents` and operators keep submitting failing `handleKLAYTransfer` transactions indefinitely. [4](#0-3) 

`_updateHandleNonce` advances `lowerHandleNonce` only when consecutive nonces starting from `lowerHandleNonce` are all present in `handleNoncesToBlockNums`. With the stuck nonce permanently absent, `lowerHandleNonce` never moves: [5](#0-4) 

The same structural flaw exists in `handleERC20Transfer` (non-`modeMintBurn` path uses `safeTransfer` which reverts on failure) and `handleERC721Transfer` (`transferFrom` reverts on failure): [6](#0-5) [7](#0-6) 

---

### Impact Explanation

| Asset / State | Corrupted Value |
|---|---|
| KAIA locked in bridge | `_value` KAIA permanently undeliverable to `_to` |
| `lowerHandleNonce` | Stuck at the stuck nonce; never advances |
| `recoveryBlockNumber` | Never advances past the stuck nonce's block |
| `handleNoncesToBlockNums` | Entries for all out-of-order handled nonces accumulate and are never cleaned up (storage bloat) |

The bridge does not completely halt — nonces above the stuck one can still be handled — but `lowerHandleNonce` never advances, the recovery system burns gas in an infinite retry loop, and the KAIA owed to the recipient is permanently locked in the bridge contract.

---

### Likelihood Explanation

Any user on the parent chain can call `requestKLAYTransfer` (or the fallback) with `_to` set to a contract that reverts on receiving KAIA. This requires no special privilege. Contracts that reject KAIA (e.g., contracts with no payable fallback, or contracts that deliberately revert) are common in practice. A single such request is sufficient to trigger the condition permanently. [8](#0-7) 

---

### Recommendation

1. **Pull pattern (preferred)**: Instead of pushing KAIA to `_to` inside `handleKLAYTransfer`, record the pending withdrawal in a mapping (`pendingWithdrawals[_to] += _value`) and let recipients claim via a separate `withdraw()` function. This is the exact fix recommended for the Moloch analog.

2. **Emergency skip**: Add an owner/operator function that can mark a nonce as permanently skipped (setting `handleNoncesToBlockNums[nonce]` to a sentinel value and advancing `lowerHandleNonce`) without performing the transfer, so the bridge can recover from a permanently-reverting recipient.

3. **Soft failure**: Replace `require(ok, ...)` with a conditional that emits a `TransferFailed` event and still commits the nonce as handled, so the bridge advances even when the push fails (accepting that the KAIA stays in the bridge for later manual recovery).

---

### Proof of Concept

```solidity
// Attacker deploys this on the child chain
contract RevertOnReceive {
    receive() external payable { revert("no KAIA"); }
    fallback() external payable { revert("no KAIA"); }
}
```

1. Attacker calls `requestKLAYTransfer(revertOnReceiveAddr, 1 ether, "")` on the **parent** bridge, paying `1 ether + fee`. A `RequestValueTransfer` event is emitted with `requestNonce = N`.

2. Bridge operators observe the event and call `handleKLAYTransfer(..., revertOnReceiveAddr, 1 ether, N, ...)` on the **child** bridge.

3. Inside `handleKLAYTransfer`:
   - Nonce state is updated (steps 2–5 above).
   - `_to.call.value(1 ether)("")` → `ok = false` (recipient reverts).
   - `require(ok, ...)` → entire transaction reverts; all state rolled back.

4. `handleNoncesToBlockNums[N]` remains `0`. `isHandledEvent` returns `false`. Recovery system re-queues nonce `N`.

5. Every subsequent operator attempt to handle nonce `N` fails identically. `lowerHandleNonce` is permanently stuck at `N`. The 1 KAIA is locked in the bridge contract with no delivery path. [9](#0-8) [10](#0-9) [3](#0-2)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L127-134)
```text
    function () external payable {
        _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
    }

    // requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L107-116)
```text
        require(!closedValueTransferVotes[_requestNonce], "closed vote");

        bytes32 voteKey = keccak256(msg.data);
        if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
            closedValueTransferVotes[_requestNonce] = true;
            return true;
        }

        return false;
    }
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

**File:** node/sc/vt_recovery.go (L307-321)
```go
		for reqVTevIt.Next() {
			logger.Trace("pending nonce in the RequestValueTransfer event", "requestNonce", reqVTevIt.Event.RequestNonce)
			if reqVTevIt.Event.RequestNonce >= hint.handleNonce {
				// Check if the event is already handled in target bridge contract
				if isHandledEvent(to, RequestValueTransferEvent{reqVTevIt.Event}) {
					continue
				}
				logger.Trace("filtered pending nonce", "requestNonce", reqVTevIt.Event.RequestNonce, "handledNonce", hint.handleNonce)
				pendingEvents = append(pendingEvents, RequestValueTransferEvent{reqVTevIt.Event})
				if len(pendingEvents) >= maxPendingTxs {
					reqVTevIt.Close()
					break pendingTxLoop
				}
			}
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```
