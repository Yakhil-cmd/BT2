### Title
Reverting Fallback in `_to` Permanently Locks Bridged KAIA and Corrupts `lowerHandleNonce`/`recoveryBlockNumber` — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` pushes KAIA to a user-controlled `_to` address via a low-level call. If `_to` is a contract whose fallback reverts, the `require(ok, ...)` guard causes the entire transaction to revert. Because all state mutations — including `handleNoncesToBlockNums[_requestedNonce]`, `_updateHandleNonce`, and `_setHandledRequestTxHash` — are written **before** the push, every retry by bridge operators also reverts. The KAIA is permanently locked in the bridge, and `lowerHandleNonce` / `recoveryBlockNumber` are permanently frozen at the stuck nonce, corrupting the bridge's recovery accounting.

---

### Finding Description

In `handleKLAYTransfer`:

```solidity
// contracts/service_chain/bridge/BridgeTransferKLAY.sol  lines 75–99
_lowerHandleNonceCheck(_requestedNonce);
if (!_voteValueTransfer(_requestedNonce)) { return; }

_setHandledRequestTxHash(_requestTxHash);
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);

emit HandleValueTransfer(...);

(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");   // ← revert rolls back everything above
```

The state writes at lines 81–84 are placed **before** the external call at line 98. When `_to.call.value(_value)("")` returns `false` (reverting fallback), `require(ok, ...)` reverts the whole transaction, undoing those writes. `handleNoncesToBlockNums[_requestedNonce]` is therefore never durably set to a non-zero value.

`_updateHandleNonce` advances `lowerHandleNonce` by scanning consecutive nonces:

```solidity
// BridgeTransfer.sol  lines 149–155
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    ...
}
lowerHandleNonce = i;
```

Because `handleNoncesToBlockNums[N]` is never written (every attempt reverts), the loop stops immediately at nonce N. `lowerHandleNonce` and `recoveryBlockNumber` are permanently frozen.

The Go-level recovery reads `RecoveryBlockNumber()` to determine the scan start block:

```go
// node/sc/vt_recovery.go  line 211
hint.blockNumber, err = to.bridge.RecoveryBlockNumber(nil)
```

With `recoveryBlockNumber` frozen, `checkRecoveryCondition` perpetually detects `requestNonce != handleNonce && prevHandleNonce == handleNonce` and keeps triggering recovery, but can never resolve nonce N.

---

### Impact Explanation

1. **Bridged KAIA permanently locked.** The KAIA deposited on the source chain for nonce N is held in the bridge contract and can never be delivered or refunded. There is no admin escape hatch in the non-upgradeable bridge contract.

2. **`lowerHandleNonce` permanently frozen.** `_updateHandleNonce` cannot advance past nonce N. `closedValueTransferVotes` entries for all subsequent nonces accumulate and are never deleted (storage leak).

3. **`recoveryBlockNumber` permanently frozen.** The bridge recovery daemon (`valueTransferRecovery`) uses this value as its log-scan start point. It will re-scan from the same old block on every recovery cycle, causing unbounded redundant RPC work and preventing the recovery hint from ever converging.

4. **Other users' transfers are not blocked** (because `_lowerHandleNonceCheck` only requires `lowerHandleNonce <= _requestedNonce`), but the recovery subsystem is permanently degraded for the entire bridge pair.

---

### Likelihood Explanation

Any user who calls `requestKLAYTransfer` on the source chain and specifies a contract address as `_to` whose fallback reverts — whether intentionally (griefing their own funds) or accidentally (e.g., a multisig or smart-contract wallet that does not accept plain KAIA) — triggers this condition. No special privilege is required; the standard public `requestKLAYTransfer` entry point is sufficient.

---

### Recommendation

Replace the "push" with a "pull" (claimable balance) pattern, analogous to the mitigation applied in the referenced report:

```diff
-   (bool ok, ) = _to.call.value(_value)("");
-   require(ok, "handleKLAYTransfer: transfer failed");
+   pendingWithdrawals[_to] += _value;
```

Add a separate `withdrawKLAY()` function that lets `_to` pull their balance. This decouples the bridge's nonce accounting from the recipient's ability to accept KAIA, ensuring that a reverting fallback can never block the bridge state machine.

Alternatively, if the push must be retained, wrap it without `require` and emit a `TransferFailed` event so operators can take manual remediation action without corrupting `lowerHandleNonce`.

---

### Proof of Concept

1. Deploy a malicious contract on the service chain:

```solidity
contract RevertOnReceive {
    receive() external payable { revert("no KAIA"); }
}
```

2. On the source chain, call:

```solidity
bridge.requestKLAYTransfer{value: 1 ether}(address(revertOnReceive), 1 ether, "");
// emits RequestValueTransfer with requestNonce = N
```

3. Bridge operator calls `handleKLAYTransfer` on the destination chain with `_to = address(revertOnReceive)`. The transaction reverts with `"handleKLAYTransfer: transfer failed"` every time.

4. Verify state is frozen:

```solidity
assert(bridge.lowerHandleNonce() == N);          // stuck
assert(bridge.recoveryBlockNumber() == oldBlock); // stuck
// 1 ether is locked in bridge, unreachable
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** node/sc/vt_recovery.go (L202-238)
```go
func updateRecoveryHintFromTo(prevHint *valueTransferHint, from, to *BridgeInfo) (*valueTransferHint, error) {
	var err error
	var hint valueTransferHint

	logger.Trace("updateRecoveryHintFromTo start")
	if prevHint != nil {
		logger.Trace("recovery prevHint", "rnonce", prevHint.requestNonce, "hnonce", prevHint.handleNonce, "phnonce", prevHint.prevHandleNonce, "cand", prevHint.candidate)
	}

	hint.blockNumber, err = to.bridge.RecoveryBlockNumber(nil)
	if err != nil {
		return nil, err
	}

	requestNonce, err := from.bridge.RequestNonce(nil)
	if err != nil {
		return nil, err
	}
	from.SetRequestNonce(requestNonce)
	to.SetRequestNonceFromCounterpart(requestNonce)
	hint.requestNonce = requestNonce

	handleNonce, err := to.bridge.LowerHandleNonce(nil)
	if err != nil {
		return nil, err
	}
	to.UpdateLowerHandleNonce(handleNonce)

	if prevHint != nil {
		hint.prevHandleNonce = prevHint.handleNonce
		hint.candidate = prevHint.candidate
	}
	hint.handleNonce = handleNonce

	logger.Trace("updateRecoveryHintFromTo finish", "rnonce", hint.requestNonce, "hnonce", hint.handleNonce, "phnonce", hint.prevHandleNonce, "cand", hint.candidate)

	return &hint, nil
```

**File:** node/sc/vt_recovery.go (L363-379)
```go
func checkRecoveryCandidateCondition(hint *valueTransferHint) bool {
	return hint.requestNonce != hint.handleNonce && hint.prevHandleNonce == hint.handleNonce
}

// checkRecoveryCondition checks if recovery for the handle value transfers is needed or not.
func checkRecoveryCondition(hint *valueTransferHint) bool {
	if checkRecoveryCandidateCondition(hint) && hint.candidate {
		hint.candidate = false
		return true
	}
	if checkRecoveryCandidateCondition(hint) && !hint.candidate {
		hint.candidate = true
		return false
	}
	hint.candidate = false
	return false
}
```
