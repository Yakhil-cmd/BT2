### Title
Malicious KAIA Recipient Can Permanently Freeze Bridge Funds via Reverting Fallback — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` makes a low-level external call to the user-controlled `_to` address after committing all nonce-state updates. If `_to` is a contract whose fallback reverts, the entire transaction reverts, rolling back the nonce state. Because the bridge has no skip or refund mechanism, the corresponding KAIA locked on the source chain is permanently frozen and `lowerHandleNonce` is stuck, breaking the value-transfer recovery system for all subsequent nonces.

---

### Finding Description

In `handleKLAYTransfer`:

```solidity
// BridgeTransferKLAY.sol lines 81-99
_setHandledRequestTxHash(_requestTxHash);
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);          // advances lowerHandleNonce

emit HandleValueTransfer(...);

(bool ok, ) = _to.call.value(_value)("");     // external call to user-controlled address
require(ok, "handleKLAYTransfer: transfer failed");  // reverts entire tx if _to reverts
``` [1](#0-0) 

Because `require(ok, ...)` reverts the entire transaction, all state changes on lines 81–84 are rolled back. The nonce is never marked handled. The bridge operators cannot advance past this nonce because `_to` will always revert.

The `_to` address originates from the user's `requestKLAYTransfer` call on the source chain:

```solidity
// BridgeTransferKLAY.sol lines 132-134
function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
    uint256 feeLimit = msg.value.sub(_value);
    _requestKLAYTransfer(_to, feeLimit, _extraData);
``` [2](#0-1) 

Bridge operators relay `_to` faithfully from the `RequestValueTransfer` event to `handleKLAYTransfer`; they cannot substitute a different recipient. [3](#0-2) 

The `lowerHandleNonce` advancement logic in `_updateHandleNonce` requires consecutive nonces starting from `lowerHandleNonce` to have non-zero `handleNoncesToBlockNums` entries. A permanently unprocessable nonce N keeps `lowerHandleNonce` pinned at N forever:

```solidity
// BridgeTransfer.sol lines 149-155
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    delete handleNoncesToBlockNums[i];
    delete closedValueTransferVotes[i];
}
lowerHandleNonce = i;
``` [4](#0-3) 

---

### Impact Explanation

1. **Permanent KAIA freeze**: The KAIA deposited by the user into the source-chain bridge is locked with no refund path. The destination-chain bridge's KAIA is also never disbursed. Both pools are permanently reduced.
2. **Recovery system DoS**: `lowerHandleNonce` and `recoveryBlockNumber` are stuck at the blocked nonce. The off-chain `ValueTransferRecovery` module (`vt_recovery.go`) will loop indefinitely retrying the failing nonce, wasting operator gas and preventing clean recovery-hint advancement for all subsequent nonces. [5](#0-4) 

---

### Likelihood Explanation

Any unprivileged user can trigger this by deploying a contract with a reverting fallback and using it as `_to` in `requestKLAYTransfer`. No special role or key is required. The attacker sacrifices their own bridged KAIA, making this a low-cost griefing vector against the bridge's recovery infrastructure.

---

### Recommendation

Replace the push-payment pattern with a pull-payment (withdrawal) pattern, exactly as the Augur C07 fix did:

```solidity
mapping(address => uint256) public pendingWithdrawals;

function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    // ... nonce checks and state updates ...
    pendingWithdrawals[_to] += _value;   // record; do NOT call _to
}

function withdraw() external nonReentrant {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0);
    pendingWithdrawals[msg.sender] = 0;
    (bool ok, ) = msg.sender.call.value(amount)("");
    require(ok);
}
```

This ensures a reverting recipient cannot block the bridge's nonce progression or freeze funds.

---

### Proof of Concept

```solidity
// Malicious recipient
contract MaliciousReceiver {
    fallback() external payable { revert("blocked"); }
}

// Attack steps:
// 1. Deploy MaliciousReceiver on destination chain
// 2. On source chain: bridge.requestKLAYTransfer{value: 1 ether}(
//        address(maliciousReceiver), 1 ether, "");
//    → source bridge now holds 1 KAIA, emits RequestValueTransfer(nonce=N)
// 3. Bridge operators call handleKLAYTransfer(..., maliciousReceiver, 1e18, N, ...)
//    → _to.call.value(1e18)("") → MaliciousReceiver.fallback() reverts
//    → require(ok) reverts entire tx; all state rolled back
//    → lowerHandleNonce stays at N; 1 KAIA permanently locked in source bridge
// 4. Every retry by operators or recovery system produces the same revert.
//    recoveryBlockNumber is stuck; recovery loop spins on nonce N indefinitely.
``` [6](#0-5) [7](#0-6)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-134)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
```

**File:** node/sc/bridge_manager.go (L331-337)
```go
	switch tokenType {
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
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

**File:** node/sc/vt_recovery.go (L201-238)
```go
// updateRecoveryHint updates a hint for the one-way value transfers.
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

**File:** contracts/service_chain/bridge/BridgeFee.sol (L43-66)
```text
    function _payKLAYFeeAndRefundChange(uint256 _feeLimit) internal returns(uint256) {
        uint256 fee = feeOfKLAY;

        if (feeReceiver != address(0) && fee > 0) {
            require(_feeLimit >= fee, "insufficient feeLimit");

            (bool ok, ) = feeReceiver.call.value(fee)("");
            require(ok, "transfer fee failed");

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                (bool ok, ) = msg.sender.call.value(feeRefund)("");
                require(ok, "refund fee failed");
            }

            return fee;
        }

        if (_feeLimit > 0) {
            (bool ok, ) = msg.sender.call.value(_feeLimit)("");
            require(ok, "refund fee failed");
        }
        return 0;
    }
```
