### Title
Push-Payment Pattern in `handleKLAYTransfer` Permanently Locks Bridged KAIA When Recipient Contract Rejects KLAY — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in the Kaia service-chain bridge uses a push-payment pattern to deliver KAIA to the recipient `_to`. If `_to` is a contract that reverts on receiving KAIA (no payable fallback, or an explicit revert), the `require(ok, ...)` guard causes the entire transaction to revert. Because `_to` is fixed by the original source-chain request event and operators cannot alter it, the KAIA is permanently locked in the destination bridge (or burned on the source chain in mint/burn mode), with no on-chain recovery path.

---

### Finding Description

In `handleKLAYTransfer`, the execution order is:

1. `_lowerHandleNonceCheck` — validates nonce
2. `_voteValueTransfer` — sets `closedValueTransferVotes[nonce] = true`
3. `_setHandledRequestTxHash` — marks `handledRequestTx[txHash] = true`
4. `handleNoncesToBlockNums[nonce] = blockNumber`
5. `_updateHandleNonce` — advances `lowerHandleNonce`, `upperHandleNonce`, `recoveryBlockNumber`
6. `emit HandleValueTransfer`
7. `(bool ok, ) = _to.call.value(_value)("")` — push KAIA to recipient
8. `require(ok, "handleKLAYTransfer: transfer failed")` — **reverts entire tx if push fails** [1](#0-0) 

Because Solidity reverts all state changes on `require` failure, steps 2–5 are all rolled back. The nonce is never consumed, the vote is never closed, and the tx hash is never marked handled. Operators will retry, but if `_to` always reverts on KAIA receipt, every retry fails identically.

The `_to` address is sourced directly from the original `RequestValueTransfer` event on the counterpart chain: [2](#0-1) 

Operators relay the exact parameters from the source-chain event; they cannot substitute a different `_to`. There is no `withdraw` or `rescue` function in the bridge contract to recover stuck KAIA.

The `_voteValueTransfer` function sets `closedValueTransferVotes[nonce] = true` before the push, but since the whole transaction reverts on push failure, this flag is also rolled back, leaving the nonce permanently retryable but permanently failing: [3](#0-2) 

The `_updateHandleNonce` loop advances `lowerHandleNonce` only through consecutive handled nonces. A permanently-failing nonce N causes `lowerHandleNonce` to stall at N, and `recoveryBlockNumber` never advances past the block of nonce N−1, causing the off-chain bridge manager to re-scan from that block indefinitely: [4](#0-3) 

---

### Impact Explanation

Bridged KAIA assets are permanently lost:

- **Lock/unlock mode**: KAIA is locked in the source bridge and can never be delivered to `_to` on the destination chain.
- **Mint/burn mode**: KAIA is burned on the source chain and can never be minted on the destination chain.

There is no on-chain recovery function. The bridge contract has no `rescueKLAY` or pull-withdrawal mechanism.

---

### Likelihood Explanation

Two realistic triggers exist:

1. **Accidental**: A user bridges KAIA to a smart contract address on the destination chain that has no `payable` fallback (a common Solidity pattern). The bridge silently locks their funds forever.

2. **Adversarial**: An attacker who controls `_to` (e.g., a proxy contract) upgrades it to revert on KAIA receipt after the source-chain request is already committed. The sender's KAIA is permanently lost; the attacker sacrifices their own receipt to grief the sender. This is the direct analog of the H-4 Cooler lender-blacklist attack: the recipient is the attacker.

---

### Recommendation

Replace the push-payment pattern with a pull-payment pattern:

```solidity
mapping(address => uint256) public pendingWithdrawals;

// In handleKLAYTransfer, replace lines 98-99 with:
pendingWithdrawals[_to] = pendingWithdrawals[_to].add(_value);

// Add a new function:
function withdraw() external nonReentrant {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "nothing to withdraw");
    pendingWithdrawals[msg.sender] = 0;
    (bool ok, ) = msg.sender.call.value(amount)("");
    require(ok, "withdraw: transfer failed");
}
```

This ensures that a recipient's inability to receive KAIA does not permanently lock bridged assets; the recipient can withdraw at any time, and the bridge's nonce state is always correctly advanced.

---

### Proof of Concept

```solidity
// Attacker contract: reverts on receiving KAIA
contract KAIARejecter {
    function() external payable { revert("no KAIA"); }
}
```

1. Deploy `KAIARejecter` on the destination chain at address `R`.
2. User calls `requestKLAYTransfer(R, value, extraData)` on the source bridge, locking `value` KAIA.
3. Operators observe the `RequestValueTransfer` event and call `handleKLAYTransfer(txHash, user, R, value, nonce, blockNum, extraData)` on the destination bridge.
4. Steps 2–5 of `handleKLAYTransfer` execute and commit state.
5. `R.call.value(value)("")` returns `ok = false` (revert from `KAIARejecter`).
6. `require(ok, "handleKLAYTransfer: transfer failed")` reverts the entire transaction; all state is rolled back.
7. Operators retry indefinitely; every attempt reverts identically.
8. `value` KAIA is permanently locked in the source bridge (or burned in mint/burn mode). `lowerHandleNonce` stalls at `nonce`. No recovery is possible on-chain. [5](#0-4)

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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L139-156)
```text
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
