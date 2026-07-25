### Title
Unvalidated `_requestedBlockNumber` in Bridge Handle Functions Corrupts `recoveryBlockNumber`, Permanently Disabling VTR Asset Recovery — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

`handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` accept a caller-supplied `_requestedBlockNumber` that is stored verbatim into `handleNoncesToBlockNums` and then propagated to the on-chain `recoveryBlockNumber` state variable. No check is ever made against the actual block number of the source-chain `RequestValueTransfer` event. With the default operator threshold of 1, any single registered operator can supply an arbitrarily large future block number, permanently advancing `recoveryBlockNumber` beyond the current chain tip. The off-chain Value Transfer Recovery (VTR) system reads `recoveryBlockNumber` as its scan start point; once it exceeds the current block height, the scan loop never executes and all pending bridge transfers are silently abandoned, causing permanent loss of bridged KLAY/ERC20/ERC721 assets.

---

### Finding Description

**Root cause — no on-chain validation of `_requestedBlockNumber`:**

In all three handle functions the pattern is identical:

```solidity
// BridgeTransferKLAY.sol
function handleKLAYTransfer(
    bytes32 _requestTxHash,
    address _from,
    address payable _to,
    uint256 _value,
    uint64 _requestedNonce,
    uint64 _requestedBlockNumber,   // ← fully caller-controlled
    bytes memory _extraData
) public onlyOperators nonReentrant {
    _lowerHandleNonceCheck(_requestedNonce);
    if (!_voteValueTransfer(_requestedNonce)) { return; }
    _setHandledRequestTxHash(_requestTxHash);
    handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber; // ← stored without any check
    _updateHandleNonce(_requestedNonce);
    ...
}
``` [1](#0-0) 

`_updateHandleNonce` then sweeps consecutive entries and writes each stored block number into `recoveryBlockNumber`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];   // ← poisoned value lands here
    delete handleNoncesToBlockNums[i];
    ...
}
lowerHandleNonce = i;
``` [2](#0-1) 

The same unvalidated assignment exists in `BridgeTransferERC20.sol` and `BridgeTransferERC721.sol`: [3](#0-2) [4](#0-3) 

**Default threshold is 1 — a single operator suffices:**

`BridgeOperator`'s constructor initialises every vote type to threshold 1:

```solidity
constructor() internal {
    for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
        operatorThresholds[uint8(i)] = 1;
    }
    operators[msg.sender] = true;
    ...
}
``` [5](#0-4) 

With threshold 1, `_voteValueTransfer` returns `true` on the very first call, so the single operator's `_requestedBlockNumber` is immediately committed.

**VTR uses `recoveryBlockNumber` as its scan start — poisoning it silences recovery:**

`updateRecoveryHintFromTo` reads `RecoveryBlockNumber()` from the destination bridge and stores it as `hint.blockNumber`:

```go
hint.blockNumber, err = to.bridge.RecoveryBlockNumber(nil)
``` [6](#0-5) 

`retrievePendingEventsFrom` then uses that value as `startBlkNum`:

```go
startBlkNum := hint.blockNumber
endBlkNum   := startBlkNum + filterLogsStride

for startBlkNum <= curBlkNum {   // ← never entered if startBlkNum > curBlkNum
    ...
    reqVTevIt, _ = from.bridge.FilterRequestValueTransfer(opts, ...)
    ...
}
``` [7](#0-6) 

If `recoveryBlockNumber` has been set to any value beyond the current chain tip, the loop body is never reached, `pendingEvents` stays empty, and `recoverPendingEvents` has nothing to resubmit.

---

### Impact Explanation

`recoveryBlockNumber` is the **only** mechanism by which the bridge re-discovers `RequestValueTransfer` events that were missed by the real-time subscription (e.g., due to node restarts, network partitions, or reorgs). Once it is advanced past the current block height:

- All in-flight user deposits whose `RequestValueTransfer` events predate the poisoned block number are permanently invisible to VTR.
- The corresponding KLAY/ERC20/ERC721 assets locked in the source bridge contract can never be released on the destination chain.
- The corruption is persistent: `recoveryBlockNumber` is only ever updated forward (to the block number of the next consecutive handled nonce), so it cannot self-heal.

This constitutes **permanent loss of bridged assets** — an allowed impact under the contest scope.

---

### Likelihood Explanation

- The default operator threshold is 1, so **any single registered operator** can trigger this with one transaction.
- The operator does not need to forge signatures, compromise keys, or collude with other operators.
- The malicious call is indistinguishable from a legitimate `handleKLAYTransfer` call at the contract level; no event or revert signals the anomaly.
- The VTR failure is silent — the system logs nothing when the scan loop is skipped because `startBlkNum > curBlkNum`.

---

### Recommendation

1. **On-chain bound check**: In each handle function, require that `_requestedBlockNumber` does not exceed the current block number (or a small tolerance):
   ```solidity
   require(_requestedBlockNumber <= block.number, "future block number");
   ```
2. **Include block number in the vote key**: The vote key `keccak256(msg.data)` already covers `_requestedBlockNumber`, so with threshold > 1 operators must agree on the same value. Enforce threshold ≥ 2 in production deployments and document that `_requestedBlockNumber` is security-critical.
3. **Monotonicity guard**: Require `_requestedBlockNumber >= recoveryBlockNumber` so that `recoveryBlockNumber` can only advance, never jump to an arbitrary future value.

---

### Proof of Concept

1. Deploy `Bridge` (lock mode) with default threshold 1; register one operator `OP`.
2. User calls `requestKLAYTransfer` on the source bridge at block 500, emitting `RequestValueTransfer(nonce=0, ...)`. The real-time subscription is offline.
3. `OP` calls:
   ```solidity
   bridge.handleKLAYTransfer(
       txHash, from, to, value,
       /*_requestedNonce=*/ 0,
       /*_requestedBlockNumber=*/ type(uint64).max,  // ← poisoned
       ""
   );
   ``` [8](#0-7) 
4. `_updateHandleNonce(0)` runs; `handleNoncesToBlockNums[0] = type(uint64).max`; `recoveryBlockNumber = type(uint64).max`; `lowerHandleNonce = 1`. [9](#0-8) 
5. VTR fires. `updateRecoveryHintFromTo` reads `recoveryBlockNumber = type(uint64).max` → `hint.blockNumber = 18446744073709551615`. [6](#0-5) 
6. `retrievePendingEventsFrom`: `startBlkNum = 18446744073709551615`, `curBlkNum ≈ 500`. Condition `startBlkNum <= curBlkNum` is false; loop body never executes; `pendingEvents = []`. [7](#0-6) 
7. The user's `RequestValueTransfer` at block 500 (nonce 0) is never recovered. The KLAY deposited in the source bridge is permanently locked.

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L53-54)
```text
        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L51-52)
```text
        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);
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

**File:** node/sc/vt_recovery.go (L211-214)
```go
	hint.blockNumber, err = to.bridge.RecoveryBlockNumber(nil)
	if err != nil {
		return nil, err
	}
```

**File:** node/sc/vt_recovery.go (L287-291)
```go
	startBlkNum := hint.blockNumber
	endBlkNum := startBlkNum + filterLogsStride

pendingTxLoop:
	for startBlkNum <= curBlkNum {
```
