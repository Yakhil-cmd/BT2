### Title
`_updateHandleNonce` Loop Halts Permanently When `_requestedBlockNumber == 0`, Sticking `lowerHandleNonce` and Breaking Bridge Recovery — (`contracts/service_chain/bridge/BridgeTransfer.sol`)

---

### Summary

`BridgeTransfer._updateHandleNonce()` uses `handleNoncesToBlockNums[i] > 0` as the sentinel to decide whether nonce `i` has been handled. Because `handleNoncesToBlockNums[_requestedNonce]` is set directly from the caller-supplied `_requestedBlockNumber`, passing `_requestedBlockNumber == 0` stores the value `0` for that slot. The loop then immediately exits on that nonce, `lowerHandleNonce` is never advanced past it, and `recoveryBlockNumber` is never updated — permanently corrupting both bridge-state variables.

---

### Finding Description

`_updateHandleNonce` in `BridgeTransfer.sol` advances `lowerHandleNonce` and `recoveryBlockNumber` by iterating over consecutive handled nonces:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    delete handleNoncesToBlockNums[i];
    delete closedValueTransferVotes[i];
}
lowerHandleNonce = i;
``` [1](#0-0) 

The loop condition `handleNoncesToBlockNums[i] > 0` is intended to detect whether nonce `i` has been recorded. However, the mapping entry is written directly from the operator-supplied argument:

```solidity
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);
``` [2](#0-1) 

No validation enforces `_requestedBlockNumber > 0`. If an operator submits `_requestedBlockNumber == 0` for nonce `N`:

1. `handleNoncesToBlockNums[N] = 0` is stored.
2. The loop condition `handleNoncesToBlockNums[N] > 0` evaluates to `false` immediately.
3. The loop body never executes; `lowerHandleNonce` is set to `N` (unchanged from its pre-call value).
4. `recoveryBlockNumber` is never updated.

Every subsequent call to `_updateHandleNonce` for nonces `N+1`, `N+2`, … re-enters the loop at `i = N`, hits the same `0` sentinel, and exits again. `lowerHandleNonce` is permanently stuck at `N`.

The initial value `recoveryBlockNumber = 1` (not 0) shows the developers were aware that block 0 is a sentinel, but the handle entry-points impose no corresponding guard. [3](#0-2) 

---

### Impact Explanation

**Persistent bridge-state corruption** with two concrete consequences:

1. **`lowerHandleNonce` stuck forever.** The variable is supposed to track the minimum unhandled nonce. Once stuck at `N`, it can never advance past `N` without a contract upgrade. The VT recovery system reads `lowerHandleNonce` to decide which nonces still need handling; a stuck value causes the recovery daemon to repeatedly attempt nonce `N` (which is already handled) and never make progress on the gap detection logic.

2. **`recoveryBlockNumber` frozen.** `node/sc/vt_recovery.go` reads `RecoveryBlockNumber()` from the bridge contract as the starting block for log filtering:

```go
hint.blockNumber, err = to.bridge.RecoveryBlockNumber(nil)
...
startBlkNum := hint.blockNumber
``` [4](#0-3) [5](#0-4) 

If `recoveryBlockNumber` is frozen at `1` (or any stale value), the recovery daemon scans the entire chain history on every cycle, and — more critically — the `checkRecoveryCondition` logic that detects stuck transfers may never correctly identify the pending nonces, leaving bridged assets stranded.

---

### Likelihood Explanation

- **Trigger**: Any registered bridge operator can call `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` with `_requestedBlockNumber == 0`. No special privilege beyond operator registration is required.
- **Realistic path**: A transfer requested at genesis block (block 0) on the service chain would legitimately carry `_requestedBlockNumber == 0`. A compromised or malicious operator can also supply this value deliberately.
- **Threshold**: If the operator threshold is 1 (default in tests), a single operator suffices. With threshold > 1, colluding operators are required.

---

### Recommendation

Replace the zero-sentinel check with a dedicated boolean mapping that is independent of the block-number value, mirroring the TWAV fix of using `cumulativeValuation != 0` instead of `timestamp != 0`:

```solidity
mapping(uint64 => bool) public handledNonces; // NEW

// In handle functions, after storing block number:
handledNonces[_requestedNonce] = true;

// In _updateHandleNonce:
for (i = lowerHandleNonce; i <= limit && handledNonces[i]; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    delete handleNoncesToBlockNums[i];
    delete handledNonces[i];
    delete closedValueTransferVotes[i];
}
lowerHandleNonce = i;
```

Alternatively, add an explicit input validation in all three handle functions:

```solidity
require(_requestedBlockNumber > 0, "invalid block number");
``` [6](#0-5) 

---

### Proof of Concept

1. Deploy `Bridge` with a single operator (threshold = 1).
2. Call `handleKLAYTransfer(txHash, from, to, value, nonce=0, blockNumber=0, "")`.
3. Observe: `handleNoncesToBlockNums[0] == 0`, loop exits immediately, `lowerHandleNonce == 0`, `recoveryBlockNumber == 1` (unchanged).
4. Call `handleKLAYTransfer(txHash2, from, to, value, nonce=1, blockNumber=500, "")`.
5. Observe: loop re-enters at `i=0`, `handleNoncesToBlockNums[0] > 0` is still false, loop exits, `lowerHandleNonce` remains `0`, `recoveryBlockNumber` remains `1`.
6. `lowerHandleNonce` and `recoveryBlockNumber` are permanently stuck regardless of how many subsequent nonces are handled.

The existing test `TestNoncesAndBlockNumberUnordered` confirms the loop's dependence on `handleNoncesToBlockNums[i] > 0` but does not exercise the `_requestedBlockNumber == 0` edge case. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L33-33)
```text
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-84)
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

**File:** node/sc/vt_recovery.go (L287-288)
```go
	startBlkNum := hint.blockNumber
	endBlkNum := startBlkNum + filterLogsStride
```
