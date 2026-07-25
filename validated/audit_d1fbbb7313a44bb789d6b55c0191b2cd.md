### Title
`_updateHandleNonce` Zero-Value Sentinel Bypass Permanently Corrupts `lowerHandleNonce` and `recoveryBlockNumber` — (File: `contracts/service_chain/bridge/BridgeTransfer.sol`)

---

### Summary

The `_updateHandleNonce` function in `BridgeTransfer.sol` uses `handleNoncesToBlockNums[i] > 0` as a sentinel to detect whether nonce `i` has been handled. When nonce `0` is handled with `_requestedBlockNumber = 0`, the stored value `handleNoncesToBlockNums[0] = 0` is indistinguishable from the Solidity mapping default (unset = 0). The loop terminates immediately, `lowerHandleNonce` is permanently stuck at `0`, and `recoveryBlockNumber` never advances from its initial value of `1`.

---

### Finding Description

`_updateHandleNonce` in `BridgeTransfer.sol` advances `lowerHandleNonce` by iterating through consecutive handled nonces:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
    recoveryBlockNumber = handleNoncesToBlockNums[i];
    delete handleNoncesToBlockNums[i];
    delete closedValueTransferVotes[i];
}
lowerHandleNonce = i;
``` [1](#0-0) 

The termination condition `handleNoncesToBlockNums[i] > 0` is a zero-value sentinel: a mapping entry that was never written returns `0`, and the loop stops. This is the same structural flaw as the external report — using the type's zero/default value as the "uninitialized" sentinel.

`requestNonce` starts at `0` in `BridgeTransfer.sol`:

```solidity
uint64 public requestNonce; // the number of value transfer request that this contract received.
``` [2](#0-1) 

The first cross-chain request therefore carries `requestNonce = 0`. When an operator calls `handleKLAYTransfer` with `_requestedNonce = 0` and `_requestedBlockNumber = 0` (no on-chain check prevents this):

1. `handleNoncesToBlockNums[0] = 0` — identical to the default unset value.
2. The loop condition `handleNoncesToBlockNums[0] > 0` evaluates to `false` immediately.
3. `lowerHandleNonce` is set to `0` (unchanged).
4. `recoveryBlockNumber` is never updated and stays at its constructor-set value of `1`. [3](#0-2) 

`handleKLAYTransfer` has no guard on `_requestedBlockNumber`:

```solidity
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
    ...
    handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
    _updateHandleNonce(_requestedNonce);
``` [4](#0-3) 

The same pattern applies to `handleERC20Transfer` and `handleERC721Transfer`. [5](#0-4) 

---

### Impact Explanation

**Persistent bridge state corruption:**

- `lowerHandleNonce` is permanently frozen at `0`. The `_lowerHandleNonceCheck` (`require(lowerHandleNonce <= _requestedNonce)`) always passes for every nonce, meaning the "already-removed nonce" guard is permanently disabled.
- `recoveryBlockNumber` stays at `1`. The off-chain recovery module (`vt_recovery.go`) uses `recoveryBlockNumber` as the starting block for scanning missed `RequestValueTransfer` events. With it frozen at `1`, the recovery module re-scans the entire chain history on every recovery cycle.
- `closedValueTransferVotes[i]` entries for all processed nonces are never deleted (the `delete` inside the loop never executes), permanently consuming contract storage and preventing any future vote-reset logic from working correctly.

The KAIA transfer itself executes (the `_to.call.value(_value)("")` succeeds), so the immediate transfer is not blocked. However, the bridge's settlement accounting is persistently corrupted: `lowerHandleNonce` never reflects the true lower bound of unhandled nonces, breaking the invariant the recovery and nonce-window mechanisms depend on. [6](#0-5) 

---

### Likelihood Explanation

- `requestNonce` starts at `0`, so the first legitimate cross-chain request carries nonce `0`.
- `_requestedBlockNumber = 0` is not validated anywhere in the call path.
- A single operator (threshold = 1) or a colluding set of operators meeting the threshold can trigger this with one transaction.
- Operators are semi-trusted (registered by the owner) but are an explicit part of the bridge's threat model.

---

### Recommendation

Add a validation that `_requestedBlockNumber > 0` in all `handle*Transfer` functions, or replace the zero-value sentinel with an explicit boolean `handledNonces` mapping:

```solidity
// Option A: reject block number 0
require(_requestedBlockNumber > 0, "invalid block number");

// Option B: use a separate boolean mapping
mapping(uint64 => bool) public handledNonces;
// in _updateHandleNonce: for (...; handledNonces[i]; i++)
```

This mirrors the recommended fix in the external report: use a non-zero-default field (e.g., `owner != address(0)`) rather than the ID/value field itself as the initialization sentinel.

---

### Proof of Concept

```
1. Deploy Bridge (modeMintBurn=false), fund it with KAIA.
2. Register one operator (threshold=1).
3. Call handleKLAYTransfer(
       txhash=0x1234...,
       from=alice,
       to=bob,
       value=1 ether,
       _requestedNonce=0,
       _requestedBlockNumber=0,   // <-- zero block number
       extraData=0x
   ) from the operator.
4. Observe:
   - bob receives 1 ether (transfer succeeds).
   - lowerHandleNonce() == 0  (should be 1 after nonce 0 is handled).
   - recoveryBlockNumber() == 1  (never updated).
   - handleNoncesToBlockNums[0] == 0  (indistinguishable from unset).
5. Handle nonces 1..500 normally.
6. lowerHandleNonce() still == 0 (loop always stops at i=0).
7. Off-chain recovery module scans from block 1 on every cycle,
   re-submitting nonce 0 indefinitely (each attempt fails at _voteValueTransfer
   because closedValueTransferVotes[0] is set, but gas is wasted and the
   recovery module never advances its scan window).
``` [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L30-30)
```text
    uint64 public requestNonce; // the number of value transfer request that this contract received.
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L33-33)
```text
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L29-52)
```text
    function handleERC721Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _tokenId,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        string memory _tokenURI,
        bytes memory _extraData
    )
        public
        onlyOperators
    {
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);
```

**File:** node/sc/vt_recovery.go (L199-238)
```go
}

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
