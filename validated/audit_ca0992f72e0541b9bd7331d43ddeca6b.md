Now I have enough context to write the finding. Let me verify the exact line numbers for the key code paths.

### Title
Blacklisted ERC20 Recipient Permanently Freezes Bridge `lowerHandleNonce`, Locking All Subsequent Recovery — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

In `BridgeTransferERC20::handleERC20Transfer`, the actual ERC20 token transfer to `_to` is performed **after** all nonce-state mutations. If the ERC20 token has a blacklist feature (e.g., USDC) and `_to` is blacklisted, `safeTransfer` reverts, rolling back every state change in the same transaction — including the nonce bookkeeping. Because no admin escape hatch exists to skip or force-advance `lowerHandleNonce`, that nonce is permanently unresolvable, and the value-transfer recovery daemon loops forever re-submitting the failing transaction.

The same structural defect exists in `BridgeTransferKLAY::handleKLAYTransfer` when `_to` is a contract that rejects KLAY.

---

### Finding Description

`handleERC20Transfer` executes in this order:

```
1. _lowerHandleNonceCheck(_requestedNonce)          // guard
2. _voteValueTransfer(_requestedNonce)               // sets closedValueTransferVotes[N] = true
3. _setHandledRequestTxHash(_requestTxHash)          // marks tx hash handled
4. handleNoncesToBlockNums[N] = _requestedBlockNumber
5. _updateHandleNonce(N)                             // advances lowerHandleNonce
6. emit HandleValueTransfer(...)
7. IERC20(_tokenAddress).safeTransfer(_to, _value)  // ← REVERTS if _to is blacklisted
``` [1](#0-0) 

When step 7 reverts, the EVM rolls back **all** state changes from steps 2–6. Consequently:

- `closedValueTransferVotes[N]` is reset to `false`
- `handleNoncesToBlockNums[N]` is reset to `0`
- `lowerHandleNonce` is not advanced

`_updateHandleNonce` advances `lowerHandleNonce` only while `handleNoncesToBlockNums[i] > 0` for consecutive `i` starting from the current `lowerHandleNonce`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) { ... }
lowerHandleNonce = i;
``` [2](#0-1) 

Because `handleNoncesToBlockNums[N]` is always reverted to `0`, `lowerHandleNonce` is permanently stuck at `N`. `recoveryBlockNumber` is also stuck at the block of nonce `N-1`.

The same pattern exists in `handleKLAYTransfer`:

```solidity
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [3](#0-2) 

The value-transfer recovery daemon (`vt_recovery.go`) uses `lowerHandleNonce` and `recoveryBlockNumber` to determine which requests need re-processing: [4](#0-3) [5](#0-4) 

With `lowerHandleNonce` frozen at `N`, the recovery daemon perpetually re-discovers nonce `N`, submits `handleERC20Transfer`, pays gas, and fails — indefinitely.

There is no owner-callable function to skip a nonce or force-advance `lowerHandleNonce`.

---

### Impact Explanation

- **Bridged assets permanently locked**: The user's ERC20 tokens were already burned/locked on the source chain when `requestERC20Transfer` was called. Because `handleERC20Transfer` can never succeed for nonce `N`, those tokens are irrecoverable.
- **`lowerHandleNonce` frozen**: All subsequent nonces' `handleNoncesToBlockNums` entries are set correctly, but `lowerHandleNonce` never advances past `N` because the gap at `N` breaks the consecutive-scan loop in `_updateHandleNonce`.
- **Recovery daemon infinite loop**: `vt_recovery.go` perpetually re-submits the failing handle transaction, burning operator gas with no resolution path.
- **`recoveryBlockNumber` frozen**: The bridge's recovery start-block never advances, causing the daemon to re-scan an ever-growing range of historical blocks.

---

### Likelihood Explanation

- USDC and other blacklistable ERC20 tokens are commonly bridged assets. A user can be blacklisted by the token issuer at any time after submitting a bridge request but before operators execute the handle transaction.
- For KLAY: any user who specifies a contract address as `_to` that lacks a payable fallback (e.g., a multisig, a DAO contract, or a self-destructed contract) triggers the same freeze.
- The window between `requestERC20Transfer` on the source chain and `handleERC20Transfer` on the destination chain can span multiple blocks, giving ample time for a blacklisting event to occur.
- No special privilege is required; any ordinary user initiating a bridge transfer is a potential trigger.

---

### Recommendation

Move the asset transfer **before** any nonce-state mutations, or — preferably — wrap the transfer in a try/catch (Solidity ≥ 0.6) and, on failure, record the nonce as "failed" in a separate mapping that the owner can later redirect to an alternative recipient or refund address. A minimal fix:

```solidity
// 1. Attempt transfer first
bool transferOk;
if (modeMintBurn) {
    transferOk = ERC20Mintable(_tokenAddress).mint(_to, _value);
} else {
    (bool success, ) = address(_tokenAddress).call(
        abi.encodeWithSelector(IERC20.transfer.selector, _to, _value)
    );
    transferOk = success;
}
require(transferOk, "handleERC20Transfer: transfer failed");

// 2. Only then commit nonce state
_setHandledRequestTxHash(_requestTxHash);
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);
emit HandleValueTransfer(...);
```

Alternatively, add an owner-only `skipHandleNonce(uint64 nonce)` function that manually sets `handleNoncesToBlockNums[nonce]` to a sentinel value and calls `_updateHandleNonce`, allowing recovery from permanently-stuck nonces.

---

### Proof of Concept

1. Deploy `BridgeTransferERC20` with a USDC-like ERC20 token (supports blacklisting) in lock/unlock mode (`modeMintBurn = false`).
2. Alice calls `requestERC20Transfer(token, aliceDest, 1000e6, 0, "")` on the source bridge. This emits `RequestValueTransfer` with `requestNonce = N` and locks 1000 USDC in the bridge.
3. The USDC issuer blacklists `aliceDest` before operators process the request.
4. Operator calls `handleERC20Transfer(txHash, alice, aliceDest, token, 1000e6, N, blockNum, "")`.
   - Steps 2–6 execute (nonce state updated, event emitted).
   - Step 7: `IERC20(token).safeTransfer(aliceDest, 1000e6)` reverts because `aliceDest` is blacklisted.
   - Entire transaction reverts; `lowerHandleNonce` remains at `N`.
5. Repeat step 4 indefinitely — always reverts.
6. Verify: `bridge.lowerHandleNonce()` returns `N` forever.
7. Verify: `bridge.handleNoncesToBlockNums(N)` returns `0` forever.
8. Alice's 1000 USDC is permanently locked in the source bridge with no recovery path. [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-73)
```text
    function handleERC20Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
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

**File:** node/sc/vt_recovery.go (L34-57)
```go
// valueTransferHint stores the last handled block number and nonce (Request or Handle).
type valueTransferHint struct {
	blockNumber     uint64 // block number to start searching event logs
	requestNonce    uint64
	handleNonce     uint64
	prevHandleNonce uint64 // previous handleNonce between recovery interval
	candidate       bool   // to check recovery candidate between recovery interval
}

// valueTransferRecovery stores status information for the value transfer recovery.
type valueTransferRecovery struct {
	stopCh    chan interface{}
	isRunning bool           // to check duplicated start
	wg        sync.WaitGroup // wait group to handle the Stop() sync

	child2parentHint *valueTransferHint
	parent2childHint *valueTransferHint
	childEvents      []IRequestValueTransferEvent
	parentEvents     []IRequestValueTransferEvent

	config      *SCConfig
	cBridgeInfo *BridgeInfo
	pBridgeInfo *BridgeInfo
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

**File:** node/sc/vt_recovery.go (L211-228)
```go
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
```
