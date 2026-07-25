### Title
KAIA Permanently Locked via `requestKLAYTransfer` with Counterpart Bridge Address as Destination — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`BridgeTransferKLAY.requestKLAYTransfer` accepts an arbitrary `_to` address with no check that it is not the counterpart bridge's own address. When a user specifies the counterpart bridge address as `_to`, the KAIA is locked in chain A's bridge and the corresponding `handleKLAYTransfer` on chain B always reverts due to the shared `nonReentrant` guard, permanently locking the KAIA with no recovery path.

---

### Finding Description

`requestKLAYTransfer` on chain A locks `msg.value` KAIA in the bridge and emits a `RequestValueTransfer` event with the caller-supplied `_to` as the destination on chain B. [1](#0-0) 

The off-chain relayer (`SubBridge`) picks up this event and calls `handleKLAYTransfer` on chain B's bridge, forwarding `_to` verbatim. [2](#0-1) 

`handleKLAYTransfer` on chain B sends KAIA to `_to` via a low-level call: [3](#0-2) 

When `_to` is chain B's bridge address itself, this triggers the bridge's own payable fallback: [4](#0-3) 

The fallback calls `_requestKLAYTransfer`, which carries the `nonReentrant` modifier from the same `ReentrancyGuard` instance: [5](#0-4) 

Because `handleKLAYTransfer` also holds the `nonReentrant` lock at this point, the inner call reverts. The outer `require(ok, "handleKLAYTransfer: transfer failed")` then reverts the entire `handleKLAYTransfer` transaction. Every subsequent relay attempt for this nonce will fail identically.

Neither `BridgeTransferKLAY` nor any parent contract exposes a `withdraw` or `rescue` function, so the KAIA locked in chain A's bridge has no recovery path.

Additionally, because `handleNoncesToBlockNums[nonce]` is set inside `handleKLAYTransfer` (before the transfer) and the whole transaction reverts, `_updateHandleNonce` never advances `lowerHandleNonce` past the stuck nonce. The `recoveryBlockNumber` is frozen at the stuck nonce's block, and `closedValueTransferVotes` / `handleNoncesToBlockNums` entries for all subsequent nonces accumulate without cleanup. [6](#0-5) 

---

### Impact Explanation

- **KAIA permanently locked**: The KAIA deposited by the user in chain A's bridge cannot be released. `handleKLAYTransfer` on chain B will always revert for this nonce, and there is no owner-callable rescue function.
- **Bridge nonce state corruption**: `lowerHandleNonce` on chain B is frozen at the stuck nonce. `recoveryBlockNumber` does not advance, causing the recovery scanner to re-scan from an old block on every restart. Storage for all subsequent nonces is never cleaned up, causing unbounded growth of `closedValueTransferVotes` and `handleNoncesToBlockNums`.

---

### Likelihood Explanation

Any user who knows the counterpart bridge address (a public, on-chain value) can trigger this, either accidentally or deliberately. The counterpart bridge address is stored in `counterpartBridge` and is readable by anyone. [7](#0-6) 

No privileged role is required. The trigger is a single unprivileged call to `requestKLAYTransfer`.

---

### Recommendation

Add a guard in `_requestKLAYTransfer` (or `requestKLAYTransfer`) rejecting the counterpart bridge address as a destination:

```solidity
require(_to != counterpartBridge, "cannot transfer to counterpart bridge");
```

Analogously, add the same guard in `_requestERC20Transfer` and `_requestERC721Transfer` to prevent tokens from being minted/transferred into the bridge contract itself on the counterpart chain.

---

### Proof of Concept

1. Chain A bridge is deployed at `0xBridgeA`; chain B bridge is deployed at `0xBridgeB`. `counterpartBridge` on chain A is set to `0xBridgeB`.
2. Alice calls `requestKLAYTransfer(0xBridgeB, 1 ether, "")` on chain A with `msg.value = 1 ether`.
   - 1 KAIA is locked in `0xBridgeA`.
   - `RequestValueTransfer` event emitted with `_to = 0xBridgeB`.
3. The SubBridge relayer observes the event and calls `handleKLAYTransfer(txHash, Alice, 0xBridgeB, 1 ether, nonce, blockNum, "")` on chain B.
4. Inside `handleKLAYTransfer` (which holds the `nonReentrant` lock), `0xBridgeB.call{value: 1 ether}("")` is executed.
5. Chain B bridge's fallback fires, calling `_requestKLAYTransfer(address(this), feeOfKLAY, "")`.
6. `_requestKLAYTransfer` has `nonReentrant`; the guard is already held → **reverts**.
7. `require(ok, "handleKLAYTransfer: transfer failed")` → **entire `handleKLAYTransfer` reverts**.
8. The relayer retries indefinitely; every attempt reverts.
9. Alice's 1 KAIA in `0xBridgeA` is permanently locked. `lowerHandleNonce` on chain B is frozen at `nonce`. [8](#0-7) [9](#0-8)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L102-135)
```text
    // _requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
        require(isRunning, "stopped bridge");
        require(msg.value > _feeLimit, "insufficient amount");

        uint256 fee = _payKLAYFeeAndRefundChange(_feeLimit);

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
    }

    // () requests transfer KLAY to msg.sender address on relative chain.
    function () external payable {
        _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
    }

    // requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```

**File:** node/sc/bridge_manager.go (L332-337)
```go
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
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

**File:** contracts/service_chain/bridge/BridgeCounterPart.sol (L22-33)
```text
contract BridgeCounterPart is Ownable {
    address public counterpartBridge;

    event CounterpartBridgeChanged(address _bridge);

    function setCounterPartBridge(address _bridge)
        external
        onlyOwner
    {
        counterpartBridge = _bridge;
        emit CounterpartBridgeChanged(_bridge);
    }
```
