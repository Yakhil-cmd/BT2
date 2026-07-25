Now I have enough information to write the finding. Let me confirm the exact state-update ordering in `handleKLAYTransfer` and the nonce-blocking consequence.

### Title
Recipient contract with reverting fallback permanently freezes bridged KAIA in `handleKLAYTransfer` — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`BridgeTransferKLAY.handleKLAYTransfer` delivers KAIA to the destination address via a low-level `.call.value(_value)("")`. If `_to` is a contract whose fallback/receive function reverts, the `require(ok, "handleKLAYTransfer: transfer failed")` reverts the entire transaction, rolling back every state mutation including the nonce record and vote closure. Because the source-chain KAIA is already locked or burned and the `_to` address is immutably fixed by the original request event, the bridged KAIA is permanently frozen in the destination bridge with no recovery path.

---

### Finding Description

In `handleKLAYTransfer`, the execution order is:

1. `_lowerHandleNonceCheck` — passes
2. `_voteValueTransfer` — threshold reached, vote closed
3. `_setHandledRequestTxHash` — marks request tx hash as handled
4. `handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber` — records block number
5. `_updateHandleNonce` — advances `lowerHandleNonce` / `upperHandleNonce`
6. `emit HandleValueTransfer`
7. `(bool ok, ) = _to.call.value(_value)("")` — **external call to recipient**
8. `require(ok, "handleKLAYTransfer: transfer failed")` — **reverts entire tx if step 7 fails** [1](#0-0) 

Because Solidity reverts roll back all state changes atomically, steps 2–6 are undone when step 8 fires. The nonce entry `handleNoncesToBlockNums[_requestedNonce]` is never durably written, so `_updateHandleNonce`'s inner loop:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) { ... }
lowerHandleNonce = i;
``` [2](#0-1) 

…stalls at the stuck nonce. `lowerHandleNonce` cannot advance past it, and `recoveryBlockNumber` is frozen at the last successfully handled block, causing the off-chain bridge manager to perpetually re-scan from that point. [3](#0-2) 

The off-chain handler in `bridge_manager.go` calls `HandleKLAYTransfer` with the exact parameters from the source-chain event; there is no mechanism to substitute a different `_to` address. [4](#0-3) 

---

### Impact Explanation

**Permanent loss of bridged KAIA.** The user's KAIA on the source chain is already locked in (or burned from) the source bridge at the time of the `RequestValueTransfer` event. The destination bridge holds the corresponding KAIA but can never release it because every `handleKLAYTransfer` attempt reverts. There is no admin function to redirect the transfer to a different address or to force-mark the nonce as handled. The stuck nonce also freezes `lowerHandleNonce`, degrading the off-chain recovery subsystem for all subsequent transfers on that bridge pair.

---

### Likelihood Explanation

Any user who specifies a contract address as `_to` that lacks a `payable` fallback or `receive` function — a common pattern for multisigs, proxy wallets, DeFi vaults, and governance contracts — will trigger this condition. The user need not act maliciously; a simple mistake (e.g., specifying a contract address that does not accept native KAIA) is sufficient. The trigger requires only a standard `requestKLAYTransfer` call, which is an unprivileged user action. [5](#0-4) 

---

### Recommendation

Decouple the KAIA delivery from the nonce-accounting state update. Two complementary approaches:

1. **Pull pattern**: Record the pending payout in a mapping (`pendingWithdrawals[_to] += _value`) after the nonce is durably committed, and expose a separate `withdraw()` function. This mirrors the mitigation suggested in the original Astaria report.

2. **Soft failure**: Replace `require(ok, ...)` with a conditional that, on failure, stores the amount in a claimable mapping rather than reverting. This preserves the nonce advance and prevents the bridge from being permanently blocked.

Either approach ensures that a reverting recipient cannot prevent the nonce from being consumed or the bridge state from advancing.

---

### Proof of Concept

1. Deploy a contract `RejectKAIA` on the destination chain with a reverting fallback:
   ```solidity
   contract RejectKAIA {
       fallback() external payable { revert("no KAIA"); }
   }
   ```

2. On the source chain, call `requestKLAYTransfer(address(rejectKAIA), value, "")` with `msg.value = value + fee`. The source bridge emits `RequestValueTransfer` with nonce N and locks/burns the KAIA.

3. Bridge operators observe the event and call `handleKLAYTransfer(..., address(rejectKAIA), value, N, ...)` on the destination bridge. The call to `rejectKAIA.call.value(value)("")` returns `ok = false`; `require(ok)` reverts the transaction. All state (nonce record, vote closure) is rolled back.

4. Operators retry indefinitely — every attempt reverts. `lowerHandleNonce` remains at N. The KAIA in the destination bridge is permanently frozen. The user's KAIA on the source chain is already gone. [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L81-99)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L131-135)
```text
    // requestKLAYTransfer requests transfer KLAY to _to on relative chain.
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L30-34)
```text
    uint64 public requestNonce; // the number of value transfer request that this contract received.
    uint64 public lowerHandleNonce; // a minimum nonce of a value transfer request that will be handled.
    uint64 public upperHandleNonce; // a maximum nonce of the counterpart bridge's value transfer request that is handled.
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
    mapping(uint64 => uint64) public handleNoncesToBlockNums;  // <request nonce> => <request blockNum>
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

**File:** node/sc/bridge_manager.go (L332-337)
```go
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
```
