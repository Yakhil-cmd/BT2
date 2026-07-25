### Title
Permanently Failed Bridge Asset Delivery Has No Recovery Path, Locking Bridged KLAY/ERC20/ERC721 in Destination Bridge — (File: `contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

In Kaia's service-chain bridge, `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` commit nonce/vote state before attempting asset delivery. If the delivery permanently fails (e.g., `_to` is a contract that always reverts on receiving KLAY, or the ERC20/ERC721 token is paused), the `require(ok, ...)` at the end reverts the entire transaction, rolling back the nonce state. The off-chain recovery system (`vt_recovery.go`) then retries indefinitely. Since the failure is permanent, the bridged assets are locked in the destination bridge forever with no path for the original sender to recover them.

---

### Finding Description

In `handleKLAYTransfer` the execution order is:

1. **Nonce/vote state committed** (lines 81–84):
   - `_setHandledRequestTxHash(_requestTxHash)` → `handledRequestTx[hash] = true`
   - `handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber`
   - `_updateHandleNonce(_requestedNonce)` → advances `lowerHandleNonce`, `upperHandleNonce`, deletes `closedValueTransferVotes[nonce]`
   - (earlier) `_voteValueTransfer` → `closedValueTransferVotes[_requestNonce] = true`

2. **Asset delivery attempted** (line 98):
   ```solidity
   (bool ok, ) = _to.call.value(_value)("");
   ```

3. **Hard revert if delivery fails** (line 99):
   ```solidity
   require(ok, "handleKLAYTransfer: transfer failed");
   ```

Because Solidity reverts roll back all state changes in the same call frame, every state mutation from step 1 is undone. The nonce is never consumed, `closedValueTransferVotes` is reset, and the off-chain `ValueTransferRecovery` (`vt_recovery.go`) will re-submit the same `handleKLAYTransfer` call. If `_to` permanently rejects KLAY (reverting fallback, zero-gas fallback, or a contract that was upgraded to reject ETH/KLAY), every retry fails identically. The KLAY that was locked or burned on the source chain is now permanently stranded in the destination bridge.

The identical pattern exists in:
- `handleERC20Transfer` — `IERC20(_tokenAddress).safeTransfer(_to, _value)` or `ERC20Mintable.mint(_to, _value)` at the end; a paused token or a `_to` that rejects ERC20 callbacks causes the same permanent lock.
- `handleERC721Transfer` — `IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId)` or `mintWithTokenURI`; a paused NFT contract or a `_to` that rejects ERC721 callbacks causes the same permanent lock.

There is no pull-based refund mapping, no operator-callable "redirect" function, and no owner-callable "rescue" path for permanently undeliverable transfers.

---

### Impact Explanation

Bridged KAIA, ERC20, or ERC721 assets are permanently locked in the destination bridge contract. The original sender on the source chain has already irrevocably lost their assets (locked in the source bridge or burned in mint-burn mode). The destination bridge holds the assets but can never deliver them, and no on-chain mechanism exists to return them to the original sender or redirect them to a valid address.

This satisfies the allowed impact: **unauthorized lock of bridged assets affecting KAIA and bridged tokens**.

---

### Likelihood Explanation

Any user who specifies a `_to` address that is:
- A contract with a reverting or gas-consuming fallback (common for multisigs, proxy contracts, or contracts that explicitly reject plain KLAY transfers),
- An ERC20/ERC721 token contract that is subsequently paused by its admin,
- A contract whose `onERC721Received` hook reverts,

will trigger this condition. No privileged access is required on the attacker's side; the user simply chooses the recipient address on the source chain. The condition is reachable through normal bridge usage.

---

### Recommendation

Implement a pull-based recovery mechanism analogous to LayerZero's `failedMessages`:

1. **Track undeliverable transfers**: When `_to.call.value(_value)("")` returns `ok = false`, instead of reverting, store `(requestTxHash → amount)` in a new `undeliverableKLAY` mapping and mark the nonce as consumed.
2. **Provide a claim function**: Allow the original `_from` address (recorded in the `RequestValueTransfer` event) to withdraw the locked KLAY/ERC20/ERC721 from the bridge.
3. **Guard against double-claim/retry**: Ensure that once a refund is claimed, the corresponding nonce cannot be retried via `retryMessage` or the recovery system.
4. **Apply to all three token types**: `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` all share this pattern and all need the fix.

---

### Proof of Concept

1. Deploy `RejectKLAY` on the destination chain:
   ```solidity
   contract RejectKLAY { fallback() external payable { revert("no KLAY"); } }
   ```

2. On the source chain, call:
   ```solidity
   bridge.requestKLAYTransfer{value: 1 ether}(address(rejectKLAY), 1 ether, "");
   ```
   Source bridge locks 1 KLAY and emits `RequestValueTransfer`.

3. Operators call `handleKLAYTransfer` on the destination bridge with `_to = address(rejectKLAY)`.

4. `_to.call.value(1 ether)("")` returns `ok = false`. `require(ok, ...)` reverts the transaction. All nonce state is rolled back.

5. `ValueTransferRecovery.recoverPendingEvents()` re-submits the same call → same revert → infinite loop.

6. The 1 KLAY is permanently locked in the destination bridge. The original sender has no on-chain path to recover it.

**Affected files:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L44-72)
```text
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L43-70)
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
            TokenType.ERC721,
            _from,
            _to,
            _tokenAddress,
            _tokenId,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
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
