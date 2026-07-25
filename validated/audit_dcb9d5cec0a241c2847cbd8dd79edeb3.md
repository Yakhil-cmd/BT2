### Title
Bridge KAIA/ERC20 Transfer Permanently Locked When Recipient Cannot Receive Funds — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

The Kaia service-chain bridge's `handleKLAYTransfer` and `handleERC20Transfer` functions update critical nonce-tracking state **before** performing the external asset transfer to `_to`. If the transfer to `_to` reverts (e.g., `_to` is a contract with a reverting fallback for KAIA, or `_to` is blacklisted by an ERC20 token such as USDC), the entire transaction reverts — including the nonce state update. Because operators cannot change the `_to` address (it is fixed by the original `RequestValueTransfer` event), the transfer for that nonce can never succeed. The bridged assets are permanently locked in the bridge contract, and `lowerHandleNonce` is stuck, breaking the value-transfer recovery system for all subsequent nonces.

---

### Finding Description

In `BridgeTransferKLAY.sol`, `handleKLAYTransfer` performs the following sequence:

1. Validates the nonce (`_lowerHandleNonceCheck`)
2. Collects operator votes (`_voteValueTransfer`)
3. Marks the request tx hash as handled (`_setHandledRequestTxHash`)
4. **Updates nonce state** (`handleNoncesToBlockNums[_requestedNonce]`, `_updateHandleNonce`)
5. Emits `HandleValueTransfer`
6. **Sends KAIA** to `_to` via `_to.call.value(_value)("")`
7. `require(ok, "handleKLAYTransfer: transfer failed")` [1](#0-0) 

If step 6 fails (e.g., `_to` is a contract with a reverting fallback), `require` at step 7 causes the entire transaction to revert. All state changes from steps 3–5 are rolled back. The nonce is never marked as handled, so `lowerHandleNonce` never advances past this nonce.

The identical pattern exists in `BridgeTransferERC20.sol` for the non-mintBurn path: [2](#0-1) 

Here, `IERC20(_tokenAddress).safeTransfer(_to, _value)` will revert if `_to` is blacklisted by the token contract (e.g., USDC, USDT). The nonce state update at lines 53–54 is also reverted.

The `_updateHandleNonce` function advances `lowerHandleNonce` only when `handleNoncesToBlockNums[i] > 0` for consecutive nonces starting from `lowerHandleNonce`: [3](#0-2) 

Since the stuck nonce N never has `handleNoncesToBlockNums[N]` set (every attempt reverts), `lowerHandleNonce` is permanently stuck at N. The `recoveryBlockNumber` never advances past the block preceding nonce N.

The `_to` address is fixed by the original `RequestValueTransfer` event on the source chain. The Go-layer bridge manager reads it directly from the event and passes it unchanged to `HandleKLAYTransfer`/`HandleERC20Transfer`: [4](#0-3) 

Operators have no mechanism to substitute a different recipient or skip the stuck nonce.

---

### Impact Explanation

- **Permanent asset lock**: The KAIA or ERC20 tokens corresponding to the stuck nonce are locked in the bridge contract forever. The user on the source chain has already had their assets locked/burned; they receive nothing on the destination chain.
- **Recovery system corruption**: `lowerHandleNonce` and `recoveryBlockNumber` are permanently stuck at the problematic nonce. The value-transfer recovery system (`vt_recovery.go`) uses `recoveryBlockNumber` to determine where to scan for pending events; a stale value causes it to re-scan from an old block indefinitely or miss events.
- **Scope**: Affects bridged KAIA (native asset) and any ERC20 token with a blacklist mechanism (USDC, USDT, etc.) in lock/unlock mode.

---

### Likelihood Explanation

- **Unprivileged trigger**: Any user can call `requestKLAYTransfer` or `requestERC20Transfer` on the source chain and specify any address as `_to`, including a non-payable contract or a blacklisted address.
- **Accidental trigger**: A user may accidentally specify a contract address (e.g., a token contract) as `_to`, causing permanent lock.
- **Intentional griefing**: A malicious user can intentionally specify a non-payable contract as `_to` to break the bridge's recovery mechanism, affecting all other users' pending transfers.
- **ERC20 blacklist**: USDC and USDT are commonly bridged assets. If a user's address is blacklisted after initiating a bridge request (analogous to the original bug), the bridge is permanently stuck for that nonce.

---

### Recommendation

Apply the checks-effects-interactions pattern: perform the external transfer **before** updating nonce state, or implement a pull-payment / claims pattern for failed transfers. Specifically:

1. **Try-catch pattern**: Wrap the external call in a try/catch (Solidity ≥0.6) or use a low-level call without `require`. If the transfer fails, record the amount in a `pendingClaims[_to][token]` mapping so the recipient can claim later, and still advance the nonce.
2. **Separate nonce advancement from asset delivery**: Mark the nonce as handled regardless of transfer success, and store failed transfers in a claimable mapping.
3. **Operator override**: Allow operators to designate an alternative recipient for a stuck nonce (with multi-sig threshold), so the bridge can recover without protocol upgrade.

---

### Proof of Concept

**KLAY scenario:**

1. Attacker deploys `RejectKAIA` contract with a reverting fallback on the destination chain.
2. Attacker calls `requestKLAYTransfer(RejectKAIA.address, 1 ether, "0x")` on the source bridge, sending `1 ether + fee`.
3. Operators observe `RequestValueTransfer` event with `to = RejectKAIA.address`, nonce = N.
4. Operators call `handleKLAYTransfer(..., RejectKAIA.address, 1 ether, N, ...)` on the destination bridge.
5. `_to.call.value(1 ether)("")` returns `ok = false` because `RejectKAIA` reverts.
6. `require(ok, "handleKLAYTransfer: transfer failed")` reverts the entire transaction.
7. `handleNoncesToBlockNums[N]` is never set; `lowerHandleNonce` stays at N.
8. Every subsequent operator retry for nonce N also reverts. The 1 KAIA is permanently locked.
9. `lowerHandleNonce` is stuck at N; `recoveryBlockNumber` never advances.

**ERC20 (USDC) scenario:**

1. User `A` calls `requestERC20Transfer(USDC, blacklistedAddr, 1000e6, feeLimit, "0x")` on the source bridge.
2. Operators call `handleERC20Transfer(..., blacklistedAddr, USDC, 1000e6, N, ...)` on the destination bridge.
3. `IERC20(USDC).safeTransfer(blacklistedAddr, 1000e6)` reverts (USDC blacklist check).
4. Entire transaction reverts; nonce N is never marked handled.
5. 1000 USDC is permanently locked in the destination bridge contract.

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L51-72)
```text
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
