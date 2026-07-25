### Title
Bridge `handleERC20Transfer` Push-Transfer to Blacklisted Recipient Permanently Locks Bridge Nonce and Bridged Assets — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`handleERC20Transfer` in `BridgeTransferERC20.sol` uses a push-payment pattern: after accumulating operator votes and updating nonce state, it calls `IERC20(_tokenAddress).safeTransfer(_to, _value)` directly. If `_to` is blacklisted by the ERC20 token (e.g., USDC/USDT), the `safeTransfer` reverts, rolling back the entire transaction including all nonce state updates. Because there is no mechanism to skip or redirect a stuck nonce, `lowerHandleNonce` is permanently frozen at the blocked nonce, the bridged assets are permanently locked in the bridge contract, and the value-transfer recovery system is broken for the bridge pair.

---

### Finding Description

In `handleERC20Transfer`, the execution order is:

1. `_lowerHandleNonceCheck(_requestedNonce)` — validates nonce is not below lower bound
2. `_voteValueTransfer(_requestedNonce)` — sets `closedValueTransferVotes[N] = true` when threshold reached
3. `_setHandledRequestTxHash(_requestTxHash)` — marks tx hash handled
4. `handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber` — records block number
5. `_updateHandleNonce(_requestedNonce)` — attempts to advance `lowerHandleNonce`
6. `emit HandleValueTransfer(...)`
7. **`IERC20(_tokenAddress).safeTransfer(_to, _value)`** — push transfer to recipient [1](#0-0) 

If step 7 reverts (because `_to` is on the ERC20 blacklist), the EVM rolls back all state changes from steps 2–5. The result:

- `closedValueTransferVotes[N]` is reset to `false`
- `handleNoncesToBlockNums[N]` remains `0`
- `lowerHandleNonce` is not advanced

`_updateHandleNonce` advances `lowerHandleNonce` only while `handleNoncesToBlockNums[i] > 0` in a contiguous sequence starting from `lowerHandleNonce`: [2](#0-1) 

Since `handleNoncesToBlockNums[N]` is never durably set (every attempt reverts), `lowerHandleNonce` is permanently frozen at `N`. Even if all subsequent nonces `N+1, N+2, ...` are successfully handled, the loop in `_updateHandleNonce` stops immediately at `N` because `handleNoncesToBlockNums[N] == 0`.

The same pattern exists in `handleKLAYTransfer`, where `require(ok, "handleKLAYTransfer: transfer failed")` after `_to.call.value(_value)("")` causes the same permanent freeze if `_to` is a contract that rejects KLAY: [3](#0-2) 

There is no admin function to skip a nonce, redirect `_to`, or force-advance `lowerHandleNonce`. The bridge owner can only stop the bridge entirely (`setRunningStatus(false)`), which does not resolve the stuck nonce.

The value-transfer recovery system reads `recoveryBlockNumber` (which is only updated inside the `_updateHandleNonce` loop) to determine where to start scanning for missed events: [4](#0-3) 

With `lowerHandleNonce` frozen, `recoveryBlockNumber` is also frozen, causing the recovery system to perpetually replay from the same block.

---

### Impact Explanation

- **Bridged assets permanently locked:** The ERC20 tokens (or KLAY) corresponding to nonce `N` are held in the bridge contract and can never be delivered or reclaimed. There is no escape hatch.
- **`lowerHandleNonce` permanently frozen:** The bridge's sequential nonce accounting is broken. `recoveryBlockNumber` never advances, causing the VT recovery subsystem to loop indefinitely over the same block range.
- **Unauthorized asset lock:** A user who initiates a bridge transfer and is subsequently blacklisted by the token issuer (or who deploys a KLAY-rejecting contract as `_to`) causes permanent loss of bridged funds — an unauthorized asset lock affecting system-managed bridge funds.

---

### Likelihood Explanation

- USDC and USDT both implement address blacklists. Any address that receives a bridge transfer and is later blacklisted (e.g., due to sanctions, exploit involvement, or deliberate manipulation) triggers this condition.
- For KLAY: any user can specify a contract address as `_to` that has no payable fallback or explicitly reverts on receipt.
- The trigger requires only a valid bridge request on the source chain — no privileged access is needed. The blacklisting is performed by the token issuer (an external party), not by the attacker directly, but the outcome is deterministic once the blacklisting occurs.

---

### Recommendation

Separate the nonce state update from the asset delivery. After the vote threshold is reached and nonce state is committed, store the pending delivery in a mapping rather than pushing immediately:

```solidity
mapping(uint64 => PendingTransfer) public pendingTransfers;

struct PendingTransfer {
    address token;
    address to;
    uint256 value;
}
```

Allow the recipient (or an admin) to claim via a separate `claimTransfer(uint64 nonce)` function. This way, a failed delivery does not revert the nonce state update, and `lowerHandleNonce` advances correctly regardless of whether the recipient can receive tokens.

Alternatively, wrap the transfer in a try/catch (Solidity ≥0.6) and store failed deliveries for later claim, ensuring the nonce is always consumed.

---

### Proof of Concept

1. Alice initiates a bridge transfer of 1000 USDC from the parent chain to the child chain, specifying `_to = aliceAddr` with request nonce `N`.
2. The bridge operators observe the `RequestValueTransfer` event and call `handleERC20Transfer(..., aliceAddr, usdcAddr, 1000, N, ...)` on the child bridge.
3. Before the operator transaction is mined (or after), USDC's issuer blacklists `aliceAddr`.
4. Inside `handleERC20Transfer`: votes pass, `handleNoncesToBlockNums[N]` is written, `_updateHandleNonce` runs — then `IERC20(usdcAddr).safeTransfer(aliceAddr, 1000)` reverts because `aliceAddr` is blacklisted.
5. The entire transaction reverts. `handleNoncesToBlockNums[N] == 0`, `lowerHandleNonce` stays at `N`.
6. Every subsequent retry by operators also reverts at step 7.
7. `lowerHandleNonce` is permanently `N`. The 1000 USDC are locked in the child bridge contract forever.
8. The VT recovery system reads `recoveryBlockNumber` (frozen at the block before `N`) and keeps replaying the same block range indefinitely. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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
