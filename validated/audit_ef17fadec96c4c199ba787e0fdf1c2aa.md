Based on my analysis of the Kaia codebase, I found a valid native analog to the reported DEX bug. The bug class — sending native tokens to a contract address that cannot receive them, causing a critical operation to fail permanently — maps directly onto the service-chain bridge's KLAY delivery path.

---

### Title
`handleKLAYTransfer` Permanently Locks Bridged KLAY When Recipient Is a Contract Without a `receive` Function — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

The `handleKLAYTransfer` function in the Kaia service-chain bridge delivers KLAY to the destination address `_to` via a low-level `call.value()`. If `_to` is a contract that lacks a `receive` or `fallback` function, the call returns `false`, the mandatory `require` reverts the entire transaction, and the KLAY is permanently locked in the source bridge contract. Because bridge operators cannot alter `_to` — it is fixed by the original `RequestValueTransfer` event on the source chain — every subsequent attempt to handle that nonce will revert identically, with no on-chain recovery path.

---

### Finding Description

In `BridgeTransferKLAY.sol` lines 98–99:

```solidity
(bool ok, ) = _to.call.value(_value)("");
require(ok, "handleKLAYTransfer: transfer failed");
``` [1](#0-0) 

The function unconditionally attempts to push KLAY to `_to`. If `_to` is a deployed contract with no `receive` or `fallback`, the EVM call returns `ok = false`. The `require` then reverts the entire transaction, unwinding every state mutation that preceded it in the same call frame:

- `handledRequestTx[_requestTxHash]` is **not** persisted.
- `handleNoncesToBlockNums[_requestedNonce]` is **not** persisted.
- `_updateHandleNonce` is **not** committed. [2](#0-1) 

`_updateHandleNonce` advances `lowerHandleNonce` only when `handleNoncesToBlockNums[i] > 0` for every consecutive nonce starting from `lowerHandleNonce`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) { ... }
lowerHandleNonce = i;
``` [3](#0-2) 

Because nonce N is never recorded, `lowerHandleNonce` is permanently stuck at N. Operators can handle nonces > N (the check is `lowerHandleNonce <= _requestedNonce`), but `recoveryBlockNumber` never advances past the block before N, and the KLAY locked on the source chain has no refund mechanism. [4](#0-3) 

---

### Impact Explanation

- **Asset loss**: The user's KLAY is locked in the source bridge contract with no on-chain refund path. The bridge has no "skip nonce" or "cancel request" function.
- **Bridge recovery impairment**: `lowerHandleNonce` and `recoveryBlockNumber` are permanently frozen at the failed nonce, causing the off-chain bridge daemon to re-scan from an increasingly stale block height for all future recovery operations.

Both effects satisfy the allowed impact gate: *unauthorized lock of KAIA / bridged assets* and *persistent corruption of bridge nonce state*.

---

### Likelihood Explanation

Any user on the source chain can trigger this by calling `requestKLAYTransfer` with a destination address that is a contract without a `receive` function. This can occur:

- **Accidentally**: a user mistakenly provides a multisig, proxy, or other contract address that does not implement `receive`.
- **Intentionally**: a griever deploys a minimal contract with no `receive` function and uses it as `_to` to permanently freeze the bridge's `lowerHandleNonce` and lock their own (or others') KLAY.

No privileged access is required; the source-chain `requestKLAYTransfer` is a public payable function. [5](#0-4) 

---

### Recommendation

1. **Wrap the delivery in a success-or-escrow pattern**: if `ok == false`, record the failed amount in a per-address claimable mapping rather than reverting, so the nonce can still be marked handled and `lowerHandleNonce` can advance.
2. **Alternatively**, add an owner-callable `skipNonce(uint64 nonce)` that marks a nonce as handled without transferring funds, crediting the amount to a claimable escrow for the original requester.
3. **At minimum**, emit a `HandleValueTransferFailed` event and do not revert, so the nonce is consumed and the bridge is not permanently stuck.

---

### Proof of Concept

1. Deploy on the destination chain: `contract Sink {}` — no `receive`, no `fallback`.
2. On the source chain, call `bridge.requestKLAYTransfer{value: 1 ether}(sinkAddress, 1 ether - fee, "0x")`. KLAY is locked in the source bridge; a `RequestValueTransfer` event is emitted with nonce N.
3. Bridge operators reach threshold and call `handleKLAYTransfer(txHash, from, sinkAddress, 1 ether - fee, N, blockNum, "0x")` on the destination bridge.
4. `_voteValueTransfer` passes. State writes begin. Then `sinkAddress.call.value(...)("")` returns `false`.
5. `require(ok, "handleKLAYTransfer: transfer failed")` reverts the transaction. All state writes are undone.
6. `handleNoncesToBlockNums[N]` remains `0`; `lowerHandleNonce` stays at N.
7. Every subsequent operator attempt with nonce N reverts identically. The 1 KLAY is permanently locked in the source bridge. `recoveryBlockNumber` never advances past the block before N.

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

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L149-155)
```text
        uint64 i;
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L158-160)
```text
    function _lowerHandleNonceCheck(uint64 _requestedNonce) internal {
        require(lowerHandleNonce <= _requestedNonce, "removed vote");
    }
```
