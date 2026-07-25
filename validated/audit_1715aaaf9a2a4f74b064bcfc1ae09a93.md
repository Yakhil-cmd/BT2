### Title
KLAY Bridge Delivery Permanently Bricked When Recipient Cannot Receive ETH — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

### Summary

`handleKLAYTransfer` in the service-chain bridge delivers KAIA to a user-supplied `_to` address via a low-level `.call.value()`. If `_to` is a contract that lacks a payable `receive`/`fallback` function, the call returns `ok = false`, the `require` reverts the entire transaction (rolling back all state), and the transfer can never succeed. Because there is no admin escape hatch to skip or redirect a stuck nonce, the bridged KAIA is permanently locked inside the destination bridge contract.

### Finding Description

`handleKLAYTransfer` in `BridgeTransferKLAY.sol` executes the following sequence:

1. Nonce check (`_lowerHandleNonceCheck`)
2. Operator vote (`_voteValueTransfer`) — returns early if threshold not met
3. State writes: `_setHandledRequestTxHash`, `handleNoncesToBlockNums[_requestedNonce]`, `_updateHandleNonce`
4. Emit `HandleValueTransfer`
5. **KLAY delivery**: `(bool ok, ) = _to.call.value(_value)("");`
6. `require(ok, "handleKLAYTransfer: transfer failed");` [1](#0-0) 

Because step 6 reverts the entire transaction when `ok == false`, all state writes from steps 3–4 are also rolled back. The nonce is never consumed. Every subsequent operator retry for the same nonce will hit the same revert. There is no `skipNonce`, `redirectTransfer`, or similar admin function in the contract. [2](#0-1) 

The user on the source chain controls the `_to` field via `requestKLAYTransfer(_to, _value, _extraData)`: [3](#0-2) 

No validation is performed to ensure `_to` can accept native KAIA. If `_to` is a contract without a payable fallback (e.g., a multisig, a proxy, or any contract that explicitly reverts on ETH receipt), the bridge delivery is permanently bricked for that nonce.

### Impact Explanation

The KAIA sent from the source chain is either burned (mint-burn mode) or locked in the source bridge at the time of `requestKLAYTransfer`. On the destination chain, the equivalent KAIA sits in the bridge contract and can never be delivered. There is no refund path and no admin function to redirect the transfer. The user's KAIA is permanently lost.

This matches the allowed impact gate: **unauthorized lock of KAIA** — bridged assets are permanently frozen in a system-managed contract with no recovery.

### Likelihood Explanation

Low-to-medium. A user can accidentally specify a contract address (e.g., a DAO treasury, a multisig, a DeFi protocol address) that does not implement a payable fallback. The scenario is also reachable intentionally: a user can grief the bridge by bridging KAIA to a known non-payable contract, permanently consuming bridge liquidity and blocking `recoveryBlockNumber` advancement for that nonce slot.

### Recommendation

Move the KAIA transfer **before** any state writes, or use a pull-payment pattern: record the owed amount in a mapping and let the recipient claim it separately. Alternatively, add an owner-callable `rescueStuckTransfer(uint64 nonce, address payable newRecipient)` that can redirect a permanently-failing delivery to a different address.

### Proof of Concept

1. Alice on the source chain calls `requestKLAYTransfer(contractWithNoFallback, 1 ether, "0x")` sending 1 KAIA + fee. The source bridge emits `RequestValueTransfer` with `requestNonce = N`.
2. Bridge operators observe the event and call `handleKLAYTransfer(txHash, alice, contractWithNoFallback, 1 ether, N, blockNum, "0x")` on the destination bridge.
3. Steps 1–4 execute (state written, event emitted), then `contractWithNoFallback.call.value(1 ether)("")` returns `ok = false`.
4. `require(ok, "handleKLAYTransfer: transfer failed")` reverts the transaction; all state writes are rolled back.
5. Operators retry indefinitely — every attempt reverts identically.
6. The 1 KAIA is permanently locked in the destination bridge. The source-chain KAIA is already burned/locked. No recovery is possible. [4](#0-3)

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L132-135)
```text
    function requestKLAYTransfer(address _to, uint256 _value, bytes calldata _extraData) external payable {
        uint256 feeLimit = msg.value.sub(_value);
        _requestKLAYTransfer(_to, feeLimit, _extraData);
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
