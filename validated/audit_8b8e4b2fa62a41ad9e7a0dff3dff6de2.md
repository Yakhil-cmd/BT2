### Title
Permanent KAIA Lock via Unrecoverable Failed `handleKLAYTransfer` — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`handleKLAYTransfer` in the service-chain bridge performs all nonce-accounting state writes **before** the external KAIA push to `_to`, then hard-reverts the entire transaction if that push fails. Because the revert rolls back every state change, the nonce is never consumed and `lowerHandleNonce` can never advance past it. There is no admin escape-hatch to skip or redirect a stuck nonce. Any KAIA locked in the source-chain bridge for that request is permanently unrecoverable.

---

### Finding Description

`handleKLAYTransfer` executes in this order:

```
_lowerHandleNonceCheck(_requestedNonce)          // gate: nonce >= lowerHandleNonce
_voteValueTransfer(_requestedNonce)              // multi-sig quorum
_setHandledRequestTxHash(_requestTxHash)         // marks tx hash handled
handleNoncesToBlockNums[_requestedNonce] = ...   // records block number
_updateHandleNonce(_requestedNonce)              // advances lowerHandleNonce
emit HandleValueTransfer(...)
(bool ok, ) = _to.call.value(_value)("");        // external push
require(ok, "handleKLAYTransfer: transfer failed"); // REVERTS on failure
``` [1](#0-0) 

When `_to` is a contract whose fallback reverts or is absent, `ok == false` and `require` causes the entire transaction to revert. Solidity reverts roll back **all** state changes atomically, so:

- `handledRequestTx[_requestTxHash]` is unset
- `handleNoncesToBlockNums[_requestedNonce]` is unset
- `lowerHandleNonce` is not advanced

`_updateHandleNonce` advances `lowerHandleNonce` by scanning consecutive entries in `handleNoncesToBlockNums` starting from the current `lowerHandleNonce`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) { ... }
lowerHandleNonce = i;
``` [2](#0-1) 

Because nonce N's entry is always rolled back, `lowerHandleNonce` is permanently pinned at N. `recoveryBlockNumber` also never advances past N's block.

The contract exposes no `skipNonce`, `redirectPayment`, or any other owner/operator function that could clear the stuck slot. The only owner-level controls are `setRunningStatus`, `lockKLAY`/`unlockKLAY`, and `setFeeReceiver` — none of which can unblock a stuck nonce. [3](#0-2) [4](#0-3) 

The same structural flaw exists in `handleERC20Transfer` (the `mint` or `safeTransfer` call after state writes can also revert): [5](#0-4) 

---

### Impact Explanation

**Bridged KAIA is permanently locked with no recovery path.**

On the source chain the user's KAIA is held by the bridge contract from the moment `requestKLAYTransfer` / `_requestKLAYTransfer` succeeds: [6](#0-5) 

If the destination-side `handleKLAYTransfer` can never succeed (because `_to` always reverts), the source-chain KAIA is permanently stranded. The bridge operators cannot skip the nonce; the bridge owner cannot redirect the payment; no timeout mechanism exists. The value is effectively burned from the user's perspective while remaining locked in the bridge contract.

Secondary effect: `recoveryBlockNumber` is frozen at the stuck nonce's block, causing the `ValueTransferRecovery` subsystem to re-scan from that block on every recovery cycle indefinitely. [7](#0-6) 

---

### Likelihood Explanation

The trigger is any `_to` address that cannot accept a plain KAIA transfer:

- A contract with no `payable` fallback (the most common Solidity default).
- A contract whose `receive`/fallback explicitly reverts.
- A contract that runs out of gas in its fallback (the `.call` forwards all remaining gas, but the callee can still revert).

A user can reach this state accidentally (e.g., specifying a multisig or DAO contract as recipient that was not designed to receive raw KAIA). An adversary can reach it deliberately at the cost of their own KAIA, permanently pinning `lowerHandleNonce` and `recoveryBlockNumber`. The cost to the attacker is the bridged amount; the damage is permanent loss of those funds and degraded recovery performance.

---

### Recommendation

1. **Separate asset delivery from nonce accounting.** Commit the nonce as handled unconditionally; if the push fails, emit a `HandleValueTransferFailed` event and allow the recipient to pull funds via a separate claim function (pull-payment pattern).

2. **Add an owner-callable `skipNonce(uint64 nonce)` escape-hatch** that marks a nonce as handled without sending value, so operators can unblock the queue when a recipient is permanently non-payable.

3. **Validate `_to` before committing state.** Check `_to.code.length == 0` or use a try/catch (Solidity ≥ 0.6) to handle the failure gracefully rather than reverting the entire transaction.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.5.6;

// Recipient that always rejects KAIA
contract RejectKAIA {
    function() external payable { revert("no KAIA"); }
}

// Attack sequence (pseudo-code):
// 1. Deploy RejectKAIA on the destination chain → address rejectAddr
// 2. On the source chain, call:
//      bridge.requestKLAYTransfer{value: 1 ether}(rejectAddr, 1 ether, "")
//    → source bridge locks 1 KAIA, emits RequestValueTransfer(nonce=N)
// 3. Bridge operators observe the event and call on the destination chain:
//      bridge.handleKLAYTransfer(txHash, from, rejectAddr, 1e18, N, blockNum, "")
//    → _to.call.value(1e18)("") → RejectKAIA.fallback() reverts
//    → require(ok) fires → entire tx reverts
//    → handleNoncesToBlockNums[N] is NOT set
//    → lowerHandleNonce stays at N forever
// 4. No matter how many times operators retry, the result is identical.
// 5. lowerHandleNonce == N permanently; recoveryBlockNumber frozen at N-1's block.
// 6. The 1 KAIA is permanently locked in the source-chain bridge.
```

Root cause line: [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L39-59)
```text
    // lockKLAY can to prevent request KLAY transferring.
    function lockKLAY()
        external
        onlyOwner
        unlockedKLAY
    {
        isLockedKLAY = true;

        emit KLAYLocked();
    }

    // unlockToken can allow request KLAY transferring.
    function unlockKLAY()
        external
        onlyOwner
        lockedKLAY
    {
        isLockedKLAY = false;

        emit KLAYUnlocked();
    }
```

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L102-124)
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
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L33-34)
```text
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
    mapping(uint64 => uint64) public handleNoncesToBlockNums;  // <request nonce> => <request blockNum>
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L50-65)
```text
    // setRunningStatus can allow or disallow the value transfer request.
    function setRunningStatus(bool _status)
        public
        onlyOwner
    {
        isRunning = _status;
        emit RunningStatusChanged(_status);
    }

    // start is an alias of setRunningStatus created for backwards compatibility.
    function start(bool _status)
        external
        onlyOwner
    {
        setRunningStatus(_status);
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
