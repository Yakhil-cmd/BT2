### Title
`handledRequestTx` Mapping Is Set But Never Checked, Allowing Bridge Replay With Different Nonce — (File: `contracts/service_chain/bridge/BridgeHandledRequests.sol`)

---

### Summary

`BridgeHandledRequests.sol` declares `handledRequestTx` as a per-tx-hash replay-protection mapping and sets it on every handled transfer, but **no code in the bridge ever reads it**. The only replay guard that is actually enforced is `closedValueTransferVotes`, which is keyed by `_requestedNonce`, not by `_requestTxHash`. A malicious operator can therefore submit the same originating `_requestTxHash` a second time under a fresh, unused nonce, bypassing the nonce-based guard and causing the bridge to execute the same cross-chain transfer twice, draining bridge-held KLAY, ERC20, or ERC721 assets.

---

### Finding Description

`BridgeHandledRequests.sol` defines:

```solidity
mapping(bytes32 => bool) public handledRequestTx;

function _setHandledRequestTxHash(bytes32 _requestTxHash) internal {
    handledRequestTx[_requestTxHash] = true;
}
``` [1](#0-0) 

Every handle function (`handleKLAYTransfer`, `handleERC20Transfer`, `handleERC721Transfer`) calls `_setHandledRequestTxHash` after a successful vote, recording the originating tx hash as handled. However, **none of these functions ever reads `handledRequestTx` before proceeding**. A `require(!handledRequestTx[_requestTxHash], "already handled")` guard is entirely absent. [2](#0-1) [3](#0-2) [4](#0-3) 

The only active replay guard is `closedValueTransferVotes[_requestNonce]`, set in `_voteValueTransfer` when the operator threshold is reached:

```solidity
require(!closedValueTransferVotes[_requestNonce], "closed vote");
...
closedValueTransferVotes[_requestNonce] = true;
``` [5](#0-4) 

This guard is keyed by `_requestedNonce`, not by `_requestTxHash`. Submitting the same `_requestTxHash` with a **different, unused nonce** bypasses it entirely.

The code comment in `BridgeHandledRequests.sol` itself acknowledges the incompleteness:

> `// TODO-Klaytn-Servicechain handleTxHash can be saved after Klaytn supports it.` [6](#0-5) 

This confirms the setter was implemented as a placeholder but the enforcement check was never added, leaving `handledRequestTx` as a dead mapping — the exact structural analog of the MGD.sol `orgTaken` bug.

---

### Impact Explanation

A malicious or compromised bridge operator (semi-trusted actor) with `operatorThresholds[ValueTransfer] == 1` (the default) can:

1. Relay a legitimate cross-chain transfer: `handleKLAYTransfer(txHash_A, from, to, 100e18, nonce=N, blockNum, ...)` → 100 KLAY transferred to `to`, `closedValueTransferVotes[N] = true`.
2. Immediately replay: `handleKLAYTransfer(txHash_A, from, to, 100e18, nonce=N+1, blockNum, ...)` → `closedValueTransferVotes[N+1]` is `false`, `handledRequestTx[txHash_A]` is `true` but never read → another 100 KLAY transferred.

This can be repeated for any unused nonce, draining all KLAY (or ERC20/ERC721 tokens) held by the bridge contract. The same attack applies to `handleERC20Transfer` and `handleERC721Transfer`.

---

### Likelihood Explanation

- Default `operatorThresholds[ValueTransfer]` is `1`, so a single operator suffices.
- Operators are semi-trusted (registered by the owner), but a compromised or malicious operator key is a realistic threat for a bridge holding significant value.
- No external precondition is required beyond being a registered operator.

---

### Recommendation

Add a check at the top of each handle function before the vote:

```solidity
require(!handledRequestTx[_requestTxHash], "already handled");
```

This should be placed **before** `_voteValueTransfer` so that even partial votes on a replayed tx hash are rejected. Alternatively, key `closedValueTransferVotes` on `keccak256(_requestTxHash, _requestedNonce)` to bind the nonce and tx hash together, preventing substitution of one for the other.

---

### Proof of Concept

```
Setup:
  - Deploy Bridge (modeMintBurn=false), fund with 1000 KLAY
  - operatorThresholds[ValueTransfer] = 1 (default)
  - Attacker is a registered operator

Step 1 (legitimate):
  handleKLAYTransfer(txHash_A, alice, bob, 100e18, nonce=0, blockNum=100, "")
  → closedValueTransferVotes[0] = true
  → handledRequestTx[txHash_A] = true  (never read)
  → bob receives 100 KLAY ✓

Step 2 (replay with nonce=1):
  handleKLAYTransfer(txHash_A, alice, bob, 100e18, nonce=1, blockNum=100, "")
  → _lowerHandleNonceCheck: lowerHandleNonce(0) <= 1 ✓
  → closedValueTransferVotes[1] == false → passes "closed vote" check ✓
  → handledRequestTx[txHash_A] == true → NEVER CHECKED ✓
  → bob receives another 100 KLAY — double spend

Repeat Step 2 with nonce=2,3,... until bridge is drained.
``` [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeHandledRequests.sol (L20-25)
```text
    // TODO-Klaytn-Servicechain handleTxHash can be saved after Klaytn supports it.
    mapping(bytes32 => bool) public handledRequestTx;

    function _setHandledRequestTxHash(bytes32 _requestTxHash) internal {
        handledRequestTx[_requestTxHash] = true;
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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L34-35)
```text
    mapping(uint8 => mapping (uint64 => VotesData)) private votes; // <voteType, <nonce, VotesData>
    mapping(uint64 => bool) public closedValueTransferVotes; // <nonce, bool>
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L103-116)
```text
    function _voteValueTransfer(uint64 _requestNonce)
        internal
        returns(bool)
    {
        require(!closedValueTransferVotes[_requestNonce], "closed vote");

        bytes32 voteKey = keccak256(msg.data);
        if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
            closedValueTransferVotes[_requestNonce] = true;
            return true;
        }

        return false;
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
