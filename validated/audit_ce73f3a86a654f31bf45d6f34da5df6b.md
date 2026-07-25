### Title
Bridge Operator Can Redirect Any Value Transfer to Attacker-Controlled Address via Unvalidated `_to` Parameter at Default Threshold-1 — (`contracts/service_chain/bridge/BridgeOperator.sol`, `BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge uses a multi-operator voting model to authorize cross-chain value transfers. The `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` functions accept a caller-supplied `_to` address that is **never validated against the original on-chain request**. The vote key is `keccak256(msg.data)`, so operators who supply different `_to` values cast independent, non-aggregating votes. The constructor hard-codes `operatorThresholds[ValueTransfer] = 1`, meaning a single operator's call immediately closes the vote and executes the transfer. Any one of the up to 12 registered operators can therefore call a handle function with `_to = attacker_address` for any pending nonce and irrevocably redirect the bridged assets before any other operator acts.

---

### Finding Description

**Root cause — `BridgeOperator.sol` constructor and `_voteValueTransfer`:**

```solidity
// BridgeOperator.sol constructor
for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
    operatorThresholds[uint8(i)] = 1;   // ← default threshold = 1
}
``` [1](#0-0) 

```solidity
function _voteValueTransfer(uint64 _requestNonce) internal returns(bool) {
    require(!closedValueTransferVotes[_requestNonce], "closed vote");
    bytes32 voteKey = keccak256(msg.data);   // ← entire calldata, including _to
    if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
        closedValueTransferVotes[_requestNonce] = true;
        return true;
    }
    return false;
}
``` [2](#0-1) 

Because `voteKey = keccak256(msg.data)`, two operators calling `handleKLAYTransfer` with different `_to` values produce **different vote keys** and their votes never aggregate. With threshold = 1, the very first operator call — regardless of which `_to` it specifies — immediately satisfies the threshold, closes the vote, and executes the transfer.

**Affected handle functions (no `_to` validation):**

`handleKLAYTransfer` in `BridgeTransferKLAY.sol`:
```solidity
function handleKLAYTransfer(
    bytes32 _requestTxHash, address _from, address payable _to,
    uint256 _value, uint64 _requestedNonce, uint64 _requestedBlockNumber,
    bytes memory _extraData
) public onlyOperators nonReentrant {
    _lowerHandleNonceCheck(_requestedNonce);
    if (!_voteValueTransfer(_requestedNonce)) { return; }
    ...
    (bool ok, ) = _to.call.value(_value)("");   // ← _to is attacker-controlled
``` [3](#0-2) 

`handleERC20Transfer` in `BridgeTransferERC20.sol`:
```solidity
if (modeMintBurn) {
    require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
} else {
    IERC20(_tokenAddress).safeTransfer(_to, _value);   // ← _to is attacker-controlled
}
``` [4](#0-3) 

`handleERC721Transfer` in `BridgeTransferERC721.sol`:
```solidity
if (modeMintBurn) {
    require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), ...);
} else {
    IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
}
``` [5](#0-4) 

---

### Impact Explanation

A malicious operator calls `handleKLAYTransfer(txHash, from, ATTACKER, value, nonce, blockNum, data)` for any pending bridge nonce. With threshold = 1 the call immediately:

1. Sets `closedValueTransferVotes[nonce] = true` — all subsequent handle calls for that nonce revert with `"closed vote"`.
2. Transfers `value` KLAY (or mints/transfers ERC-20/ERC-721) to `ATTACKER` instead of the legitimate recipient.

The legitimate operator's subsequent call is permanently blocked. The bridged asset is irrecoverably lost to the attacker. This satisfies the allowed-impact gate: **unauthorized transfer of bridged assets (KAIA/ERC-20/ERC-721)**.

---

### Likelihood Explanation

The bridge supports up to 12 operators (`MAX_OPERATOR = 12`). [6](#0-5) 

The default threshold is 1, so no coordination is required — any single operator can act unilaterally. The attack requires only that one of the registered operators is malicious or compromised. This is the direct analog of the external bug: multiple accounts hold the privileged role, and the protocol does not prevent any one of them from claiming pre-committed funds for themselves. Likelihood: **Medium** (requires one malicious/compromised operator out of up to 12).

---

### Recommendation

1. **Validate `_to` on-chain**: Record the intended recipient in the `RequestValueTransfer` event and require the destination bridge to verify `_to` matches the emitted value, or include a commitment hash in the request nonce.
2. **Raise the default threshold**: Set `operatorThresholds[ValueTransfer]` to `ceil(N/2) + 1` (majority) by default, so no single operator can unilaterally execute a transfer.
3. **Bind vote key to nonce only, not full calldata**: Alternatively, separate the "which nonce to handle" vote from the "what parameters to use" data, and require all operators to agree on parameters before execution.

---

### Proof of Concept

```
Setup:
  - Bridge deployed with operators [Alice, Bob, Mallory], threshold = 1 (default)
  - User locks 100 KLAY on source chain → RequestValueTransfer(nonce=5, from=User, to=Victim, value=100)

Attack:
  1. Mallory observes the RequestValueTransfer event.
  2. Mallory calls:
       handleKLAYTransfer(txHash, User, Mallory_address, 100, 5, blockNum, "")
  3. _voteValueTransfer(5):
       voteKey = keccak256(msg.data)  // includes Mallory_address as _to
       voteCounts[voteKey]++ → 1 >= threshold(1) → returns true
       closedValueTransferVotes[5] = true
  4. 100 KLAY transferred to Mallory_address.
  5. Alice later calls handleKLAYTransfer(..., Victim, 100, 5, ...) → reverts "closed vote".

Result: Victim receives 0 KLAY. Mallory steals 100 KLAY.
```

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L37-41)
```text
    uint64 public constant MAX_OPERATOR = 12;
    mapping(address => bool) public operators;
    address[] public operatorList;

    mapping(uint8 => uint8) public operatorThresholds; // <vote type, uint8>
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-57)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-99)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```
