### Title
Operator Can Supply Arbitrary `_tokenAddress` in `handleERC20Transfer` / `handleERC721Transfer` Without Registered-Token Validation — (File: `contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

`handleERC20Transfer` and `handleERC721Transfer` in the Kaia service-chain bridge accept a caller-supplied `_tokenAddress` parameter with no check that it belongs to the registered token list. Because the default operator threshold is **1**, a single bridge operator can call either function with an arbitrary token address and cause the bridge to transfer (or mint) any ERC20/ERC721 token it holds or has minter rights over.

---

### Finding Description

`BridgeOperator.sol` initialises every vote-type threshold to `1`:

```solidity
constructor() internal {
    for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
        operatorThresholds[uint8(i)] = 1;   // single operator suffices
    }
    operators[msg.sender] = true;
    ...
}
``` [1](#0-0) 

`_voteValueTransfer` uses `keccak256(msg.data)` as the vote key and returns `true` as soon as the vote count reaches the threshold:

```solidity
bytes32 voteKey = keccak256(msg.data);
if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
    closedValueTransferVotes[_requestNonce] = true;
    return true;
}
``` [2](#0-1) 

With threshold = 1, the very first operator call reaches consensus and executes the transfer.

`handleERC20Transfer` accepts `_tokenAddress` as a free parameter and performs **no** `onlyRegisteredToken` check before transferring or minting:

```solidity
function handleERC20Transfer(
    bytes32 _requestTxHash,
    address _from,
    address _to,
    address _tokenAddress,          // ← no onlyRegisteredToken guard
    uint256 _value,
    uint64 _requestedNonce,
    ...
) public onlyOperators {
    ...
    if (modeMintBurn) {
        require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
    } else {
        IERC20(_tokenAddress).safeTransfer(_to, _value);
    }
}
``` [3](#0-2) 

The **request** side enforces the invariant correctly:

```solidity
function _requestERC20Transfer(...)
    internal
    onlyRegisteredToken(_tokenAddress)   // ← guard present here
    onlyUnlockedToken(_tokenAddress)
``` [4](#0-3) 

The same asymmetry exists in `handleERC721Transfer`: [5](#0-4) 

---

### Impact Explanation

**Lock/transfer mode (`modeMintBurn = false`):** The bridge holds ERC20 balances of every registered token (and may incidentally hold other tokens sent to it). A single operator can call `handleERC20Transfer` with any token address and any `_value`, draining the bridge's balance of that token to an arbitrary `_to` address. The `_requestTxHash` can be any unused hash; `_requestedNonce` just needs to be above `lowerHandleNonce`.

**Mint/burn mode (`modeMintBurn = true`):** The bridge holds the `MinterRole` on registered tokens. Because `_tokenAddress` is unchecked, an operator can call `handleERC20Transfer` with any `ERC20Mintable` contract for which the bridge has minter rights, minting an arbitrary `_value` to any `_to` address — an unbounded token inflation attack.

Corrupted/stolen value: the full ERC20/ERC721 balance held by the bridge, or unlimited minted supply of any token where the bridge is a minter.

---

### Likelihood Explanation

The default threshold is **1**, so no collusion is required — a single registered operator is sufficient. Operators are semi-trusted (they are registered by the bridge owner, not by users), but the bridge design explicitly contemplates multiple operators and a configurable threshold precisely to limit single-operator risk. The missing guard defeats that intent even before the threshold is raised.

---

### Recommendation

Add `onlyRegisteredToken(_tokenAddress)` and `onlyUnlockedToken(_tokenAddress)` modifiers to `handleERC20Transfer` and `handleERC721Transfer`, mirroring the guards already present on the request side:

```solidity
function handleERC20Transfer(
    ...
    address _tokenAddress,
    ...
)
    public
    onlyOperators
    onlyRegisteredToken(_tokenAddress)   // add
    onlyUnlockedToken(_tokenAddress)     // add
{
```

For `handleERC721Transfer`, apply the same modifiers.

---

### Proof of Concept

Preconditions: bridge deployed with default threshold (1), one operator registered, bridge holds 1 000 USDC (a registered token) and 500 WETH (an unregistered token accidentally sent to it).

```solidity
// Attacker is the single registered operator.
// Step 1: drain unregistered WETH (lock mode)
bridge.handleERC20Transfer(
    bytes32(uint256(0xdead)),   // fresh unused tx hash
    address(0),                 // from (irrelevant)
    attacker,                   // to
    address(WETH),              // _tokenAddress — NOT registered
    500e18,                     // _value
    999,                        // nonce above lowerHandleNonce
    block.number,
    ""
);
// Succeeds: threshold=1, no registered-token check → WETH transferred to attacker.

// Step 2 (mint mode): mint unlimited registered token
bridge.handleERC20Transfer(
    bytes32(uint256(0xbeef)),
    address(0),
    attacker,
    address(USDC),              // registered, bridge is minter
    type(uint256).max,          // arbitrary amount
    1000,
    block.number,
    ""
);
// Succeeds: ERC20Mintable(USDC).mint(attacker, type(uint256).max) called.
```

Both calls succeed because `handleERC20Transfer` never checks `onlyRegisteredToken` and the default threshold of 1 means the first operator vote immediately executes the transfer. [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-61)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }

        operators[msg.sender] = true;
        operatorList.push(msg.sender);
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-73)
```text
    function handleERC20Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
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
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-87)
```text
    function _requestERC20Transfer(
        address _tokenAddress,
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L29-71)
```text
    function handleERC721Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _tokenId,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        string memory _tokenURI,
        bytes memory _extraData
    )
        public
        onlyOperators
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
    }
```
