### Title
Deregistered Token Status Ignored in `handleERC20Transfer` and `handleERC721Transfer` — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

The `handleERC20Transfer` and `handleERC721Transfer` functions in the Kaia service-chain bridge contracts do not verify that the token being handled is still registered. After the owner deregisters a token (the bridge-native analog of "rejecting a service"), bridge operators can still call these handle functions to mint or transfer the deregistered token to arbitrary recipients, bypassing the deregistration invariant.

---

### Finding Description

`BridgeTokens.sol` maintains a `registeredTokens` mapping and exposes `deregisterToken` to remove a token from the bridge. The outbound request path correctly enforces registration via the `onlyRegisteredToken` modifier on `_requestERC20Transfer` and `_requestERC721Transfer`.

However, the inbound handle path — `handleERC20Transfer` and `handleERC721Transfer` — applies **no such check**:

```solidity
// BridgeTransferERC20.sol L32-73
function handleERC20Transfer(
    bytes32 _requestTxHash,
    address _from,
    address _to,
    address _tokenAddress,   // ← no onlyRegisteredToken guard
    uint256 _value,
    uint64 _requestedNonce,
    uint64 _requestedBlockNumber,
    bytes memory _extraData
)
    public
    onlyOperators          // only guard is operator membership
{
    ...
    if (modeMintBurn) {
        require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
    } else {
        IERC20(_tokenAddress).safeTransfer(_to, _value);
    }
}
```

The same pattern exists in `handleERC721Transfer`.

The `_requestTxHash` parameter is recorded via `_setHandledRequestTxHash` but is **never verified** against an actual on-chain request event. Operators can supply any 32-byte value as the hash. The only replay protection is `closedValueTransferVotes[_requestNonce]`, which prevents the same nonce from being executed twice — but does not prevent operators from choosing a fresh nonce for a fabricated request.

---

### Impact Explanation

After the owner calls `deregisterToken(T)` to halt all bridge activity for token `T`:

- **Mint/burn mode**: Operators can call `handleERC20Transfer` with `_tokenAddress = T`, a fabricated `_requestTxHash`, and a fresh nonce. If the bridge contract still holds ERC20Mintable rights for `T`, it will mint `_value` tokens to `_to`. This is an unauthorized mint of bridged assets.
- **Lock/unlock mode**: If the bridge still holds a balance of `T`, operators can drain it to any address via `safeTransfer`.

The corrupted value is the token balance or total supply of the deregistered bridged asset. The invariant broken is: *"a deregistered token cannot be transferred or minted through the bridge."*

---

### Likelihood Explanation

Triggering this requires `operatorThresholds[ValueTransfer]` operators to vote on the same fabricated call. The default threshold is 1 (set in the constructor), meaning a single operator suffices. Even at higher thresholds, operators are semi-trusted actors registered by the owner; a mistaken or malicious operator set can exploit this window between deregistration and any off-chain remediation. The owner deregistering a token is a normal operational action (e.g., migrating to a new token contract), making the vulnerable window realistic.

---

### Recommendation

Add the `onlyRegisteredToken` modifier to `handleERC20Transfer` and `handleERC721Transfer`, mirroring the guard already present on the request path:

```solidity
function handleERC20Transfer(
    ...
    address _tokenAddress,
    ...
)
    public
    onlyOperators
    onlyRegisteredToken(_tokenAddress)   // ← add this
{
    ...
}
```

Apply the same fix to `handleERC721Transfer`. If legitimate pending requests for a token must still be completable after deregistration, introduce a separate `pendingDeregister` state (analogous to the external report's recommendation of checking `ServiceRejected`) rather than removing the guard entirely.

---

### Proof of Concept

1. Deploy `Bridge` in mint/burn mode. Register token `T`. Owner grants the bridge minting rights on `T`.
2. Owner calls `deregisterToken(T)` — intent is to stop all `T` transfers.
3. Operator (threshold = 1 by default) calls:
   ```solidity
   bridge.handleERC20Transfer(
       keccak256("fake"),   // fabricated hash
       attacker,            // _from (irrelevant)
       attacker,            // _to
       address(T),          // deregistered token
       1_000_000e18,        // _value
       999,                 // fresh nonce above upperHandleNonce
       block.number,
       ""
   );
   ```
4. `onlyOperators` passes. `_lowerHandleNonceCheck` passes (nonce 999 > lowerHandleNonce). `_voteValueTransfer` passes (threshold met). `ERC20Mintable(T).mint(attacker, 1_000_000e18)` executes.
5. Attacker receives 1,000,000 units of the deregistered bridged token, despite the owner's deregistration. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L32-50)
```text
    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
    }

    modifier onlyNotRegisteredToken(address _token) {
        require(registeredTokens[_token] == address(0), "allowed token");
        _;
    }

    modifier onlyLockedToken(address _token) {
        require(lockedTokens[_token], "unlocked token");
        _;
    }

    modifier onlyUnlockedToken(address _token) {
        require(!lockedTokens[_token], "locked token");
        _;
    }
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L73-92)
```text
    // deregisterToken can remove the token in registeredToken list.
    function deregisterToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
    {
        delete registeredTokens[_token];
        delete lockedTokens[_token];

        uint idx = indexOfTokens[_token];
        delete indexOfTokens[_token];

        if (idx < registeredTokenList.length-1) {
            registeredTokenList[idx] = registeredTokenList[registeredTokenList.length-1];
            indexOfTokens[registeredTokenList[idx]] = idx;
        }
        registeredTokenList.length--;

        emit TokenDeregistered(_token);
    }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L102-116)
```text
    // _voteValueTransfer votes value transfer transaction with the operator.
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
