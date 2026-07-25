### Title
Missing `onlyRegisteredToken` Validation in `handleERC20Transfer` and `handleERC721Transfer` Allows Operators to Drain Arbitrary Tokens from the Bridge — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC20::handleERC20Transfer()` and `BridgeTransferERC721::handleERC721Transfer()` accept a caller-supplied `_tokenAddress` parameter and immediately use it to transfer tokens out of the bridge contract, without verifying that the address belongs to the bridge's registered-token whitelist. The deposit-side counterparts (`_requestERC20Transfer`, `_requestERC721Transfer`) both enforce `onlyRegisteredToken` and `onlyUnlockedToken`, but the handle (withdrawal) side omits these guards entirely. Any operator — or a set of operators meeting the configured threshold — can therefore supply an arbitrary token address and drain tokens the bridge holds that were never registered, have been deregistered, or are currently locked.

---

### Finding Description

`_requestERC20Transfer` (the deposit path) is decorated with both `onlyRegisteredToken(_tokenAddress)` and `onlyUnlockedToken(_tokenAddress)`:

```solidity
// BridgeTransferERC20.sol L76-86
function _requestERC20Transfer(...)
    internal
    onlyRegisteredToken(_tokenAddress)   // ← enforced on deposit
    onlyUnlockedToken(_tokenAddress)
```

`handleERC20Transfer` (the withdrawal path) carries only `onlyOperators` and performs no token-whitelist check before executing the transfer:

```solidity
// BridgeTransferERC20.sol L32-73
function handleERC20Transfer(
    bytes32 _requestTxHash,
    address _from,
    address _to,
    address _tokenAddress,   // ← completely unvalidated
    uint256 _value,
    uint64  _requestedNonce,
    uint64  _requestedBlockNumber,
    bytes memory _extraData
)
    public
    onlyOperators            // ← only guard
{
    ...
    if (modeMintBurn) {
        require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
    } else {
        IERC20(_tokenAddress).safeTransfer(_to, _value);   // ← arbitrary token drained
    }
}
```

The same asymmetry exists in `BridgeTransferERC721::handleERC721Transfer` vs `_requestERC721Transfer`.

The `registeredTokens` mapping in `BridgeTokens` is the intended whitelist:

```solidity
// BridgeTokens.sol L32-35
modifier onlyRegisteredToken(address _token) {
    require(registeredTokens[_token] != address(0), "not allowed token");
    _;
}
```

Because `handleERC20Transfer` never invokes this modifier, the whitelist is enforced only on the way in, not on the way out.

---

### Impact Explanation

**Non-mintBurn mode:** The bridge holds ERC-20 balances as escrow. An operator can call `handleERC20Transfer` with any token address the bridge holds — including tokens that were deregistered, never registered, or locked — and transfer the full balance to an arbitrary `_to` address. This constitutes an unauthorized transfer of bridged assets.

**MintBurn mode:** The bridge holds minter roles on counterpart tokens. An operator can call `handleERC20Transfer` with any token for which the bridge has the minter role, minting an arbitrary amount to any address. This constitutes unauthorized minting of bridged assets.

The same impact applies to ERC-721 tokens via `handleERC721Transfer`.

---

### Likelihood Explanation

The `onlyOperators` guard reduces the attack surface to registered bridge operators. However:

1. The default operator threshold is 1 (tests explicitly raise it to 2 to test multi-sig behavior), meaning a single operator can execute the transfer unilaterally.
2. Operators are semi-trusted relayers, not fully privileged admins. The registered-token whitelist exists precisely to bound what operators can move; the missing check defeats that bound.
3. A compromised or malicious operator key is a realistic threat model for a cross-chain bridge.

---

### Recommendation

Add `onlyRegisteredToken(_tokenAddress)` (and optionally `onlyUnlockedToken(_tokenAddress)`) to both `handleERC20Transfer` and `handleERC721Transfer`, mirroring the guards already present on the deposit side:

```solidity
function handleERC20Transfer(
    ...
    address _tokenAddress,
    ...
)
    public
    onlyOperators
    onlyRegisteredToken(_tokenAddress)   // add this
    onlyUnlockedToken(_tokenAddress)     // add this
{
    ...
}
```

Apply the same fix to `handleERC721Transfer` in `BridgeTransferERC721.sol`.

---

### Proof of Concept

1. Deploy `Bridge` (non-mintBurn mode). Register `TokenA`. Fund the bridge with 1000 `TokenA` and 500 `TokenB` (unregistered).
2. Register an operator with threshold = 1.
3. Operator calls:
   ```solidity
   bridge.handleERC20Transfer(
       keccak256("fake_tx"),   // unused request hash
       address(0),             // from (irrelevant)
       attacker,               // to
       address(TokenB),        // _tokenAddress — NOT registered
       500e18,                 // _value
       99,                     // unused nonce >= lowerHandleNonce
       block.number,
       ""
   );
   ```
4. Bridge executes `IERC20(TokenB).safeTransfer(attacker, 500e18)`.
5. Attacker receives 500 `TokenB` that was never part of any legitimate cross-chain request. The bridge's `registeredTokens` mapping was never consulted.

The same steps work with `TokenA` after it is deregistered or locked, bypassing the lock/deregister protections entirely on the handle path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-86)
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
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L32-35)
```text
    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L74-84)
```text
    function _requestERC721Transfer(
        address _tokenAddress,
        address _from,
        address _to,
        uint256 _tokenId,
        bytes memory _extraData
    )
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
```
