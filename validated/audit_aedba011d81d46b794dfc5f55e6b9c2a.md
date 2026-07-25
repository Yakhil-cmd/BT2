### Title
`handleERC721Transfer` Uses `transferFrom`/`_mint` Instead of `safeTransferFrom`/`_safeMint`, Permanently Trapping Bridged ERC721 Tokens in Non-Receiver Contracts — (File: `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

### Summary

`BridgeTransferERC721.handleERC721Transfer` delivers bridged ERC721 tokens to the destination address `_to` using bare `transferFrom` (lock/unlock mode) and `mintWithTokenURI` → `_mint` (mint/burn mode). Neither path invokes the `onERC721Received` callback on the recipient. If `_to` is a contract that does not implement `IERC721Receiver`, the bridged token is permanently trapped with no recovery path.

### Finding Description

In `BridgeTransferERC721.sol`, the settlement leg of a cross-chain ERC721 transfer is:

```solidity
if (modeMintBurn) {
    require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
} else {
    IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
}
``` [1](#0-0) 

`mintWithTokenURI` calls the internal `_mint`:

```solidity
function mintWithTokenURI(address to, uint256 tokenId, string memory tokenURI) public onlyMinter returns (bool) {
    _mint(to, tokenId);   // ← no _safeMint, no onERC721Received
    ...
}
``` [2](#0-1) 

`_mint` only updates storage and emits `Transfer`; it never calls `onERC721Received`:

```solidity
function _mint(address to, uint256 tokenId) internal {
    _tokenOwner[tokenId] = to;
    _ownedTokensCount[to].increment();
    emit Transfer(address(0), to, tokenId);
}
``` [3](#0-2) 

Likewise, `transferFrom` calls `_transferFrom` which also never invokes `onERC721Received`. Only `safeTransferFrom` performs the `_checkOnERC721Received` guard:

```solidity
function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public {
    transferFrom(from, to, tokenId);
    require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
}
``` [4](#0-3) 

The bridge's own `onERC721Received` uses a non-standard signature `(address _from, uint256 _tokenId, address _to, bytes _extraData)` — different from the ERC721 standard `(address operator, address from, uint256 tokenId, bytes data)` — so the bridge itself would also fail a standard `safeTransferFrom` check: [5](#0-4) 

### Impact Explanation

When `handleERC721Transfer` settles a cross-chain transfer to a contract `_to` that does not implement `IERC721Receiver.onERC721Received`, the token is minted or transferred into that contract with no revert and no notification. The token is owned by `_to` but `_to` has no mechanism to move it. The bridged ERC721 asset is permanently lost. The source-chain token was already burned or locked, so the loss is irreversible.

### Likelihood Explanation

The destination address `_to` is supplied by the user on the source chain at request time. Users commonly bridge to multisig wallets, DAO treasuries, escrow contracts, or other smart contracts that hold assets but do not implement the ERC721 receiver interface. The bridge operator relays the address verbatim with no on-chain check that `_to` can accept ERC721 tokens. This is a realistic, low-friction trigger requiring no special privilege.

### Recommendation

- **Short term:** Replace `transferFrom` with `safeTransferFrom` and replace `mintWithTokenURI` (which calls `_mint`) with a `safeMint` variant (calling `_safeMint`) in `handleERC721Transfer`. This ensures the EVM reverts if `_to` cannot accept ERC721 tokens, preventing silent asset loss.
- **Long term:** Audit all bridge settlement paths (`handleERC20Transfer`, `handleKLAYTransfer`) for analogous missing safety checks, and add integration tests that assert settlement to a non-receiver contract reverts rather than silently trapping assets.

### Proof of Concept

1. Alice holds ERC721 token ID 42 on the child chain and calls `requestERC721Transfer` specifying `_to = address(MyContract)` on the parent chain, where `MyContract` is a contract without `onERC721Received`.
2. The bridge operator observes the `RequestValueTransferEncoded` event and calls `handleERC721Transfer(..., _to=MyContract, ...)` on the parent bridge.
3. In mint/burn mode: `mintWithTokenURI(MyContract, 42, uri)` → `_mint(MyContract, 42)` succeeds silently. Token 42 is now owned by `MyContract`.
4. In lock/unlock mode: `IERC721(token).transferFrom(bridge, MyContract, 42)` succeeds silently. Token 42 is now owned by `MyContract`.
5. `MyContract` has no `onERC721Received` and no way to call `transferFrom` on the token. Token 42 is permanently trapped.
6. The child-chain token was burned (or locked in the child bridge). Alice has lost her asset with no recovery path.

The relevant settlement code is at: [6](#0-5)

### Citations

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

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721MetadataMintable.sol (L19-23)
```text
    function mintWithTokenURI(address to, uint256 tokenId, string memory tokenURI) public onlyMinter returns (bool) {
        _mint(to, tokenId);
        _setTokenURI(tokenId, tokenURI);
        return true;
    }
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721.sol (L176-179)
```text
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public {
        transferFrom(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721.sol (L210-218)
```text
    function _mint(address to, uint256 tokenId) internal {
        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _tokenOwner[tokenId] = to;
        _ownedTokensCount[to].increment();

        emit Transfer(address(0), to, tokenId);
    }
```

**File:** contracts/service_chain/IERC721BridgeReceiver.sol (L19-21)
```text
contract IERC721BridgeReceiver {
    function onERC721Received(address _from, uint256 _tokenId, address _to, bytes memory _extraData) public;
}
```
