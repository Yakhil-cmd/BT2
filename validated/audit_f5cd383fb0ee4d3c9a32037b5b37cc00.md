### Title
Bridge ERC721 Handle Transfer Uses `transferFrom`/`_mint` Without Receiver Check, Permanently Locking Bridged NFTs — (File: contracts/service_chain/bridge/BridgeTransferERC721.sol)

---

### Summary

`handleERC721Transfer` in `BridgeTransferERC721.sol` delivers bridged ERC721 tokens to the recipient using `IERC721.transferFrom` (non-mint-burn mode) or `ERC721MetadataMintable.mintWithTokenURI` (mint-burn mode). Neither path invokes `onERC721Received` on the recipient. If the destination address is a contract that does not implement `IERC721Receiver`, the NFT is irrecoverably locked there after the bridge nonce is consumed and the handle-nonce window advances past it.

---

### Finding Description

`BridgeTransferERC721.sol` lines 66–70:

```solidity
if (modeMintBurn) {
    require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
} else {
    IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
}
```

- **Non-mint-burn path**: `IERC721.transferFrom` transfers the token without calling `_checkOnERC721Received`. The ERC721 standard (EIP-721) mandates that any implementation-specific delivery to a contract address MUST still invoke `onERC721Received` and revert if the selector is not returned.
- **Mint-burn path**: `mintWithTokenURI` internally calls OpenZeppelin v2's `_mint`, which also skips the receiver callback. The safe variant `_safeMint` would call `_checkOnERC721Received`.

The bridge's `_updateHandleNonce` permanently advances `lowerHandleNonce` past the processed nonce and deletes `closedValueTransferVotes[nonce]`. Once the handle succeeds on-chain (even if the token is locked in an incompatible contract), the nonce is consumed and the transfer cannot be replayed or recovered through the bridge protocol.

---

### Impact Explanation

A user who initiates a cross-chain ERC721 transfer on the source chain and specifies a contract address (e.g., a multisig, DAO treasury, or any contract without `onERC721Received`) as `_to` will have their NFT permanently locked in that contract on the destination chain. The bridge nonce is consumed, the `HandleValueTransfer` event is emitted, and the bridge considers the transfer complete. The bridged ERC721 asset is unrecoverable through any bridge mechanism.

**Corrupted value**: the ERC721 token ownership record — `_tokenOwner[_tokenId]` in the destination ERC721 contract — is set to a contract address that can never move the token, constituting permanent loss of a bridged asset.

---

### Likelihood Explanation

Any user can trigger this by specifying a contract address as the recipient on the source chain. Common real-world scenarios include:
- Sending to a Gnosis Safe or other multisig that was not deployed with ERC721 receiver support.
- Sending to a protocol contract (staking vault, DAO) that holds KAIA but has no NFT receiver hook.
- Sending to a contract address that exists on the destination chain but was not designed to receive NFTs.

No privileged access is required; the source-chain `requestERC721Transfer` / `onERC721Received` entry points are open to any token holder.

---

### Recommendation

Replace both delivery paths with their safe equivalents:

```solidity
if (modeMintBurn) {
    // Use safeMint (calls onERC721Received if _to is a contract)
    require(ERC721MetadataMintable(_tokenAddress).safeMintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
} else {
    // Use safeTransferFrom (calls onERC721Received if _to is a contract)
    IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
}
```

If the recipient contract does not implement `onERC721Received`, the transaction reverts, the nonce is not consumed, and the bridge operator can retry or the user can specify a different recipient.

---

### Proof of Concept

1. User calls `requestERC721Transfer(tokenAddr, contractWithoutReceiver, tokenId, extraData)` on the source-chain bridge. The NFT is locked/burned on the source chain and a `RequestValueTransfer` event is emitted.
2. Bridge operators observe the event and call `handleERC721Transfer(txHash, from, contractWithoutReceiver, tokenAddr, tokenId, nonce, blockNum, uri, extraData)` on the destination-chain bridge.
3. The bridge passes `_lowerHandleNonceCheck`, `_voteValueTransfer`, `_setHandledRequestTxHash`, and `_updateHandleNonce` — the nonce is permanently consumed.
4. In non-mint-burn mode: `IERC721(tokenAddr).transferFrom(address(this), contractWithoutReceiver, tokenId)` succeeds (no receiver check). The NFT is now owned by `contractWithoutReceiver`.
5. In mint-burn mode: `mintWithTokenURI(contractWithoutReceiver, tokenId, uri)` calls `_mint`, which succeeds without calling `onERC721Received`. The NFT is minted into `contractWithoutReceiver`.
6. `contractWithoutReceiver` has no `onERC721Received` and no way to call `transferFrom`/`safeTransferFrom` on the NFT. The token is permanently locked. The bridge nonce window has advanced; no replay is possible. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
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

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721.sol (L176-179)
```text
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public {
        transferFrom(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }
```
