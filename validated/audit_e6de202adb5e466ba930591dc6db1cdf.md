### Title
`handleERC721Transfer` Uses `transferFrom`/`mintWithTokenURI` Instead of Safe Variants, Permanently Locking Bridged ERC721 Tokens in Non-Receiver Contracts — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.handleERC721Transfer` delivers bridged ERC721 tokens to the recipient address using either `IERC721.transferFrom` (lock-unlock mode) or `ERC721MetadataMintable.mintWithTokenURI` (mint-burn mode). Neither variant invokes the `onERC721Received` callback. If the recipient `_to` is a contract that does not implement `IERC721Receiver`, the token is irrecoverably locked in that contract. The source-chain NFT has already been burned or locked in the bridge, so the asset is permanently destroyed.

---

### Finding Description

In `handleERC721Transfer`, after nonce and vote checks pass, the token is delivered via one of two paths:

```solidity
if (modeMintBurn) {
    require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
} else {
    IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
}
``` [1](#0-0) 

- **Lock-unlock path (line 69):** `IERC721.transferFrom` does not call `onERC721Received`. The OpenZeppelin v2 `ERC721.safeTransferFrom` explicitly adds this check; `transferFrom` does not.
- **Mint-burn path (line 67):** `ERC721MetadataMintable.mintWithTokenURI` internally calls `_mint`, not `_safeMint`. `_mint` does not invoke `onERC721Received`. [2](#0-1) 

The `_to` address is fully user-controlled: it is set on the source chain in `requestERC721Transfer` or `onERC721Received`, relayed by bridge operators, and passed verbatim into `handleERC721Transfer`. [3](#0-2) 

On the source chain, the NFT is either burned (`ERC721Burnable.burn`) or transferred to the bridge contract before the cross-chain request is emitted. By the time `handleERC721Transfer` executes on the counterpart chain, the source-side asset is already gone. [4](#0-3) 

---

### Impact Explanation

A user who specifies a contract address as `_to` that does not implement `IERC721Receiver` will have their bridged ERC721 token permanently locked in that contract with no recovery path. The source-chain token is already burned or escrowed in the bridge, so the asset is destroyed. This constitutes an unauthorized, irreversible loss of a bridged asset.

---

### Likelihood Explanation

Any user can trigger this by specifying a contract address (e.g., a multisig, a DAO treasury, a DeFi protocol, or any contract deployed without `onERC721Received`) as the bridge recipient. No special privilege is required. The bridge operators faithfully relay whatever `_to` was specified on the source chain; they cannot prevent the delivery to an incompatible contract.

---

### Recommendation

Replace both delivery paths with their safe equivalents:

- **Lock-unlock path:** Replace `IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId)` with `IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId)`.
- **Mint-burn path:** Replace `mintWithTokenURI` with a `safeMintWithTokenURI` variant that internally calls `_safeMint` instead of `_mint`, or add an explicit `_checkOnERC721Received` call after minting.

This mirrors the fix recommended in the external report: use `_safeMint()` instead of `_mint()`.

---

### Proof of Concept

1. User holds ERC721 token ID `42` on the parent chain.
2. User calls `requestERC721Transfer(tokenAddress, contractWithoutReceiver, 42, "0x")` on the parent-chain bridge. The token is transferred to the bridge (lock-unlock) or burned (mint-burn). A `RequestValueTransfer` event is emitted with `_to = contractWithoutReceiver`.
3. Bridge operators observe the event and call `handleERC721Transfer(..., contractWithoutReceiver, ..., 42, ...)` on the child-chain bridge.
4. In lock-unlock mode: `IERC721.transferFrom(bridge, contractWithoutReceiver, 42)` succeeds silently — no `onERC721Received` check. Token ID `42` is now owned by `contractWithoutReceiver`, which has no way to transfer it out.
5. In mint-burn mode: `mintWithTokenURI(contractWithoutReceiver, 42, uri)` calls `_mint` internally, succeeds silently — no `onERC721Received` check. Same outcome.
6. The source-chain token is permanently gone; the destination-chain token is permanently locked. The user's asset is destroyed.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L90-92)
```text
        if (modeMintBurn) {
            ERC721Burnable(_tokenAddress).burn(_tokenId);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L120-131)
```text
    // requestERC721Transfer requests transfer ERC721 to _to on relative chain.
    function requestERC721Transfer(
        address _tokenAddress,
        address _to,
        uint256 _tokenId,
        bytes memory _extraData
    )
        public
    {
        IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
        _requestERC721Transfer(_tokenAddress, msg.sender, _to, _tokenId, _extraData);
    }
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721.sol (L149-178)
```text
    /**
     * @dev Safely transfers the ownership of a given token ID to another address
     * If the target address is a contract, it must implement `onERC721Received`,
     * which is called upon a safe transfer, and return the magic value
     * `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`; otherwise,
     * the transfer is reverted.
     * Requires the msg.sender to be the owner, approved, or operator
     * @param from current owner of the token
     * @param to address to receive the ownership of the given token ID
     * @param tokenId uint256 ID of the token to be transferred
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) public {
        safeTransferFrom(from, to, tokenId, "");
    }

    /**
     * @dev Safely transfers the ownership of a given token ID to another address
     * If the target address is a contract, it must implement `onERC721Received`,
     * which is called upon a safe transfer, and return the magic value
     * `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`; otherwise,
     * the transfer is reverted.
     * Requires the msg.sender to be the owner, approved, or operator
     * @param from current owner of the token
     * @param to address to receive the ownership of the given token ID
     * @param tokenId uint256 ID of the token to be transferred
     * @param _data bytes data to send along with a safe transfer check
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public {
        transferFrom(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
```
