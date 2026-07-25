### Title
`handleERC721Transfer` Uses `transferFrom` Instead of `safeTransferFrom`, Allowing Bridged ERC721 NFTs to Be Permanently Locked — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.handleERC721Transfer` delivers bridged ERC721 tokens to the user-supplied `_to` address using the unsafe `IERC721.transferFrom`, which performs no receiver-capability check. If `_to` is a contract that does not implement `IERC721Receiver` / `onERC721Received`, the NFT is irrecoverably locked inside that contract. Because `_to` is freely chosen by the user on the source chain and is replayed verbatim by bridge operators on the destination chain, any user can trigger this outcome for their own (or another user's) bridged NFT.

---

### Finding Description

In `BridgeTransferERC721.sol`, the `handleERC721Transfer` function (the destination-side handler called by bridge operators after a quorum vote) delivers the NFT to the recipient using:

```solidity
// BridgeTransferERC721.sol line 69
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
```

`IERC721.transferFrom` does **not** invoke `onERC721Received` on the recipient. The ERC-721 standard explicitly marks `transferFrom` as unsafe for contract recipients and recommends `safeTransferFrom` whenever the recipient may be a contract.

The `IERC721` interface imported by the bridge (`contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/IERC721.sol`) exposes both `transferFrom` and `safeTransferFrom`; the safe variant is available but unused here.

The `_to` address originates from the user's call to `requestERC721Transfer` (or `requestValueTransfer` via `ERC721ServiceChain`) on the source chain and is carried verbatim into the `RequestValueTransferEncoded` event, then replayed by operators into `handleERC721Transfer`. There is no validation that `_to` is an EOA or implements `IERC721Receiver`.

---

### Impact Explanation

When `_to` is a contract without `onERC721Received` (e.g., a multisig wallet, a DAO treasury, another bridge contract, or any generic contract), the NFT is transferred into that contract with no way to retrieve it. The NFT is permanently locked. The user's bridged asset is destroyed without any recourse, and the bridge's locked/escrowed NFT on the source chain is also consumed (burn-mode) or held (lock-mode), meaning the loss is final on both sides.

**Corrupted value:** the ERC721 `_tokenOwner` mapping in the token contract is updated to point to a contract that can never move the token — a permanent, irrecoverable state corruption of the user's asset.

---

### Likelihood Explanation

- Any user can trigger this by specifying a contract address as `_to` when calling `requestERC721Transfer` or `requestValueTransfer`.
- Common contracts that do not implement `IERC721Receiver` include older Gnosis Safe multisigs, DAO treasuries, and generic proxy contracts — all plausible NFT recipients.
- No privileged access is required; the trigger is a normal user-initiated bridge request.
- Bridge operators faithfully relay whatever `_to` was emitted in the event; they perform no recipient validation.

---

### Recommendation

Replace `transferFrom` with `safeTransferFrom` in `handleERC721Transfer`:

```solidity
// Before (unsafe):
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);

// After (safe):
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
```

`safeTransferFrom` is already declared in the imported `IERC721` interface and implemented in the underlying `ERC721` base contract. This change causes the transaction to revert if `_to` is a contract that cannot receive ERC721 tokens, preventing the permanent lock. Operators would then need to handle the revert (e.g., by allowing the user to re-specify a valid recipient), which is far preferable to silent, irrecoverable asset loss.

---

### Proof of Concept

1. Deploy a contract `NoReceiver` on the destination chain that does **not** implement `onERC721Received`.
2. On the source chain, call:
   ```solidity
   bridge.requestERC721Transfer(nftAddress, address(NoReceiver), tokenId, "");
   ```
3. Bridge operators observe the `RequestValueTransferEncoded` event and call:
   ```solidity
   bridge.handleERC721Transfer(txHash, from, address(NoReceiver), nftAddress, tokenId, nonce, blockNum, uri, "");
   ```
4. `handleERC721Transfer` executes:
   ```solidity
   IERC721(nftAddress).transferFrom(address(this), address(NoReceiver), tokenId);
   ```
   This succeeds (no revert), and `NoReceiver` now owns `tokenId`.
5. `NoReceiver` has no function to call `transferFrom` or `safeTransferFrom` on the NFT contract, so `tokenId` is permanently locked.

**Relevant code locations:**
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
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

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/IERC721.sol (L35-52)
```text
    function safeTransferFrom(address from, address to, uint256 tokenId) public;
    /**
     * @dev Transfers a specific NFT (`tokenId`) from one account (`from`) to
     * another (`to`).
     *
     * Requirements:
     * - If the caller is not `from`, it must be approved to move this NFT by
     * either `approve` or `setApproveForAll`.
     */
    function transferFrom(address from, address to, uint256 tokenId) public;
    function approve(address to, uint256 tokenId) public;
    function getApproved(uint256 tokenId) public view returns (address operator);

    function setApprovalForAll(address operator, bool _approved) public;
    function isApprovedForAll(address owner, address operator) public view returns (bool);


    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public;
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721.sol (L160-179)
```text
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
    }
```
