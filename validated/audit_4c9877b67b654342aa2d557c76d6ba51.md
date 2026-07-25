### Title
Unsafe ERC721 delivery in `handleERC721Transfer` permanently freezes bridged NFTs — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.handleERC721Transfer` delivers bridged ERC721 tokens to the user-supplied `_to` address using either `_mint` (via `mintWithTokenURI`) or bare `transferFrom`, neither of which checks whether the recipient contract implements `onERC721Received`. If `_to` is a contract that cannot handle ERC721, the NFT is permanently frozen there while the original asset on the source chain has already been burned or locked, causing irreversible loss of the bridged asset.

---

### Finding Description

`handleERC721Transfer` is the destination-side handler called by bridge operators after a cross-chain ERC721 transfer request is confirmed. It delivers the NFT to `_to` via one of two paths:

**Mint-burn mode** (line 67):
```solidity
require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
```
`mintWithTokenURI` internally calls `_mint(to, tokenId)` — confirmed in `ERC721MetadataMintable.sol` line 20 — which does **not** invoke `_checkOnERC721Received`. The token is assigned to `_to` with no callback.

**Lock-unlock mode** (line 69):
```solidity
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
```
`transferFrom` also skips the `onERC721Received` check; only `safeTransferFrom` performs it.

In both cases, if `_to` is a contract without `onERC721Received`, the ERC721 token is recorded as owned by that contract but the contract has no mechanism to move it. Meanwhile, on the source chain, the NFT has already been **burned** (mint-burn mode, `_requestERC721Transfer` line 91) or **locked** in the source bridge (lock-unlock mode, `requestERC721Transfer` line 129). There is no recovery path.

The `_to` address is entirely user-controlled: it is passed in `requestERC721Transfer` / `onERC721Received` on the source chain and relayed verbatim by operators to `handleERC721Transfer` on the destination chain.

---

### Impact Explanation

A bridged ERC721 NFT is permanently frozen in a contract that cannot handle it. The source-chain asset is simultaneously destroyed (burn) or locked with no unlock trigger. The user loses the NFT with no recourse. This is an unauthorized, irreversible destruction of a bridged asset caused by a missing safety check in the bridge delivery path.

---

### Likelihood Explanation

Any user who specifies a contract address as `_to` when initiating a bridge transfer triggers this. Contract addresses are common recipients (e.g., multisigs, vaults, protocol contracts). No special privilege is required; the attacker is the user themselves, and the loss is self-inflicted but irreversible. The scenario is realistic and requires no collusion.

---

### Recommendation

Replace both unsafe delivery calls in `handleERC721Transfer` with their safe equivalents:

**Mint-burn mode** — add a `_safeMint`-based function to the token contract, or check `onERC721Received` after minting:
```solidity
// In ERC721MetadataMintable (or a bridge-specific override):
function safeMintWithTokenURI(address to, uint256 tokenId, string memory tokenURI) public onlyMinter returns (bool) {
    _safeMint(to, tokenId);   // calls _checkOnERC721Received
    _setTokenURI(tokenId, tokenURI);
    return true;
}
```

**Lock-unlock mode** — replace `transferFrom` with `safeTransferFrom`:
```solidity
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
```

Both changes cause the transaction to revert if `_to` cannot handle ERC721, preventing the source-chain burn/lock from completing in a state where the destination NFT is unrecoverable.

---

### Proof of Concept

1. User owns NFT `tokenId=42` on the source chain.
2. User calls `requestERC721Transfer(tokenAddress, victimContract, 42, "")` where `victimContract` is a deployed contract with no `onERC721Received`.
3. In mint-burn mode: the source-chain NFT is burned (`ERC721Burnable.burn(42)`, `_requestERC721Transfer` line 91).
4. Bridge operators observe the `RequestValueTransferEncoded` event and call `handleERC721Transfer(..., victimContract, 42, ...)` on the destination chain.
5. `mintWithTokenURI(victimContract, 42, uri)` calls `_mint(victimContract, 42)` — succeeds silently, no callback.
6. `victimContract` now owns token 42 on the destination chain but cannot transfer it.
7. The source-chain token is gone. The destination-chain token is frozen. The NFT is permanently lost. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L88-92)
```text
            uri = "";
        }
        if (modeMintBurn) {
            ERC721Burnable(_tokenAddress).burn(_tokenId);
        }
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721MetadataMintable.sol (L19-21)
```text
    function mintWithTokenURI(address to, uint256 tokenId, string memory tokenURI) public onlyMinter returns (bool) {
        _mint(to, tokenId);
        _setTokenURI(tokenId, tokenURI);
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
