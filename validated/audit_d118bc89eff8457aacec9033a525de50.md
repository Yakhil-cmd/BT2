### Title
Unsafe `transferFrom` in `BridgeTransferERC721.handleERC721Transfer` Permanently Locks Bridged ERC721 Tokens in Non-Receiver Contracts — (File: `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721` uses the bare `IERC721.transferFrom` when delivering bridged ERC721 tokens to the destination recipient. The ERC721 standard provides `safeTransferFrom` precisely to prevent tokens from being permanently locked in contracts that do not implement `IERC721Receiver`. Because the bridge skips this check, any bridge-handle operation whose `_to` is a non-receiver contract silently succeeds at the Solidity level while the token becomes irrecoverable. The bridge nonce is consumed and the `HandleValueTransfer` event is emitted, making the loss permanent and unrecoverable through normal bridge recovery.

---

### Finding Description

In `handleERC721Transfer`, after the operator quorum is reached and the nonce is finalized, the token delivery path is:

```solidity
// BridgeTransferERC721.sol line 66-70
if (modeMintBurn) {
    require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
} else {
    IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);   // ← bare transferFrom
}
``` [1](#0-0) 

The `IERC721` interface exposes both `transferFrom` and `safeTransferFrom`:

```solidity
function safeTransferFrom(address from, address to, uint256 tokenId) public;
function transferFrom(address from, address to, uint256 tokenId) public;
``` [2](#0-1) 

`safeTransferFrom` checks whether `to` is a contract and, if so, calls `onERC721Received(operator, from, tokenId, data)` on it, reverting if the call fails or returns the wrong selector. `transferFrom` performs no such check. When `_to` is a contract that does not implement the standard `IERC721Receiver` interface, `transferFrom` succeeds, the token is owned by `_to`, but no code in `_to` can move it — it is permanently locked.

The nonce accounting and event emission happen **before** the transfer call:

```solidity
handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
_updateHandleNonce(_requestedNonce);
emit HandleValueTransfer(...);
// then transferFrom — if token is locked, nonce is already consumed
``` [3](#0-2) 

There is no retry or reversal path once `_updateHandleNonce` advances `lowerHandleNonce` past the request nonce.

---

### Impact Explanation

A user on the source chain calls `requestERC721Transfer` specifying a contract address as `_to` (e.g., a multisig, a DeFi vault, or any contract without `onERC721Received`). The bridge operators faithfully relay the request. On the destination chain, `handleERC721Transfer` executes `transferFrom(address(this), _to, _tokenId)`. The ERC721 token is now owned by `_to` but permanently inaccessible. The bridge handle nonce is consumed and cannot be replayed. The user's bridged asset is destroyed with no recourse.

**Affected asset:** bridged ERC721 tokens held in the service-chain bridge (lock-and-mint mode, `modeMintBurn == false`).

---

### Likelihood Explanation

The `_to` address is fully user-controlled on the source chain and is passed verbatim through the bridge event to `handleERC721Transfer`. Contract addresses are common bridge recipients (protocol treasuries, NFT vaults, multisigs). No validation of `_to` being an EOA or a valid ERC721 receiver is performed anywhere in the bridge pipeline. The trigger path is: any user calling the public `requestERC721Transfer` on the source chain with a contract `_to` that lacks `onERC721Received`. [4](#0-3) 

---

### Recommendation

Replace the bare `transferFrom` in `handleERC721Transfer` with `safeTransferFrom`:

```solidity
// Before
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);

// After
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
```

This causes the transaction to revert if `_to` cannot accept ERC721 tokens, preventing nonce consumption and allowing operators to retry with a corrected recipient. Note that `requestERC721Transfer` (line 129) intentionally uses `transferFrom` to deposit into the bridge itself — this is correct because the bridge's own `onERC721Received` uses a non-standard signature and would fail the ERC721 receiver check; that call site does not need to change. [1](#0-0) 

---

### Proof of Concept

1. Deploy a contract `NoReceiver` on the destination service chain with no `onERC721Received` implementation.
2. On the source chain, call:
   ```solidity
   bridge.requestERC721Transfer(tokenAddress, address(noReceiver), tokenId, "");
   ```
3. Bridge operators observe the `RequestValueTransferEncoded` event and call `handleERC721Transfer` on the destination bridge with `_to = address(noReceiver)`.
4. `IERC721(tokenAddress).transferFrom(address(bridge), address(noReceiver), tokenId)` succeeds — ERC721 does not revert for non-receiver contracts when using `transferFrom`.
5. `ownerOf(tokenId)` now returns `address(noReceiver)`, but `noReceiver` has no function to call `transferFrom` or `safeTransferFrom` on the token contract.
6. The token is permanently locked. The handle nonce has been consumed; the bridge will never re-process this request.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L51-70)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L121-131)
```text
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

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/IERC721.sol (L35-44)
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
```
