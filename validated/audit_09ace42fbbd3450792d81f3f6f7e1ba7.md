### Title
Unsafe `transferFrom` in `handleERC721Transfer` Permanently Locks Bridged ERC721 Tokens in Non-Receiver Contracts — (File: `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.handleERC721Transfer()` uses the bare `IERC721.transferFrom()` to deliver bridged NFTs to the destination address `_to`. Unlike `safeTransferFrom()`, this call does not invoke `onERC721Received` on contract recipients. Any bridged ERC721 token sent to a contract that does not implement `IERC721Receiver` is permanently locked with no recovery path, while the bridge nonce is already consumed and the handle event already emitted.

---

### Finding Description

In `BridgeTransferERC721.sol`, the `handleERC721Transfer` function — called by bridge operators to settle a cross-chain ERC721 transfer — executes the final delivery as:

```solidity
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
``` [1](#0-0) 

This is the lock-mode (non-mint-burn) path. The `IERC721` interface available in this project explicitly exposes both `transferFrom` and `safeTransferFrom`: [2](#0-1) 

`safeTransferFrom` calls `onERC721Received` on the recipient if it is a contract and reverts if the callback is absent or returns the wrong selector. `transferFrom` performs no such check — the NFT is moved unconditionally, and any contract recipient that cannot handle ERC721 tokens will hold the token forever with no way to recover it.

Critically, the bridge nonce accounting and the `HandleValueTransfer` event are both committed **before** the token delivery call: [3](#0-2) 

Once `_updateHandleNonce` runs and the event is emitted, the bridge considers the request fully settled. There is no retry or reversal mechanism.

By contrast, the ERC20 bridge path correctly uses `SafeERC20` throughout: [4](#0-3) [5](#0-4) 

The ERC721 path has no equivalent protection.

---

### Impact Explanation

A bridged ERC721 token is permanently destroyed from the user's perspective:

1. The user on the source chain calls `requestERC721Transfer` specifying `_to` as a contract address (e.g., a multisig, a DeFi vault, a smart-contract wallet) that does not implement `IERC721Receiver.onERC721Received`.
2. Bridge operators call `handleERC721Transfer` on the destination chain.
3. The handle nonce is consumed and `HandleValueTransfer` is emitted — the bridge considers the request closed.
4. `transferFrom(address(this), _to, _tokenId)` succeeds silently; the NFT is now owned by `_to`, a contract with no ability to transfer it out.
5. The NFT is permanently locked. The bridge has no refund or re-route mechanism once the nonce is consumed.

This is a direct loss of bridged assets, squarely within the allowed impact gate ("unauthorized … burn … affecting … bridged assets").

---

### Likelihood Explanation

- Smart-contract wallets (Gnosis Safe, account-abstraction wallets) and DeFi protocols are common `_to` targets for NFT bridges; many do not implement `IERC721Receiver`.
- The user specifies `_to` freely; no on-chain validation of `_to`'s receiver capability exists.
- The trigger requires only a valid bridge request — no privilege escalation, no majority-validator collusion, no compromised keys.

---

### Recommendation

Replace the bare `transferFrom` with `safeTransferFrom` in the lock-mode branch of `handleERC721Transfer`:

```solidity
// Before
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);

// After
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
``` [6](#0-5) 

If `_to` cannot receive ERC721 tokens, `safeTransferFrom` will revert before the nonce is consumed (or, given the current ordering, the revert will roll back the entire transaction including the nonce update), preventing permanent loss. Operators can then re-submit with a corrected `_to`.

---

### Proof of Concept

1. Deploy a bridged ERC721 token on the destination chain in lock mode (`modeMintBurn = false`).
2. On the source chain, call `requestERC721Transfer(_tokenAddress, _to, _tokenId, "")` where `_to` is a plain Solidity contract with no `onERC721Received` implementation.
3. Bridge operators call `handleERC721Transfer(...)` on the destination bridge.
4. The call succeeds: `lowerHandleNonce` advances, `HandleValueTransfer` is emitted, and `IERC721(_tokenAddress).ownerOf(_tokenId)` returns `_to`.
5. Attempt any transfer from `_to` — impossible, as `_to` has no ERC721 handling logic.
6. The NFT is permanently locked; the bridge nonce is consumed with no recovery path.

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L29-29)
```text
    using SafeERC20 for IERC20;
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L71-71)
```text
            IERC20(_tokenAddress).safeTransfer(_to, _value);
```
