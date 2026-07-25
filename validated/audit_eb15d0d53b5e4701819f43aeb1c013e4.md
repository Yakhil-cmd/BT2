### Title
Unsafe `transferFrom` in ERC721 Bridge Delivery Permanently Locks Bridged NFTs in Non-Receiver Contracts — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.handleERC721Transfer()` delivers bridged ERC721 tokens to the recipient using the raw `IERC721.transferFrom()` instead of `safeTransferFrom()`. Unlike the ERC20 path (which correctly uses `SafeERC20`), the ERC721 delivery path skips the `onERC721Received` callback check. When `_to` is a contract that does not implement `IERC721Receiver`, the transfer silently succeeds but the token is permanently locked — effectively destroyed — with no recovery path.

---

### Finding Description

In `BridgeTransferERC721.handleERC721Transfer()`, the lock-and-release (non-mint/burn) path delivers the token to the recipient with:

```solidity
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
``` [1](#0-0) 

The `IERC721` interface used by the bridge explicitly declares both `transferFrom` and `safeTransferFrom`:

```solidity
function safeTransferFrom(address from, address to, uint256 tokenId) public;
function transferFrom(address from, address to, uint256 tokenId) public;
``` [2](#0-1) 

`safeTransferFrom` calls `onERC721Received` on the recipient if it is a contract, and reverts if the recipient does not return the correct selector. `transferFrom` performs no such check. The bridge uses `transferFrom`, so delivery to any contract address that does not implement `IERC721Receiver` will silently succeed while the token becomes permanently inaccessible.

By contrast, the ERC20 bridge path correctly imports and applies `SafeERC20`:

```solidity
using SafeERC20 for IERC20;
...
IERC20(_tokenAddress).safeTransfer(_to, _value);
``` [3](#0-2) [4](#0-3) 

No `SafeERC721` equivalent is applied anywhere in the ERC721 bridge path. There is no `safeTransferFrom` usage anywhere in the production bridge contracts.

---

### Impact Explanation

When `_to` is a contract without `IERC721Receiver` support (e.g., a multisig, a DAO treasury, a DeFi protocol, or any generic contract), the bridge operators execute `handleERC721Transfer`, the raw `transferFrom` call succeeds without reverting, the bridge nonce is consumed and marked handled, and the NFT is permanently locked inside `_to` with no recovery mechanism. The bridged asset is effectively destroyed. The bridge state records the transfer as successfully completed, so there is no retry or rollback.

---

### Likelihood Explanation

Any user who initiates an ERC721 bridge transfer specifying a contract address as `_to` on the destination chain triggers this path. Contract addresses are common bridge destinations (protocol treasuries, smart wallets, DAOs). The user does not need any special privilege — they only need to call `requestERC721Transfer` or `onERC721Received` on the source chain with a contract `_to`. Bridge operators faithfully relay whatever `_to` was specified. [5](#0-4) 

---

### Recommendation

Replace the raw `transferFrom` call in `handleERC721Transfer` with `safeTransferFrom`:

```solidity
// Before
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);

// After
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
``` [6](#0-5) 

Note: `safeTransferFrom` introduces a reentrancy surface via the `onERC721Received` callback. Ensure a `nonReentrant` guard (already present on the KLAY path) is added to `handleERC721Transfer` alongside this fix.

---

### Proof of Concept

1. Deploy a contract `BadReceiver` on the destination chain that does **not** implement `IERC721Receiver`.
2. On the source chain, call `BridgeTransferERC721.requestERC721Transfer(tokenAddress, BadReceiver_address, tokenId, extraData)`.
3. Bridge operators observe the `RequestValueTransfer` event and call `handleERC721Transfer(..., _to=BadReceiver_address, ...)` on the destination bridge.
4. `IERC721(_tokenAddress).transferFrom(address(this), BadReceiver_address, tokenId)` executes and succeeds — no revert.
5. The bridge records the nonce as handled (`handleNoncesToBlockNums[nonce]` set, `lowerHandleNonce` advanced).
6. The NFT is now owned by `BadReceiver_address` but permanently inaccessible — no `onERC721Received` was called, no revert occurred, and the bridge considers the transfer complete with no retry path. [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L43-70)
```text
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
