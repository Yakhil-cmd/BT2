After thorough examination of the Kaia bridge contracts, I found the following:

**ERC20 path:** `BridgeTransferERC20.sol` and `BridgeFee.sol` both import and use `SafeERC20` for all token transfers (`safeTransfer`, `safeTransferFrom`). There is no unsafe ERC20 transfer analog.

**ERC721 path:** `BridgeTransferERC721.sol` uses bare `IERC721.transferFrom` instead of `safeTransferFrom` in `handleERC721Transfer`, which is a real unsafe-transfer analog in the bridge's asset-delivery path.

---

### Title
Unsafe `transferFrom` in `BridgeTransferERC721.handleERC721Transfer` Permanently Locks Bridged NFTs in Non-Receiver Contracts — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

### Summary
`BridgeTransferERC721.handleERC721Transfer` uses `IERC721.transferFrom` instead of `safeTransferFrom` when delivering a bridged NFT to the destination recipient. If the user-supplied `_to` address is a smart contract that does not implement `IERC721Receiver`, the transfer succeeds silently and the NFT is permanently locked in that contract with no recovery path.

### Finding Description
In the non-mint-burn mode of `handleERC721Transfer`, the bridge delivers the NFT to the recipient using:

```solidity
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
``` [1](#0-0) 

The ERC721 standard's `transferFrom` does not invoke `onERC721Received` on the recipient and does not revert if the recipient is a contract lacking that callback. By contrast, `safeTransferFrom` would revert in that case, keeping the NFT in the bridge and allowing operators to retry or refund.

The `_to` address originates from the user's original `RequestValueTransfer` event on the source chain and is passed verbatim through the operator's `handleERC721Transfer` call. No validation of `_to` as an ERC721-capable receiver is performed anywhere in the call chain. [2](#0-1) 

The `requestERC721Transfer` deposit path also uses bare `transferFrom`, but there the caller is the token owner explicitly initiating the deposit, so silent acceptance is acceptable. The vulnerability is exclusively in the delivery direction. [3](#0-2) 

### Impact Explanation
A bridged NFT is permanently destroyed from the user's perspective: it was burned or locked on the source chain, the bridge nonce was consumed and marked handled, the `HandleValueTransfer` event was emitted, but the NFT is irrecoverably locked in a contract that cannot transfer it out. This is an irreversible loss of a bridged asset with no on-chain recovery mechanism.

### Likelihood Explanation
Any user who requests an ERC721 bridge transfer to a multisig wallet, a DAO treasury, a DeFi protocol, or any other contract that does not implement `IERC721Receiver` triggers this path. Such destinations are common in practice. The operators faithfully relay the user-specified `_to` address; no operator error is required.

### Recommendation
Replace `transferFrom` with `safeTransferFrom` in `handleERC721Transfer`:

```solidity
// Before
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);

// After
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
``` [4](#0-3) 

If `safeTransferFrom` reverts (recipient cannot accept ERC721), the entire `handleERC721Transfer` transaction reverts, the nonce is not consumed, and operators can retry with a corrected recipient or implement a refund flow. This mirrors the pattern already used correctly in `BridgeTransferERC20.handleERC20Transfer`:

```solidity
IERC20(_tokenAddress).safeTransfer(_to, _value);
``` [5](#0-4) 

### Proof of Concept

1. User on source chain calls `requestERC721Transfer` (or `onERC721Received`) specifying `_to = address(SomeContractWithoutERC721Receiver)`.
2. Source-chain bridge emits `RequestValueTransfer` / `RequestValueTransferEncoded` with the user-supplied `_to`.
3. Operators on the destination chain reach quorum and call `handleERC721Transfer(..., _to, _tokenId, ...)`.
4. The function passes all nonce checks, emits `HandleValueTransfer`, marks the nonce as handled, and executes:
   ```solidity
   IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
   ```
5. The ERC721 token is transferred to `_to`. Because `_to` has no `onERC721Received` and no way to call `transferFrom` itself, the NFT is permanently locked.
6. The source-chain NFT was already burned/locked; the bridge nonce is consumed; there is no on-chain mechanism to recover the destination NFT.

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L71-71)
```text
            IERC20(_tokenAddress).safeTransfer(_to, _value);
```
