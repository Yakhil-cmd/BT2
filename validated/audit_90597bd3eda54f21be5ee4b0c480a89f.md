### Title
`transferFrom` Used Instead of `safeTransferFrom` in Bridge ERC721 Delivery — Bridged NFTs Permanently Locked in Non-Receiver Contracts - (File: `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.handleERC721Transfer` uses `IERC721.transferFrom` instead of `safeTransferFrom` when delivering bridged ERC721 tokens to the recipient on the destination chain. If the recipient `_to` is a contract that does not implement `IERC721Receiver`, the token ownership is transferred but the recipient contract is never notified, permanently locking the bridged NFT with no recovery path.

---

### Finding Description

In `contracts/service_chain/bridge/BridgeTransferERC721.sol`, the `handleERC721Transfer` function (called by bridge operators to settle a cross-chain ERC721 transfer) contains the following delivery logic in the non-mintBurn path:

```solidity
// line 69
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
``` [1](#0-0) 

`transferFrom` performs a raw ownership change with no callback to the recipient. The ERC721 standard's `safeTransferFrom` variant, by contrast, calls `onERC721Received` on the recipient if it is a contract and reverts if the magic value is not returned, ensuring the recipient is capable of handling the token.

The `_to` address is fully user-controlled: it is set by the originating user when they call `requestERC721Transfer` on the source-chain bridge:

```solidity
// line 121-131
function requestERC721Transfer(
    address _tokenAddress,
    address _to,
    uint256 _tokenId,
    bytes memory _extraData
) public {
    IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
    _requestERC721Transfer(_tokenAddress, msg.sender, _to, _tokenId, _extraData);
}
``` [2](#0-1) 

The `_to` value is then relayed verbatim by the bridge operator into `handleERC721Transfer`: [3](#0-2) 

The OpenZeppelin `ERC721.sol` bundled in the repository explicitly documents that `transferFrom` usage is discouraged and that `safeTransferFrom` should be preferred: [4](#0-3) 

---

### Impact Explanation

When `_to` is a contract that does not implement `IERC721Receiver.onERC721Received` (e.g., a multisig wallet, a DAO treasury, a DeFi protocol, or any generic contract), the following occurs:

1. The ERC721 token's ownership record is updated to `_to` — the transfer succeeds at the EVM level.
2. The recipient contract receives no notification and has no awareness of the incoming token.
3. The token is permanently locked inside `_to` with no recovery mechanism in the bridge contract.

The asset lost is a **bridged ERC721 token** — the user already burned or locked the original NFT on the source chain (via `requestERC721Transfer`). The source-chain asset is gone; the destination-chain delivery is silently broken. There is no refund or retry mechanism in the bridge.

This satisfies the allowed impact gate: **permanent loss of bridged assets** due to a broken delivery invariant in the bridge path.

---

### Likelihood Explanation

- Any user can specify an arbitrary contract address as `_to` when initiating a bridge transfer — no privilege required.
- Contract recipients are common in DeFi: multisigs, DAOs, vaults, and protocol treasuries routinely hold NFTs.
- The user may not realize their recipient contract lacks ERC721 receiver support until after the source-chain NFT is already burned/locked.
- The `modeMintBurn` path (line 67) uses `mintWithTokenURI` which also mints directly to `_to` without a safe-transfer check, but the `transferFrom` path (line 69) is the clearest instance.

---

### Recommendation

Replace `transferFrom` with `safeTransferFrom` in the non-mintBurn delivery path:

```solidity
// Before
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);

// After
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
```

To avoid a DoS vector (a malicious `_to` contract that deliberately reverts `onERC721Received` to block the bridge nonce from advancing), wrap the call in a `try/catch`:

```solidity
try IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId) {
    // success
} catch {
    // emit a failure event; allow operators to redirect or recover
}
```

Alternatively, provide an owner-callable rescue function to redirect a stuck token to a fallback address.

---

### Proof of Concept

1. Alice owns NFT tokenId=42 on the parent chain.
2. Alice calls `requestERC721Transfer(nftAddr, vaultContract, 42, "0x")` where `vaultContract` is a deployed contract without `onERC721Received`.
3. The source-chain bridge takes custody of tokenId=42 (or burns it in mintBurn mode).
4. Bridge operators observe the `RequestValueTransferEncoded` event and call `handleERC721Transfer(..., vaultContract, nftAddr, 42, ...)` on the destination bridge.
5. The bridge executes `IERC721(nftAddr).transferFrom(address(this), vaultContract, 42)`.
6. The ERC721 ownership record now shows `vaultContract` as owner of tokenId=42.
7. `vaultContract` has no `onERC721Received`, no internal record of the token, and no function to transfer it out.
8. tokenId=42 is permanently locked. Alice's NFT is gone from both chains. [5](#0-4)

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

**File:** node/sc/bridge_manager.go (L344-350)
```go
	case ERC721:
		uri := GetURI(ev)
		handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, uri, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC721], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721.sol (L134-147)
```text
    /**
     * @dev Transfers the ownership of a given token ID to another address.
     * Usage of this method is discouraged, use `safeTransferFrom` whenever possible.
     * Requires the msg.sender to be the owner, approved, or operator.
     * @param from current owner of the token
     * @param to address to receive the ownership of the given token ID
     * @param tokenId uint256 ID of the token to be transferred
     */
    function transferFrom(address from, address to, uint256 tokenId) public {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(msg.sender, tokenId), "ERC721: transfer caller is not owner nor approved");

        _transferFrom(from, to, tokenId);
    }
```
