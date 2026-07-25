### Title
`transferFrom` Used Instead of `safeTransferFrom` in Bridge ERC721 Handle Path — (`File: contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.handleERC721Transfer` uses the unsafe `IERC721.transferFrom` (not `safeTransferFrom`) when delivering a bridged NFT to the destination address in non-`modeMintBurn` mode. This is the direct Kaia-native analog of the `_mint` vs `_safeMint` bug class: recipient contract capability is never verified, so any bridged ERC721 token sent to a contract that does not implement `IERC721Receiver` is permanently locked with no recovery path.

---

### Finding Description

In `BridgeTransferERC721.sol`, the `handleERC721Transfer` function has two delivery branches:

```solidity
if (modeMintBurn) {
    require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
} else {
    IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);   // ← unsafe
}
``` [1](#0-0) 

In the `else` branch (lock/unlock mode, the default for most deployments), `transferFrom` is called directly. Unlike `safeTransferFrom`, `transferFrom` performs no `onERC721Received` callback and no receiver-interface check. The OpenZeppelin v2 `ERC721` base used by this codebase documents this explicitly:

```solidity
function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public {
    transferFrom(from, to, tokenId);
    require(_checkOnERC721Received(from, to, tokenId, _data),
        "ERC721: transfer to non ERC721Receiver implementer");
}
``` [2](#0-1) 

The `_to` address in `handleERC721Transfer` originates from the user's original `requestERC721Transfer` call on the source chain — it is fully user-controlled. The bridge operator faithfully relays whatever `_to` was specified. There is no on-chain validation that `_to` is capable of receiving ERC721 tokens. [3](#0-2) 

The Go-layer bridge manager in `node/sc/bridge_manager.go` also passes `_to` through without any address-capability check:

```go
case ERC721:
    uri := GetURI(ev)
    handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, uri, extraData)
``` [4](#0-3) 

---

### Impact Explanation

A bridged ERC721 token delivered to a contract address that does not implement `IERC721Receiver` is permanently inaccessible. The token ownership record is updated in the ERC721 contract, but the owning contract has no mechanism to transfer it out. Neither the original sender nor any other party can recover the asset. This constitutes permanent loss of a bridged asset — squarely within the allowed impact gate ("unauthorized … burn … affecting … bridged assets").

---

### Likelihood Explanation

The trigger is an unprivileged user action: any user who initiates a cross-chain ERC721 transfer and specifies a contract address as `_to` (e.g., a multisig wallet, a DAO treasury, a DeFi protocol, or any contract not explicitly implementing `IERC721Receiver`) will lose their NFT permanently. No special privilege is required beyond being a normal bridge user. The bridge operator merely relays the request faithfully. The condition is reachable on every `handleERC721Transfer` execution in lock/unlock mode.

---

### Recommendation

Replace `transferFrom` with `safeTransferFrom` in the non-`modeMintBurn` delivery path of `handleERC721Transfer`:

```solidity
// Before (unsafe):
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);

// After (safe):
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
``` [5](#0-4) 

`safeTransferFrom` calls `_checkOnERC721Received`, which verifies the recipient contract returns the correct `bytes4` selector, reverting the transaction if the recipient cannot handle ERC721 tokens. This causes the bridge handle transaction to revert rather than silently locking the asset. [6](#0-5) 

---

### Proof of Concept

1. Deploy a contract `Sink` on the destination chain that has no `onERC721Received` function.
2. On the source chain, call `requestERC721Transfer(tokenAddress, Sink.address, tokenId, "0x")` — this is a normal unprivileged user action.
3. The bridge operator observes the `RequestValueTransferEncoded` event and calls `handleERC721Transfer(..., _to=Sink.address, ...)` on the destination bridge.
4. The bridge is in lock/unlock mode (`modeMintBurn == false`), so line 69 executes: `IERC721(_tokenAddress).transferFrom(address(this), Sink.address, _tokenId)`.
5. The ERC721 contract records `Sink` as the owner. `Sink` has no `onERC721Received` and no transfer capability.
6. The NFT is permanently locked. The `HandleValueTransfer` event is emitted and the nonce is consumed, so the bridge considers the transfer complete and will not retry. [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L43-71)
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

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721.sol (L176-179)
```text
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public {
        transferFrom(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721.sol (L279-288)
```text
    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory _data)
        internal returns (bool)
    {
        if (!to.isContract()) {
            return true;
        }

        bytes4 retval = IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, _data);
        return (retval == _ERC721_RECEIVED);
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
