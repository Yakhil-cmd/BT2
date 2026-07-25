### Title
Unsafe `transferFrom` in `handleERC721Transfer` Permanently Locks Bridged NFTs When Recipient Is a Non-ERC721-Receiver Contract — (File: `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.handleERC721Transfer` uses the bare `IERC721.transferFrom` instead of `safeTransferFrom` when delivering a bridged NFT to the destination address in lock/unlock mode. If the user-specified `_to` address is a smart contract that does not implement the standard `IERC721Receiver.onERC721Received` callback, the NFT is silently transferred into that contract and permanently locked there. Because the bridge nonce is consumed and the `HandleValueTransfer` event is emitted before the transfer call, the bridge considers the operation complete with no recovery path.

---

### Finding Description

In `handleERC721Transfer` (non-mint-burn path), the sequence is:

1. `_setHandledRequestTxHash(_requestTxHash)` — marks the source tx as handled
2. `handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber` — records nonce
3. `_updateHandleNonce(_requestedNonce)` — advances `lowerHandleNonce`
4. `emit HandleValueTransfer(...)` — emits the completion event
5. `IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId)` — actual delivery [1](#0-0) 

The bare `transferFrom` at step 5 does not invoke `onERC721Received` on the recipient. If `_to` is a contract without ERC721-handling logic (e.g., a multisig, DAO treasury, or any contract that does not implement `IERC721Receiver`), the ERC721 token is transferred into it and may be permanently irrecoverable. The `IERC721` interface imported by this contract does expose `safeTransferFrom`, which would revert in this case and prevent the nonce from being consumed. [2](#0-1) 

By contrast, `BridgeTransferERC20.handleERC20Transfer` correctly uses `IERC20.safeTransfer` for the equivalent ERC20 delivery path, and `BridgeTransferERC20.requestERC20Transfer` uses `safeTransferFrom` for deposits. [3](#0-2) 

The `_to` address originates from the user's original `requestERC721Transfer` call on the source chain, making it fully user-controlled and reachable without any privileged access. [4](#0-3) 

---

### Impact Explanation

Once `transferFrom` succeeds at step 5, the bridge state is already finalized: the request tx hash is marked handled, the handle nonce is advanced past `_requestedNonce`, and the `HandleValueTransfer` event has been emitted. The bridge's off-chain relayer (`handleRequestValueTransferEvent`) records the handle tx hash and increments the account nonce. [5](#0-4) 

There is no on-chain mechanism to re-issue the transfer for the same `_requestedNonce` once it is consumed. The bridged ERC721 asset is permanently lost to a contract that cannot move it. This constitutes an unauthorized loss of bridged assets affecting system-managed funds held by the bridge.

---

### Likelihood Explanation

The `_to` address is entirely user-specified. Any user who bridges an NFT to a contract destination that does not implement `IERC721Receiver` (e.g., a Gnosis Safe deployed before ERC721 support, a DAO vault, a custom escrow, or any contract without explicit NFT handling) triggers this path. No privileged access or majority-validator collusion is required. The trigger is a normal, valid bridge request.

---

### Recommendation

Replace the bare `transferFrom` call in `handleERC721Transfer` with `safeTransferFrom`:

```solidity
// Before (line 69):
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);

// After:
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
``` [6](#0-5) 

If `_to` cannot receive ERC721 tokens, `safeTransferFrom` reverts the entire `handleERC721Transfer` transaction, leaving the nonce unconsumed and the bridge state unchanged. Bridge operators can then coordinate an alternative resolution (e.g., operator-level override or user correction of the destination address).

---

### Proof of Concept

1. User on the child chain calls `requestERC721Transfer(tokenAddr, contractWithoutReceiver, tokenId, "")`. The NFT is pulled into the bridge and a `RequestValueTransferEncoded` event is emitted with `_to = contractWithoutReceiver`.

2. Bridge operators observe the event and call `handleERC721Transfer(txHash, from, contractWithoutReceiver, tokenAddr, tokenId, nonce, blockNum, uri, "")` on the parent chain bridge.

3. The function executes steps 1–4 (nonce consumed, event emitted), then calls `IERC721(tokenAddr).transferFrom(bridge, contractWithoutReceiver, tokenId)`.

4. `transferFrom` succeeds — the NFT is now owned by `contractWithoutReceiver`, which has no logic to transfer it out.

5. The bridge's `lowerHandleNonce` has advanced past `nonce`. The request tx hash is marked handled. No retry is possible. The NFT is permanently locked. [7](#0-6) [8](#0-7)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** node/sc/bridge_manager.go (L344-358)
```go
	case ERC721:
		uri := GetURI(ev)
		handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, uri, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC721], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	default:
		logger.Error("Got Unknown Token Type ReceivedEvent", "bridge", contractAddr, "nonce", requestNonce, "from", from)
		return nil
	}

	bridgeAcc.IncNonce()

	bi.bridgeDB.WriteHandleTxHashFromRequestTxHash(txHash, handleTx.Hash())
```

**File:** contracts/service_chain/bridge/BridgeHandledRequests.sol (L23-25)
```text
    function _setHandledRequestTxHash(bytes32 _requestTxHash) internal {
        handledRequestTx[_requestTxHash] = true;
    }
```
