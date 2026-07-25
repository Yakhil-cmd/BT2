### Title
Unchecked ERC721 `transferFrom` Return Value in Bridge Allows Silent Asset Loss and Nonce Consumption — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721` uses raw `IERC721(_tokenAddress).transferFrom(...)` calls without checking the return value or using a safe wrapper. In contrast, `BridgeTransferERC20` consistently uses OpenZeppelin's `SafeERC20` (`safeTransfer`/`safeTransferFrom`), and the `modeMintBurn` path in `handleERC721Transfer` guards the mint with `require(...)`. The ERC721 non-mint path has no such guard. If a registered ERC721 token returns `false` instead of reverting on a failed transfer, the bridge silently proceeds: in `handleERC721Transfer` the handle-nonce is permanently consumed and the `HandleValueTransfer` event is emitted with no asset delivered; in `requestERC721Transfer` a cross-chain request event is emitted and `requestNonce` is incremented without the NFT ever being locked.

---

### Finding Description

`BridgeTransferERC721.sol` contains two unchecked `transferFrom` calls:

**Call 1 — `handleERC721Transfer`, non-`modeMintBurn` path (line 69):**

```solidity
// nonce already consumed, event already emitted above
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
```

The handle-nonce bookkeeping (`_setHandledRequestTxHash`, `handleNoncesToBlockNums`, `_updateHandleNonce`) and the `HandleValueTransfer` event emission all occur **before** this call. [1](#0-0) 

If the token's `transferFrom` silently returns `false` (non-standard token), the EVM does not revert. Because `IERC721` declares `transferFrom` as returning nothing, Solidity 0.5.x discards any return data; the call is treated as successful. The nonce is permanently consumed and the request is irrecoverable.

**Call 2 — `requestERC721Transfer` (line 129):**

```solidity
IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
_requestERC721Transfer(_tokenAddress, msg.sender, _to, _tokenId, _extraData);
``` [2](#0-1) 

If `transferFrom` silently fails, the NFT is never locked in the bridge, yet `_requestERC721Transfer` still emits `RequestValueTransferEncoded` and increments `requestNonce`. Bridge operators observing this event will call `handleERC721Transfer` on the counterpart chain.

**Contrast with ERC20 handling (safe):**

`BridgeTransferERC20` uses `SafeERC20` throughout: [3](#0-2) [4](#0-3) 

`BridgeFee` also uses `SafeERC20` for all ERC20 fee transfers: [5](#0-4) [6](#0-5) 

The `modeMintBurn` path in `handleERC721Transfer` correctly guards the mint: [7](#0-6) 

The non-mint path has no equivalent guard.

---

### Impact Explanation

**`handleERC721Transfer` (non-`modeMintBurn`):** The bridge permanently marks the cross-chain request as handled (nonce consumed, request tx hash recorded, `HandleValueTransfer` emitted) but delivers no asset to `_to`. The user's NFT was locked on the source chain; it is now unrecoverable because the handle-nonce cannot be replayed. This is a permanent loss of a bridged asset.

**`requestERC721Transfer`:** A `RequestValueTransferEncoded` event is emitted and `requestNonce` is incremented without the NFT being locked. In `modeMintBurn` mode on the destination bridge, operators will call `handleERC721Transfer`, which mints a new NFT to the user — an unauthorized mint of a bridged asset with no corresponding lock on the source side.

Both outcomes satisfy the allowed impact gate: unauthorized asset loss/mint affecting bridged assets, and bridge nonce consumption without corresponding asset transfer.

---

### Likelihood Explanation

The trigger requires a registered ERC721 token whose `transferFrom` returns `false` instead of reverting. Token registration is controlled by the bridge owner, so the token must be either malicious or buggy. This makes the likelihood low-to-medium: the bridge is designed to support arbitrary ERC721 tokens registered by the owner, and non-standard ERC721 implementations (e.g., tokens that return `bool` like ERC20) exist in the wild. The asymmetry — ERC20 paths are hardened with `SafeERC20` while ERC721 paths are not — suggests this was an oversight rather than an intentional design choice.

---

### Recommendation

Replace the raw `IERC721.transferFrom` calls with `safeTransferFrom`, which performs an `onERC721Received` callback check and reverts on failure. Alternatively, wrap the call and require success:

```solidity
// In handleERC721Transfer (non-modeMintBurn):
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);

// In requestERC721Transfer:
IERC721(_tokenAddress).safeTransferFrom(msg.sender, address(this), _tokenId);
```

`safeTransferFrom` reverts if the transfer fails, ensuring the transaction atomically rolls back the nonce update and event emission. This mirrors the pattern already used for ERC20 (`SafeERC20.safeTransfer`) and for the mint path (`require(mintWithTokenURI(...))`).

---

### Proof of Concept

1. Deploy a non-standard ERC721 token whose `transferFrom` always returns `false` without reverting, and register it on the bridge.
2. Call `requestERC721Transfer` with this token. The `transferFrom` silently fails; the NFT stays with the caller. `RequestValueTransferEncoded` is emitted and `requestNonce` increments.
3. Bridge operators observe the event and call `handleERC721Transfer` on the destination bridge (in `modeMintBurn` mode). The `mintWithTokenURI` call succeeds, minting the NFT to the recipient.
4. Result: the recipient holds a minted NFT on the destination chain; the source NFT was never locked. Unauthorized mint of a bridged asset.

For the `handleERC721Transfer` path:
1. Lock a legitimate NFT on the source chain (standard token, `requestERC721Transfer` succeeds).
2. On the destination bridge (non-`modeMintBurn`), the registered token is a non-standard ERC721 whose `transferFrom` returns `false`.
3. Operators call `handleERC721Transfer`. Lines 49–64 consume the nonce and emit `HandleValueTransfer`. Line 69 silently fails.
4. Result: handle-nonce permanently consumed, `HandleValueTransfer` emitted, but `_to` never receives the NFT. The source NFT is permanently locked in the source bridge with no recourse. [8](#0-7) [9](#0-8)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L28-29)
```text
contract BridgeTransferERC20 is BridgeTokens, IERC20BridgeReceiver, BridgeTransfer {
    using SafeERC20 for IERC20;
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L71-72)
```text
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L27-27)
```text
    using SafeERC20 for IERC20;
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L74-78)
```text
            IERC20(_token).safeTransfer(feeReceiver, fee);

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                IERC20(_token).safeTransfer(from, feeRefund);
```
