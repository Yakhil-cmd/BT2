### Title
Unchecked ERC721 `transferFrom` Return in Bridge Allows Free Cross-Chain NFT Minting — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.sol` calls the bare `IERC721.transferFrom()` in two places without any safe wrapper or return-value check. The ERC20 bridge in the same codebase correctly uses `safeTransferFrom` (via `SafeERC20`), but the ERC721 bridge does not apply an equivalent guard. If a registered ERC721 token silently fails its `transferFrom` instead of reverting, the bridge still emits `RequestValueTransfer`, increments `requestNonce`, and the counterpart bridge will mint or release the NFT to the attacker on the other chain — without the attacker ever depositing the token.

---

### Finding Description

`BridgeTransferERC20.requestERC20Transfer` uses `safeTransferFrom` from `SafeERC20`: [1](#0-0) 

`BridgeTransferERC721.requestERC721Transfer` uses the bare `IERC721.transferFrom` with no check: [2](#0-1) 

The `IERC721` interface declares `transferFrom` as a void function: [3](#0-2) 

Because the ABI-declared return type is `void`, Solidity silently discards any return data. A non-standard ERC721 token whose `transferFrom` returns `false` instead of reverting will pass the call without transferring ownership. Immediately after, `_requestERC721Transfer` is executed unconditionally: [4](#0-3) 

This emits `RequestValueTransferEncoded` and increments `requestNonce`. The counterpart bridge's operators then call `handleERC721Transfer`, which either mints a new NFT to the attacker (`modeMintBurn = true`) or transfers one from the bridge's own custody (`modeMintBurn = false`): [5](#0-4) 

The same bare `transferFrom` appears in `handleERC721Transfer` (line 69) for the lock/unlock mode, meaning a silent failure there also leaves the recipient without their NFT while the nonce is permanently consumed.

---

### Impact Explanation

- **`modeMintBurn = true`**: Attacker receives a freshly minted NFT on the counterpart chain for free. Unbounded repetition inflates NFT supply on the child chain.
- **`modeMintBurn = false`**: Attacker drains NFTs held in the bridge's custody on the counterpart chain. Each stolen NFT corresponds to a real NFT that a legitimate user deposited.
- In both cases `requestNonce` is incremented, permanently consuming a nonce slot and corrupting bridge accounting.

---

### Likelihood Explanation

The `onlyRegisteredToken` modifier restricts which tokens can be used, so the attack requires a registered non-standard ERC721 token. However, the bridge owner/operator controls registration and may register tokens without auditing their `transferFrom` revert behavior. The ERC20 bridge's use of `SafeERC20` shows the developers are aware of this class of bug for fungible tokens but did not apply the same discipline to ERC721.

---

### Recommendation

Replace the bare `IERC721.transferFrom` calls with `safeTransferFrom` (which reverts if the callee does not implement `IERC721Receiver` and also propagates any revert from the token), or add an explicit ownership check after the call:

```solidity
// In requestERC721Transfer — deposit path
IERC721(_tokenAddress).safeTransferFrom(msg.sender, address(this), _tokenId);

// In handleERC721Transfer — withdrawal path (lock/unlock mode)
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
```

Alternatively, assert post-transfer ownership:

```solidity
IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
require(IERC721(_tokenAddress).ownerOf(_tokenId) == address(this), "transfer failed");
```

---

### Proof of Concept

1. Deploy a non-standard ERC721 token whose `transferFrom` returns `false` instead of reverting when the caller is not the owner/approved.
2. Register the token with the bridge (operator action).
3. Call `requestERC721Transfer(tokenAddress, attackerAddress, tokenId, "")` from any EOA that does **not** own `tokenId`.
4. The bare `transferFrom` returns `false`; Solidity ignores it.
5. `_requestERC721Transfer` emits `RequestValueTransferEncoded` and increments `requestNonce`.
6. Counterpart bridge operators call `handleERC721Transfer` with the emitted data.
7. In `modeMintBurn` mode: `ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(attacker, tokenId, uri)` succeeds — attacker receives the NFT on the counterpart chain for free.
8. In lock/unlock mode: `IERC721(_tokenAddress).transferFrom(address(this), attacker, tokenId)` transfers a legitimately deposited NFT from the bridge's custody to the attacker. [6](#0-5) [5](#0-4)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L133-134)
```text
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L73-106)
```text
    // _requestERC721Transfer requests transfer ERC721 to _to on relative chain.
    function _requestERC721Transfer(
        address _tokenAddress,
        address _from,
        address _to,
        uint256 _tokenId,
        bytes memory _extraData
    )
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
        (bool success, bytes memory uri) = _tokenAddress.call(abi.encodePacked(ERC721Metadata(_tokenAddress).tokenURI.selector, abi.encode(_tokenId)));
        if (!success) {
            uri = "";
        }
        if (modeMintBurn) {
            ERC721Burnable(_tokenAddress).burn(_tokenId);
        }
        emit RequestValueTransferEncoded(
            TokenType.ERC721,
            _from,
            _to,
            _tokenAddress,
            _tokenId,
            requestNonce,
            0,
            _extraData,
            2,
            abi.encode(string(uri))
        );
        requestNonce++;
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

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/IERC721.sol (L44-44)
```text
    function transferFrom(address from, address to, uint256 tokenId) public;
```
