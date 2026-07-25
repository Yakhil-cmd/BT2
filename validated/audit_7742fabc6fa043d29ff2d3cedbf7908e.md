### Title
`onERC721Received` Accepts Phantom Bridge Requests Without Verifying NFT Receipt — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

### Summary

`BridgeTransferERC721.onERC721Received` is declared `public` with no guard verifying that an actual ERC-721 transfer to the bridge occurred. Any registered token contract can call it directly, causing the bridge to emit `RequestValueTransferEncoded`, increment `requestNonce`, and trigger operators to execute `handleERC721Transfer` on the counterpart chain — minting an NFT there without any NFT ever being locked or burned on the source chain.

### Finding Description

`onERC721Received` is the 1-step deposit entry point. Its design assumption is that it is invoked by a token contract only after that contract has already transferred the NFT to the bridge (e.g., via `safeTransferFrom` → callback). However, the function is `public` with no such enforcement:

```solidity
// contracts/service_chain/bridge/BridgeTransferERC721.sol L108-118
function onERC721Received(
    address _from,
    uint256 _tokenId,
    address _to,
    bytes memory _extraData
)
    public          // ← no access control beyond onlyRegisteredToken(msg.sender)
{
    _requestERC721Transfer(msg.sender, _from, _to, _tokenId, _extraData);
}
``` [1](#0-0) 

`_requestERC721Transfer` then runs with `msg.sender` as the token address:

```solidity
// L73-106
internal onlyRegisteredToken(_tokenAddress) onlyUnlockedToken(_tokenAddress) {
    require(isRunning, "stopped bridge");
    // URI fetch (failure silently ignored)
    if (modeMintBurn) {
        ERC721Burnable(_tokenAddress).burn(_tokenId);   // only in mintBurn mode
    }
    // ← in lock (non-mintBurn) mode: NO check that bridge holds the NFT
    emit RequestValueTransferEncoded(...);
    requestNonce++;
}
``` [2](#0-1) 

In **lock (non-mintBurn) mode** on the source chain, the function emits the cross-chain request event and increments `requestNonce` without verifying that the bridge actually holds `_tokenId`. The `burn` path that would catch the missing NFT is skipped entirely.

Contrast with the 2-step path, which correctly enforces custody first:

```solidity
// L120-131
function requestERC721Transfer(...) public {
    IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId); // custody first
    _requestERC721Transfer(_tokenAddress, msg.sender, _to, _tokenId, _extraData);
}
``` [3](#0-2) 

On the counterpart chain, `handleERC721Transfer` in **mintBurn mode** unconditionally mints:

```solidity
// L66-70
if (modeMintBurn) {
    require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
} else {
    IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
}
``` [4](#0-3) 

### Impact Explanation

When the source bridge is in lock mode and the counterpart bridge is in mintBurn mode (a standard production configuration for service-chain ↔ mainchain bridges):

1. A registered token contract calls `bridge.onERC721Received(victim, tokenId, attacker, "")` directly — no NFT is transferred.
2. Source chain: `RequestValueTransferEncoded` is emitted, `requestNonce` is incremented. Transaction succeeds.
3. Bridge operators observe the event and call `handleERC721Transfer` on the counterpart chain.
4. Counterpart chain: `mintWithTokenURI(attacker, tokenId, uri)` executes successfully, minting a bridged NFT to the attacker.

Result: an NFT is minted on the counterpart chain with no corresponding NFT locked on the source chain — a direct unauthorized mint of a bridged asset.

### Likelihood Explanation

The trigger requires `msg.sender` to be a registered token (`onlyRegisteredToken`). Token registration is owner-controlled, making the direct attacker a semi-trusted registered token contract. This matches the H-07 case 3 ("a malicious contract deployed to take advantage of this behavior"). A legitimate registered token contract with a buggy `requestValueTransfer` implementation (one that calls `onERC721Received` before completing the transfer) also triggers the same path without any malicious intent.

### Recommendation

Add a balance/ownership check inside `onERC721Received` (or `_requestERC721Transfer` in lock mode) to verify the bridge actually holds the NFT before emitting the cross-chain request:

```solidity
function onERC721Received(
    address _from,
    uint256 _tokenId,
    address _to,
    bytes memory _extraData
) public {
    // Verify the bridge actually received the token
    require(
        IERC721(msg.sender).ownerOf(_tokenId) == address(this),
        "bridge does not hold token"
    );
    _requestERC721Transfer(msg.sender, _from, _to, _tokenId, _extraData);
}
```

Alternatively, restrict `onERC721Received` so it can only be reached via a `safeTransferFrom` call (e.g., by checking that the call originates from within a transfer callback context), or require that the 1-step path always goes through `safeTransferFrom` which atomically transfers and calls the receiver.

### Proof of Concept

```solidity
// MaliciousToken is registered as a token in the source bridge (lock mode)
contract MaliciousToken {
    BridgeTransferERC721 bridge;

    function exploit(uint256 tokenId, address victim, address attacker) external {
        // Call onERC721Received directly — no NFT is transferred to the bridge
        bridge.onERC721Received(victim, tokenId, attacker, "");
        // RequestValueTransferEncoded is now emitted; requestNonce incremented
        // Operators will mint tokenId to attacker on the counterpart (mintBurn) chain
    }
}
```

The source chain transaction succeeds. Bridge operators relay the event. On the counterpart chain (mintBurn mode), `handleERC721Transfer` calls `mintWithTokenURI(attacker, tokenId, "")` and succeeds, delivering an NFT to the attacker with no NFT ever locked on the source chain. [1](#0-0) [4](#0-3)

### Citations

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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L108-118)
```text
    // onERC721Received function of ERC721 token for 1-step deposits to the Bridge
    function onERC721Received(
        address _from,
        uint256 _tokenId,
        address _to,
        bytes memory _extraData
    )
        public
    {
        _requestERC721Transfer(msg.sender, _from, _to, _tokenId, _extraData);
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
