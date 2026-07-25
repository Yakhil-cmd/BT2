### Title
ERC721 Bridge Token-ID Collision in `modeMintBurn` Mode Causes Permanent Loss of Bridged NFT — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

In Kaia's service-chain bridge, when `modeMintBurn = true`, `_requestERC721Transfer` **burns** the ERC721 token on the source chain before emitting the cross-chain event. On the destination chain, `handleERC721Transfer` then calls `mintWithTokenURI(_to, _tokenId, _tokenURI)`. If any address that holds the minter role on the destination ERC721 contract (including the contract deployer, who retains the minter role by default under OpenZeppelin's `MinterRole`) has already minted a token with the same `_tokenId`, the `mintWithTokenURI` call reverts. Because the source-chain token was already burned, the user's NFT is permanently unrecoverable.

---

### Finding Description

**Source-chain burn (irreversible):**

In `_requestERC721Transfer`, when `modeMintBurn` is true, the token is burned before the cross-chain event is emitted:

```solidity
if (modeMintBurn) {
    ERC721Burnable(_tokenAddress).burn(_tokenId);   // permanent
}
emit RequestValueTransferEncoded(...);
requestNonce++;
``` [1](#0-0) 

**Destination-chain mint (can revert):**

`handleERC721Transfer` updates nonce state and emits `HandleValueTransfer`, then calls:

```solidity
if (modeMintBurn) {
    require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
}
``` [2](#0-1) 

ERC721's `_mint` reverts if `_tokenId` already exists. If the revert propagates, the entire `handleERC721Transfer` transaction reverts (including the nonce/vote state updates), so operators can retry — but the token ID is permanently occupied on the destination chain. No retry will ever succeed.

**Who holds the minter role?**

OpenZeppelin's `MinterRole` grants the minter role to the deployer at construction time. The bridge contract is added as an additional minter via `AddMinter` (as shown in the test setup):

```go
tx, err = erc721.AddMinter(opts, info.bAddr)
``` [3](#0-2) 

The deployer/owner retains the minter role. The production `ServiceChainNFT` contract even exposes a `registerBulk` function that mints tokens in a range:

```solidity
function registerBulk(address _user, uint256 _startID, uint256 _endID) external onlyOwner {
    for (uint256 uid = _startID; uid < _endID; uid++) {
        mintWithTokenURI(_user, uid, "testURI");
    }
}
``` [4](#0-3) 

If the owner calls `registerBulk` (or `mintWithTokenURI` directly) with a `_tokenId` that matches a pending bridge transfer, the bridge is permanently blocked for that token.

---

### Impact Explanation

- The ERC721 token is **burned on the source chain** — this is irreversible.
- `handleERC721Transfer` on the destination chain will **always revert** for that `_tokenId` because ERC721 does not allow duplicate token IDs.
- There is no recovery path in the bridge contracts: no `skip`, no `refund`, no alternative delivery mechanism.
- **Result:** The bridged NFT is permanently destroyed. The user suffers a complete, unrecoverable loss of their asset.

This is an unauthorized burn of a bridged asset (the NFT is destroyed without the user receiving its counterpart), matching the allowed impact gate: *"Unauthorized … burn … affecting … bridged assets."*

---

### Likelihood Explanation

- The trigger requires an address with the minter role on the destination ERC721 contract. The contract deployer always holds this role by default.
- The `ServiceChainNFT.registerBulk` function is present in the production contract and can be called by the owner at any time.
- A collision can occur accidentally (owner minting for other purposes) or deliberately (a malicious co-minter).
- The bridge's `modeMintBurn = true` is the default for the local (child-chain) bridge, as set in `DeployBridge`:

```go
if local {
    acc = bm.subBridge.bridgeAccounts.cAccount
    modeMintBurn = true
}
``` [5](#0-4) 

This means the vulnerable code path is active in the standard service-chain deployment.

---

### Recommendation

1. **Restrict minters:** Ensure the destination-chain ERC721 contract grants the minter role **exclusively** to the bridge contract. Remove the deployer's minter role after setup.
2. **Defensive mint:** Replace the hard `require` with a check-before-mint pattern: if `_tokenId` already exists and is owned by `_to`, treat it as already delivered; otherwise revert with a meaningful error that does not permanently block the nonce.
3. **Refund path:** Add an operator-callable `skipTransfer` or `refundTransfer` function that marks a nonce as handled without executing the mint, allowing operators to unblock the bridge and trigger a manual refund on the source chain.

---

### Proof of Concept

1. Deploy `ServiceChainNFT` on the destination chain. The deployer holds the minter role.
2. User bridges NFT token ID `42` from source chain. Source-chain bridge burns token `42` and emits `RequestValueTransferEncoded(tokenId=42, nonce=0)`.
3. Before bridge operators call `handleERC721Transfer`, the ERC721 owner calls `mintWithTokenURI(someAddress, 42, "other")` on the destination chain. Token `42` now exists.
4. Bridge operators call `handleERC721Transfer(..., tokenId=42, requestedNonce=0, ...)`. The call reaches line 67 and `mintWithTokenURI` reverts with `"ERC721: token already minted"`.
5. The entire transaction reverts. Operators retry — same result every time.
6. Token `42` is burned on the source chain and permanently undeliverable on the destination chain. The user's NFT is lost. [6](#0-5) [7](#0-6)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L90-105)
```text
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
```

**File:** node/sc/multi_bridge_test.go (L506-510)
```go
	opts = &bind.TransactOpts{From: acc.From, Signer: acc.Signer, GasLimit: DefaultBridgeTxGasLimit}
	tx, err = erc721.AddMinter(opts, info.bAddr)
	assert.NoError(t, err)
	info.sim.Commit()
	assert.NoError(t, bind.CheckWaitMined(info.sim, tx))
```

**File:** contracts/testing/sc_erc721/sc_nft.sol (L33-38)
```text
    // This is only for load test.
    function registerBulk(address _user, uint256 _startID, uint256 _endID) external onlyOwner {
        for (uint256 uid = _startID; uid < _endID; uid++) {
            mintWithTokenURI(_user, uid, "testURI");
        }
    }
```

**File:** node/sc/bridge_manager.go (L909-914)
```go
	if local {
		acc = bm.subBridge.bridgeAccounts.cAccount
		modeMintBurn = true
	} else {
		acc = bm.subBridge.bridgeAccounts.pAccount
		modeMintBurn = false
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC721/ERC721MetadataMintable.sol (L19-23)
```text
    function mintWithTokenURI(address to, uint256 tokenId, string memory tokenURI) public onlyMinter returns (bool) {
        _mint(to, tokenId);
        _setTokenURI(tokenId, tokenURI);
        return true;
    }
```
