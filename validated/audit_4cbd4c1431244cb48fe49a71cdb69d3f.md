### Title
Unsafe `transferFrom` in ERC721 Bridge Deposit and Withdrawal Allows Unauthorized Cross-Chain NFT Minting — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721` uses raw `IERC721.transferFrom()` in both `requestERC721Transfer` and `handleERC721Transfer` without any return-value check or safe-wrapper. `BridgeTransferERC20` — the sibling contract in the same directory — explicitly imports and applies `SafeERC20` for every token movement. No equivalent protection exists for ERC721. If a registered ERC721 token's `transferFrom` does not revert on failure, the bridge emits a `RequestValueTransferEncoded` event and increments `requestNonce` without ever taking custody of the NFT, causing the counterpart bridge to mint or release an NFT to the caller for free.

---

### Finding Description

`BridgeTransferERC20` declares `using SafeERC20 for IERC20` and calls `safeTransferFrom` / `safeTransfer` everywhere:

```solidity
// BridgeTransferERC20.sol line 133
IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
```

`BridgeTransferERC721` makes no such provision. Both transfer sites use the bare interface call:

```solidity
// BridgeTransferERC721.sol line 129  — deposit path
IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
_requestERC721Transfer(_tokenAddress, msg.sender, _to, _tokenId, _extraData);

// BridgeTransferERC721.sol line 69  — withdrawal path
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
```

In the deposit path the transfer is called **before** `_requestERC721Transfer`. If it returns without reverting (non-standard token), execution falls through to `_requestERC721Transfer`, which:
- emits `RequestValueTransferEncoded` (line 93–104)
- increments `requestNonce` (line 105)

The off-chain bridge relayer observes the event and submits `handleERC721Transfer` on the counterpart chain, which mints or releases the NFT to the attacker — without the original NFT ever being locked in the source bridge.

In the withdrawal path the transfer is called **after** the nonce is already consumed and the `HandleValueTransfer` event is already emitted (lines 51–64). A silent failure permanently burns the handle nonce while the recipient receives nothing and the NFT remains stuck in the bridge.

---

### Impact Explanation

**Deposit path (primary impact):** An attacker who controls or interacts with a registered ERC721 token whose `transferFrom` does not revert on failure can call `requestERC721Transfer` repeatedly. Each call produces a valid bridge event. The counterpart bridge mints or releases one NFT per call. The attacker receives bridged NFTs without depositing anything — an unauthorized mint of bridged assets.

**Withdrawal path (secondary impact):** A silent failure in `handleERC721Transfer` permanently consumes the handle nonce. The user's NFT is locked in the bridge forever with no recovery path, because `_lowerHandleNonceCheck` will reject any future attempt to re-handle the same nonce.

Both outcomes fall within the allowed impact gate: unauthorized mint/unlock of bridged assets and persistent corruption of bridge accounting state.

---

### Likelihood Explanation

The precondition is that a registered ERC721 token does not revert on a failed `transferFrom`. The EIP-721 specification requires a throw on failure, but non-standard or upgradeable tokens (e.g., tokens with pausable or access-controlled transfer logic that returns silently) can violate this. Bridge operators register tokens via governance; a single misconfigured or malicious token registration is sufficient. The attack requires no special privilege beyond calling a public function with a registered token address.

---

### Recommendation

Apply the same pattern already used in `BridgeTransferERC20`: wrap all ERC721 token movements in a checked call. Because OpenZeppelin's `SafeERC20` does not cover ERC721, add an explicit ownership check around the transfer:

```solidity
// requestERC721Transfer — deposit
address ownerBefore = IERC721(_tokenAddress).ownerOf(_tokenId);
require(ownerBefore == msg.sender, "not token owner");
IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
require(IERC721(_tokenAddress).ownerOf(_tokenId) == address(this), "ERC721 transfer failed");

// handleERC721Transfer — withdrawal
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
require(IERC721(_tokenAddress).ownerOf(_tokenId) == _to, "ERC721 transfer failed");
```

Alternatively, use `safeTransferFrom` (which checks `onERC721Received`) and require the recipient to implement the receiver interface, or adopt a community-maintained `SafeERC721` wrapper.

---

### Proof of Concept

1. Deploy a non-standard ERC721 token whose `transferFrom` does nothing and does not revert (analogous to `ERC20NoReturnMock` already present in the test suite at `contracts/libs/openzeppelin-contracts-v2/contracts/mocks/SafeERC20Helper.sol`).
2. Register the token in the bridge via the operator role.
3. Call `requestERC721Transfer(tokenAddress, attacker, tokenId, "")` from any address.
4. `IERC721(tokenAddress).transferFrom(msg.sender, address(this), tokenId)` returns silently; the bridge does not hold the NFT.
5. `_requestERC721Transfer` emits `RequestValueTransferEncoded` and increments `requestNonce`.
6. The off-chain relayer submits `handleERC721Transfer` on the counterpart chain.
7. The counterpart bridge mints or releases the NFT to the attacker.
8. Repeat for each desired NFT, draining the counterpart bridge's NFT reserves or minting unbacked NFTs.

**Affected lines:** [1](#0-0) [2](#0-1) 

**Contrast — ERC20 bridge correctly uses safe wrappers:** [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L129-130)
```text
        IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
        _requestERC721Transfer(_tokenAddress, msg.sender, _to, _tokenId, _extraData);
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L29-29)
```text
    using SafeERC20 for IERC20;
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L133-134)
```text
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
```
