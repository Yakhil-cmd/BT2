### Title
Unchecked ERC721 `transferFrom` Return in Service-Chain Bridge Allows Silent Asset Loss or Unauthorized Cross-Chain Minting — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.sol` calls `IERC721.transferFrom` at two sites without any success guard. The sibling contract `BridgeTransferERC20.sol` explicitly uses OpenZeppelin's `SafeERC20` (`safeTransfer` / `safeTransferFrom`) for every ERC-20 movement. No equivalent protection exists for ERC-721 transfers, so a non-reverting ERC-721 token can silently fail while the bridge advances its nonce and emits cross-chain events, corrupting the bridge's asset accounting.

---

### Finding Description

`BridgeTransferERC721.sol` contains two bare `IERC721.transferFrom` calls with no return-value or success check:

**Site 1 — `requestERC721Transfer` (deposit path, line 129):** [1](#0-0) 

```solidity
IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
_requestERC721Transfer(_tokenAddress, msg.sender, _to, _tokenId, _extraData);
```

If `transferFrom` does not revert (non-standard token), the bridge never receives the NFT, yet `_requestERC721Transfer` emits `RequestValueTransferEncoded` and increments `requestNonce`.

**Site 2 — `handleERC721Transfer` (withdrawal path, line 69):** [2](#0-1) 

```solidity
} else {
    IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
}
```

If `transferFrom` does not revert, the nonce is consumed and the `HandleValueTransfer` event is emitted, but the recipient never receives the NFT.

**Contrast with the ERC-20 bridge**, which correctly wraps every token movement: [3](#0-2) [4](#0-3) [5](#0-4) 

`BridgeFee.sol` also uses `SafeERC20` for every ERC-20 fee movement: [6](#0-5) 

Token registration is `onlyOwner`: [7](#0-6) 

`requestERC721Transfer` is unrestricted (`public`, no access modifier beyond `onlyRegisteredToken` / `onlyUnlockedToken` inside `_requestERC721Transfer`): [8](#0-7) 

---

### Impact Explanation

**Deposit path (Site 1):** Any user calling `requestERC721Transfer` with a registered non-reverting ERC-721 token causes the bridge to emit a cross-chain transfer event and advance `requestNonce` without ever holding the NFT. Bridge operators on the counterpart chain observe the event and call `handleERC721Transfer`, which mints or transfers an NFT to the recipient. The result is an NFT created on the counterpart chain backed by no locked asset — unauthorized minting of a bridged asset.

**Withdrawal path (Site 2):** Operators calling `handleERC721Transfer` with a non-reverting token consume the handle nonce and emit `HandleValueTransfer`, but the recipient never receives the NFT. The nonce is permanently spent; the user's bridged asset is permanently lost with no recourse.

Both outcomes match the allowed impact gate: *unauthorized transfer/mint of bridged assets* and *persistent corruption of bridge nonce/settlement state*.

---

### Likelihood Explanation

Likelihood is **low-to-medium**. Exploitation requires a registered ERC-721 token whose `transferFrom` does not revert on failure (non-standard behavior). Token registration is `onlyOwner`, so a compromised or negligent bridge owner is a prerequisite. However, the ERC-721 ecosystem contains many non-standard implementations, and the bridge is explicitly designed to support arbitrary registered tokens. The ERC-20 bridge's use of `SafeERC20` demonstrates that the developers were aware of this class of risk and mitigated it for ERC-20 but not ERC-721.

---

### Recommendation

Replace both bare `transferFrom` calls with `safeTransferFrom` using a low-level call pattern (analogous to `SafeERC20`), or add an explicit success check:

```solidity
// Deposit path
(bool ok,) = _tokenAddress.call(
    abi.encodeWithSelector(IERC721.transferFrom.selector, msg.sender, address(this), _tokenId)
);
require(ok, "ERC721 transferFrom failed");

// Withdrawal path
(bool ok,) = _tokenAddress.call(
    abi.encodeWithSelector(IERC721.transferFrom.selector, address(this), _to, _tokenId)
);
require(ok, "ERC721 transferFrom failed");
```

Alternatively, use `safeTransferFrom` (which also validates the receiver implements `IERC721Receiver` when `_to` is a contract):

```solidity
IERC721(_tokenAddress).safeTransferFrom(address(this), _to, _tokenId);
```

---

### Proof of Concept

1. Deploy a non-standard ERC-721 contract whose `transferFrom` emits no event and returns without reverting regardless of ownership.
2. Bridge owner calls `registerToken(maliciousNFT, counterpartNFT)`.
3. Attacker calls `requestERC721Transfer(maliciousNFT, victim, tokenId, "")`.
   - `IERC721(maliciousNFT).transferFrom(attacker, bridge, tokenId)` silently succeeds; bridge never holds the NFT.
   - `_requestERC721Transfer` emits `RequestValueTransferEncoded`; `requestNonce` increments.
4. Counterpart bridge operators observe the event and call `handleERC721Transfer` on the counterpart chain.
5. Counterpart bridge mints `counterpartNFT` tokenId to `victim`.
6. Attacker still owns `maliciousNFT` tokenId on the source chain; a new NFT exists on the counterpart chain — net unauthorized minting of a bridged asset.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L29-29)
```text
    using SafeERC20 for IERC20;
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L71-72)
```text
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L133-134)
```text
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L27-27)
```text
    using SafeERC20 for IERC20;
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L57-71)
```text
    function registerToken(address _token, address _cToken)
        external
        onlyOwner
        onlyNotRegisteredToken(_token)
    {
        // If _cToken == 0 then registeredTokens[_token] = 0, which confuses the
        // onlyRegisteredToken and onlyNotRegisteredToken modifiers.
        require(_cToken != address(0), "counterpart token address is zero");

        registeredTokens[_token] = _cToken;
        indexOfTokens[_token] = registeredTokenList.length;
        registeredTokenList.push(_token);

        emit TokenRegistered(_token);
    }
```
