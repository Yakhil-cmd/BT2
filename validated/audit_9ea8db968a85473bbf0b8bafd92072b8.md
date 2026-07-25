### Title
Unchecked `IERC721.transferFrom()` Return in Service-Chain Bridge Allows Unauthorized Cross-Chain ERC721 Minting/Release — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721.sol` calls `IERC721(_tokenAddress).transferFrom()` without any safe wrapper or success check at two sites. The ERC20 sibling contract (`BridgeTransferERC20.sol`) explicitly imports and uses OpenZeppelin `SafeERC20` for every token movement, but the ERC721 contract has no equivalent protection. For a registered non-standard ERC721 token whose `transferFrom` does not revert on failure, the bridge records a cross-chain transfer request (emits event, increments nonce) without ever taking custody of the token, causing the counterpart bridge to mint or release an ERC721 that was never locked.

---

### Finding Description

`BridgeTransferERC20.sol` imports `SafeERC20` and declares `using SafeERC20 for IERC20` at the top of the file: [1](#0-0) 

Every ERC20 movement in that contract goes through `safeTransfer` / `safeTransferFrom`: [2](#0-1) [3](#0-2) 

`BridgeTransferERC721.sol` imports no safe wrapper and makes two raw calls:

**Site 1 — deposit path (`requestERC721Transfer`, line 129):** [4](#0-3) 

**Site 2 — withdrawal path (`handleERC721Transfer`, line 69):** [5](#0-4) 

`registerToken` in `BridgeTokens.sol` imposes no constraint that the registered address must be a standards-compliant ERC721; it only requires a non-zero counterpart address: [6](#0-5) 

---

### Impact Explanation

**Site 1 (deposit, higher severity):** A user calls `requestERC721Transfer` with a registered non-standard ERC721 token whose `transferFrom` silently returns without reverting. The bridge never receives the token, yet `_requestERC721Transfer` emits `RequestValueTransferEncoded` and increments `requestNonce`. Bridge operators on the counterpart chain observe the event and call `handleERC721Transfer`:

- **mintBurn mode:** `ERC721MetadataMintable.mintWithTokenURI` mints a fresh token for the attacker — an ERC721 asset is created on the counterpart chain with no corresponding locked asset on the source chain.
- **lock mode:** The counterpart bridge transfers one of its held tokens to the attacker — an ERC721 asset is drained from the bridge's reserves.

**Site 2 (withdrawal, lower severity):** `handleERC721Transfer` is `onlyOperators`, so the trigger requires a compromised or malicious operator. If the `transferFrom` at line 69 silently fails, the handle nonce is consumed and the `HandleValueTransfer` event is emitted, but the recipient never receives the token. The asset is permanently locked in the bridge with no recovery path.

---

### Likelihood Explanation

The deposit path (Site 1) is reachable by any unprivileged user who holds a token ID of a registered non-standard ERC721. The only prerequisite is that the bridge owner has registered such a token — `registerToken` performs no interface validation. Non-standard ERC721 implementations (e.g., tokens that return `false` instead of reverting, or tokens with no-op `transferFrom` under certain conditions) exist in the wild. The ERC20 bridge's explicit use of `SafeERC20` demonstrates that the Kaia developers are aware of this class of issue, making the omission in the ERC721 bridge an oversight rather than an intentional design choice.

---

### Recommendation

Apply the same safe-call pattern to ERC721 transfers. OpenZeppelin does not ship a `SafeERC721` library, but the equivalent protection can be implemented inline:

```solidity
// In requestERC721Transfer (deposit)
address ownerBefore = IERC721(_tokenAddress).ownerOf(_tokenId);
IERC721(_tokenAddress).transferFrom(msg.sender, address(this), _tokenId);
require(IERC721(_tokenAddress).ownerOf(_tokenId) == address(this), "ERC721 transfer failed");

// In handleERC721Transfer (withdrawal, lock mode)
IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
require(IERC721(_tokenAddress).ownerOf(_tokenId) == _to, "ERC721 transfer failed");
```

Alternatively, use `safeTransferFrom` (which invokes `onERC721Received` on the recipient) and verify ownership after the call, or add an interface-compliance check inside `registerToken`.

---

### Proof of Concept

1. Deploy a non-standard ERC721 token `BadNFT` whose `transferFrom` emits a `Transfer` event but does not actually change ownership and does not revert.
2. Bridge owner calls `registerToken(badNFT, counterpartNFT)` — succeeds because `BridgeTokens.registerToken` only checks `_cToken != address(0)`.
3. Attacker (who holds token ID 1 of `BadNFT`) calls:
   ```solidity
   bridge.requestERC721Transfer(badNFT, attacker, 1, "");
   ```
4. `IERC721(badNFT).transferFrom(attacker, bridge, 1)` silently does nothing. `ownerOf(1)` still returns `attacker`.
5. `_requestERC721Transfer` passes `onlyRegisteredToken` and `onlyUnlockedToken`, emits `RequestValueTransferEncoded`, and increments `requestNonce`.
6. Counterpart bridge operators observe the event and call `handleERC721Transfer` on the counterpart bridge.
7. In mintBurn mode: `ERC721MetadataMintable(counterpartNFT).mintWithTokenURI(attacker, 1, uri)` succeeds — attacker now owns token ID 1 on the counterpart chain without ever surrendering token ID 1 on the source chain. [7](#0-6) [5](#0-4)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L22-29)
```text
import "../../libs/openzeppelin-contracts-v2/contracts/token/ERC20/SafeERC20.sol";

import "../../service_chain/IERC20BridgeReceiver.sol";
import "./BridgeTransfer.sol";


contract BridgeTransferERC20 is BridgeTokens, IERC20BridgeReceiver, BridgeTransfer {
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
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
