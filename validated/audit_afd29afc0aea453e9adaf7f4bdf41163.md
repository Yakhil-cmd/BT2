### Title
Missing Reentrancy Guard on `_requestERC721Transfer` Allows Fraudulent Bridge Requests via `tokenURI` External Call — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`BridgeTransferERC721._requestERC721Transfer()` makes an external call to `_tokenAddress.call(tokenURI selector, tokenId)` **before** incrementing `requestNonce`, with no reentrancy guard. A malicious registered ERC721 token can exploit this to emit a fraudulent `RequestValueTransferEncoded` event (with the current nonce) for a token that was never deposited into the bridge. Counterpart-chain operators process this event and mint or transfer the bridged asset to the attacker for free.

`BridgeTransferKLAY` explicitly uses `nonReentrant` on both `handleKLAYTransfer` and `_requestKLAYTransfer`, and `BridgeFee.sol` even documents "Caller of this function must be nonReentrant." — but `BridgeTransferERC20` and `BridgeTransferERC721` have no such guard.

---

### Finding Description

`BridgeTransferKLAY` inherits `ReentrancyGuard` and marks both its request and handle functions `nonReentrant`: [1](#0-0) [2](#0-1) [3](#0-2) 

`BridgeFee.sol` explicitly documents this requirement: [4](#0-3) 

`BridgeTransferERC721` does **not** inherit `ReentrancyGuard` and has no `nonReentrant` modifier anywhere. Inside `_requestERC721Transfer`, an external call is made to the token contract to fetch the URI **before** `requestNonce` is incremented: [5](#0-4) 

The public entry points `requestERC721Transfer` and `onERC721Received` are both unguarded: [6](#0-5) 

`BridgeTransferERC20` has the same problem: `_requestERC20Transfer` calls `_payERC20FeeAndRefundChange`, which makes two `safeTransfer` external calls before `requestNonce++`, with no reentrancy guard: [7](#0-6) [8](#0-7) 

---

### Impact Explanation

**Unauthorized minting of bridged assets on the counterpart chain.**

In `mintBurn` mode, the counterpart bridge calls `ERC721MetadataMintable.mintWithTokenURI(_to, _tokenId, _tokenURI)` for every `RequestValueTransferEncoded` event that reaches operator threshold: [9](#0-8) 

If the attacker's fraudulent event (for a token never deposited) reaches threshold, a new NFT is minted to the attacker on the counterpart chain at no cost. In non-`mintBurn` mode, the attacker receives any token the counterpart bridge already holds with the spoofed `tokenId`.

The corrupted value is: **`requestNonce` consumed for a deposit that never occurred**, and **a bridged asset minted/transferred without a corresponding source-chain deposit**.

---

### Likelihood Explanation

**Medium.** The attack requires a malicious ERC721 token to be registered by the bridge owner (`onlyOwner`). However:
- Bridge owners routinely register new tokens without full contract audits.
- The malicious token can appear legitimate (normal `transferFrom`, normal metadata) and only activate the reentrant `tokenURI` callback after registration.
- The `onERC721Received` entry point is `public` with no caller restriction, so once the token is registered, any call path through it is exploitable. [10](#0-9) 

---

### Recommendation

1. Add `ReentrancyGuard` to `BridgeTransferERC721` (and `BridgeTransferERC20`) and mark `requestERC721Transfer`, `onERC721Received`, `requestERC20Transfer`, and `onERC20Received` as `nonReentrant`, consistent with `BridgeTransferKLAY`.
2. Move `requestNonce++` to **before** any external call (checks-effects-interactions pattern).
3. Consider moving the `_tokenAddress.call(tokenURI)` fetch outside of `_requestERC721Transfer` entirely, or caching it before any state-modifying logic. [11](#0-10) 

---

### Proof of Concept

```
Setup:
  - Deploy MaliciousNFT: implements ERC721; tokenURI(id) calls bridge.onERC721Received(attacker, 999, attacker, "")
  - Bridge owner registers MaliciousNFT (attacker deceives owner with a normal-looking token)
  - Attacker mints tokenId=1 to themselves on MaliciousNFT

Attack:
  1. attacker calls bridge.requestERC721Transfer(MaliciousNFT, attacker, 1, "")
  2. MaliciousNFT.transferFrom(attacker, bridge, 1)  ← tokenId=1 deposited
  3. bridge calls _requestERC721Transfer(MaliciousNFT, attacker, attacker, 1, "")
  4. bridge calls MaliciousNFT.tokenURI(1)  ← external call, requestNonce still = N
  5. MaliciousNFT.tokenURI calls bridge.onERC721Received(attacker, 999, attacker, "")
  6. bridge calls _requestERC721Transfer(MaliciousNFT, attacker, attacker, 999, "")
       → emits RequestValueTransferEncoded(nonce=N, tokenId=999)  ← FRAUDULENT
       → requestNonce = N+1
  7. outer call resumes, emits RequestValueTransferEncoded(nonce=N+1, tokenId=1)
       → requestNonce = N+2

Counterpart chain:
  - Operators vote on nonce=N event (tokenId=999, to=attacker)
  - handleERC721Transfer calls mintWithTokenURI(attacker, 999, uri)
  - Attacker receives tokenId=999 minted for FREE — no corresponding deposit on source chain
``` [5](#0-4) [10](#0-9) [9](#0-8)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L20-23)
```text
import "../../libs/openzeppelin-contracts-v2/contracts/utils/ReentrancyGuard.sol";


contract BridgeTransferKLAY is BridgeTransfer, ReentrancyGuard {
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L73-73)
```text
        nonReentrant
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-106)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L41-43)
```text
    // Caller of this function must be nonReentrant.
    // - BridgeTransferKLAY._requestKLAYTransfer() is nonReentrant
    function _payKLAYFeeAndRefundChange(uint256 _feeLimit) internal returns(uint256) {
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L68-88)
```text
    function _payERC20FeeAndRefundChange(address from, address _token, uint256 _feeLimit) internal returns(uint256) {
        uint256 fee = feeOfERC20[_token];

        if (feeReceiver != address(0) && fee > 0) {
            require(_feeLimit >= fee, "insufficient feeLimit");

            IERC20(_token).safeTransfer(feeReceiver, fee);

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                IERC20(_token).safeTransfer(from, feeRefund);
            }

            return fee;
        }

        if (_feeLimit > 0) {
            IERC20(_token).safeTransfer(from, _feeLimit);
        }
        return 0;
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L85-106)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L108-131)
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L88-108)
```text
        require(isRunning, "stopped bridge");
        require(_value > 0, "zero ERC20 token amount");

        uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);

        if (modeMintBurn) {
            ERC20Burnable(_tokenAddress).burn(_value);
        }

        emit RequestValueTransfer(
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            requestNonce,
            fee,
            _extraData
        );
        requestNonce++;
    }
```
