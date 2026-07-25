### Title
Missing Reentrancy Guard on `_requestERC721Transfer` Allows Duplicate Bridge Events via Registered Token Callback — (`contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

`_requestERC721Transfer` makes an external call to the registered token contract (`_tokenAddress.call(tokenURI selector, tokenId)`) **before** incrementing `requestNonce`. Unlike `_requestKLAYTransfer`, which carries an explicit `nonReentrant` modifier, neither `_requestERC721Transfer` nor its public entry points (`requestERC721Transfer`, `onERC721Received`) have any reentrancy protection. A malicious registered ERC721 token can re-enter the bridge via `onERC721Received` during that callback, emitting a second `RequestValueTransferEncoded` event with a consecutive nonce for a token that was never actually deposited. The counterpart bridge processes both nonces independently, minting or releasing bridged assets for both — while only one real token was locked.

---

### Finding Description

`_requestERC721Transfer` in `BridgeTransferERC721.sol` follows this order:

```
1. _tokenAddress.call(tokenURI selector, tokenId)   ← external call
2. ERC721Burnable(_tokenAddress).burn(_tokenId)      ← external call (mintBurn mode)
3. emit RequestValueTransferEncoded(..., requestNonce, ...)
4. requestNonce++                                    ← state update LAST
``` [1](#0-0) 

This violates the check-effect-interaction pattern. The `requestNonce` counter is the only sequencing guard for the counterpart bridge; it is incremented **after** the external call, not before.

By contrast, `_requestKLAYTransfer` is explicitly marked `nonReentrant`, and the comment in `BridgeFee.sol` acknowledges that `_payKLAYFeeAndRefundChange` requires its caller to be `nonReentrant`: [2](#0-1) [3](#0-2) 

No equivalent protection exists for the ERC721 (or ERC20) path.

The public entry point `onERC721Received` is callable by any registered token with no additional guard: [4](#0-3) 

`onERC721Received` does not verify that a token was actually transferred to the bridge before calling `_requestERC721Transfer`; it trusts `msg.sender` to be a registered token and proceeds unconditionally.

---

### Impact Explanation

**Exact corrupted value:** `requestNonce` is consumed twice (nonces N and N+1) for a single real deposit. The counterpart bridge's `handleERC721Transfer` (or `handleERC20Transfer`) processes both nonces independently, each passing `_lowerHandleNonceCheck` and `_voteValueTransfer`, and each triggering a mint or `transferFrom` to the attacker. [5](#0-4) [6](#0-5) 

The result is **unauthorized minting of bridged ERC721 assets** on the counterpart chain: the attacker deposits one token on the source chain and receives two tokens on the destination chain.

---

### Likelihood Explanation

Exploitation requires a malicious ERC721 token contract to be registered on the bridge. Token registration is an owner-controlled operation: [7](#0-6) 

This is the same "whitelisting" constraint present in the Kakarot analog. The likelihood is low but non-zero: a token contract that appears legitimate at registration time could contain a hidden backdoor in its `tokenURI` implementation, or a compromised bridge owner could register a malicious token. The potential for complete loss of bridged asset integrity justifies medium severity.

---

### Recommendation

1. Add `nonReentrant` to `requestERC721Transfer` and `onERC721Received` (or to `_requestERC721Transfer` itself), mirroring the protection already applied to `_requestKLAYTransfer`.
2. Increment `requestNonce` **before** any external call to the token contract (move `requestNonce++` to the top of `_requestERC721Transfer`, after the registration checks).
3. Apply the same fix to `_requestERC20Transfer`, which also makes external calls (`_payERC20FeeAndRefundChange` → `safeTransfer`, `ERC20Burnable.burn`) before `requestNonce++`. [8](#0-7) 

---

### Proof of Concept

1. Deploy a malicious ERC721 token `MaliciousToken` whose `tokenURI(uint256 tokenId)` function calls `bridge.onERC721Received(attacker, fakeTokenId, attacker, "")` before returning.
2. Register `MaliciousToken` on the bridge (owner step).
3. Attacker calls `bridge.requestERC721Transfer(MaliciousToken, attacker, realTokenId, "")`.
4. `MaliciousToken.transferFrom(attacker, bridge, realTokenId)` succeeds (real deposit, nonce = N at this point).
5. `_requestERC721Transfer` calls `MaliciousToken.call(tokenURI selector, realTokenId)`.
6. Inside `tokenURI`, `MaliciousToken` calls `bridge.onERC721Received(attacker, fakeTokenId, attacker, "")`.
7. Reentrant `_requestERC721Transfer` runs: emits `RequestValueTransferEncoded` with `requestNonce = N`; `requestNonce` becomes N+1.
8. Outer `_requestERC721Transfer` resumes: emits `RequestValueTransferEncoded` with `requestNonce = N+1`; `requestNonce` becomes N+2.
9. Counterpart bridge sees two valid events (nonces N and N+1) and mints/releases two tokens to the attacker.
10. Only one real token (`realTokenId`) was ever deposited. [9](#0-8) [4](#0-3)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L29-71)
```text
    function handleERC721Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _tokenId,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        string memory _tokenURI,
        bytes memory _extraData
    )
        public
        onlyOperators
    {
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L109-118)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-107)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L41-43)
```text
    // Caller of this function must be nonReentrant.
    // - BridgeTransferKLAY._requestKLAYTransfer() is nonReentrant
    function _payKLAYFeeAndRefundChange(uint256 _feeLimit) internal returns(uint256) {
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L138-156)
```text
    // _updateHandleNonce increases lower and upper handle nonce after the _requestedNonce is handled.
    function _updateHandleNonce(uint64 _requestedNonce) internal {
        if (_requestedNonce > upperHandleNonce) {
            upperHandleNonce = _requestedNonce;
        }

        uint64 limit = lowerHandleNonce + 200;
        if (limit > upperHandleNonce) {
            limit = upperHandleNonce;
        }

        uint64 i;
        for (i = lowerHandleNonce; i <= limit && handleNoncesToBlockNums[i] > 0; i++) {
            recoveryBlockNumber = handleNoncesToBlockNums[i];
            delete handleNoncesToBlockNums[i];
            delete closedValueTransferVotes[i];
        }
        lowerHandleNonce = i;
    }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L134-144)
```text
    // registerOperator registers a new operator.
    function registerOperator(address _operator)
    external
    onlyOwner
    {
        require(operatorList.length < MAX_OPERATOR, "max operator limit");
        require(!operators[_operator], "exist operator");
        operators[_operator] = true;
        operatorList.push(_operator);
        emit OperatorRegistered(_operator);
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
