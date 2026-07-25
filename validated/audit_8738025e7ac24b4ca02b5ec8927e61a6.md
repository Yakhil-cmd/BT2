### Title
Unchecked `transferFrom` Return in ERC721 Bridge Allows Silent Failure to Drain Counterpart Bridge Assets — (File: `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

### Summary

`BridgeTransferERC721.sol` calls `IERC721(_tokenAddress).transferFrom(...)` in both `requestERC721Transfer` and `handleERC721Transfer` without any success check. Unlike the ERC20 bridge — which correctly uses `SafeERC20`'s `safeTransferFrom`/`safeTransfer` throughout — the ERC721 bridge uses bare `transferFrom` calls. If a registered ERC721 token silently fails (does not revert on a failed transfer), the bridge state advances (nonce incremented, event emitted) without actual token custody changing hands.

### Finding Description

In `BridgeTransferERC721.sol`, two locations call `IERC721(_tokenAddress).transferFrom(...)` with no return-value check and no revert guard:

**Location 1 — `requestERC721Transfer` (deposit path):** [1](#0-0) 

**Location 2 — `handleERC721Transfer` (withdrawal path):** [2](#0-1) 

By contrast, the ERC20 bridge declares `using SafeERC20 for IERC20` and uses `safeTransferFrom`/`safeTransfer` everywhere: [3](#0-2) [4](#0-3) [5](#0-4) 

`BridgeFee.sol` also uses `safeTransfer` for all ERC20 fee payments: [6](#0-5) 

The ERC721 bridge has no analogous protection.

### Impact Explanation

**Deposit path (`requestERC721Transfer`):** If a registered ERC721 token's `transferFrom` silently returns without reverting when the caller does not own the token (or has no approval), the call at line 129 succeeds without moving the token. `_requestERC721Transfer` then executes unconditionally: it emits `RequestValueTransferEncoded` and increments `requestNonce`. [7](#0-6) 

The counterpart bridge operators observe the event and call `handleERC721Transfer` on the other chain, releasing a real ERC721 token to the attacker — who deposited nothing. This is an unauthorized extraction of bridged ERC721 assets from the counterpart bridge's custody.

**Withdrawal path (`handleERC721Transfer`):** If the `transferFrom` at line 69 silently fails, the bridge nonce is already committed (`_updateHandleNonce` has run, `handleNoncesToBlockNums` updated, `closedValueTransferVotes` deleted), but the user never receives their token. The request is permanently marked handled with no recourse. [8](#0-7) 

### Likelihood Explanation

The ERC721 standard (EIP-721) requires `transferFrom` to throw on failure, so standard-compliant tokens are not affected. However, the bridge's `onlyRegisteredToken` modifier does not enforce standard compliance — any address registered by operators is accepted. Non-standard ERC721 implementations (e.g., tokens with no-op `transferFrom`, upgradeable proxies with broken logic, or tokens on service chains with custom behavior) that silently succeed without transferring ownership would trigger this path. The deposit path (`requestERC721Transfer`) is callable by any unprivileged user. [9](#0-8) 

### Recommendation

Replace both bare `transferFrom` calls with `safeTransferFrom` (the ERC721 variant that reverts if the recipient cannot handle ERC721 tokens) and add explicit ownership verification before and after the call, or use a pattern analogous to `SafeERC20` that asserts the token owner changed. At minimum, verify `ownerOf(_tokenId) == address(this)` after the deposit call and `ownerOf(_tokenId) == _to` after the withdrawal call to detect silent failures.

### Proof of Concept

1. Deploy a non-standard ERC721 token whose `transferFrom` is a no-op (does not revert, does not change ownership).
2. Register this token on the service-chain bridge via the operator.
3. Call `requestERC721Transfer(tokenAddress, victimAddress, tokenId, extraData)` from an account that does not own `tokenId`.
4. The `transferFrom` at line 129 silently succeeds; `_requestERC721Transfer` emits `RequestValueTransferEncoded` with `requestNonce = N` and increments `requestNonce`.
5. The counterpart bridge operators observe the event and call `handleERC721Transfer` on the main chain, releasing a real ERC721 token (held in the counterpart bridge's custody) to `victimAddress` (or any `_to` the attacker specified).
6. The attacker has extracted a real bridged ERC721 asset without depositing anything. [10](#0-9) [11](#0-10)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L93-105)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L29-29)
```text
    using SafeERC20 for IERC20;
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L71-71)
```text
            IERC20(_tokenAddress).safeTransfer(_to, _value);
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L133-133)
```text
        IERC20(_tokenAddress).safeTransferFrom(msg.sender, address(this), _value.add(_feeLimit));
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L74-85)
```text
            IERC20(_token).safeTransfer(feeReceiver, fee);

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                IERC20(_token).safeTransfer(from, feeRefund);
            }

            return fee;
        }

        if (_feeLimit > 0) {
            IERC20(_token).safeTransfer(from, _feeLimit);
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L139-156)
```text
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
