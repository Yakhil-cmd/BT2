### Title
Raw `ERC20Mintable.mint()` in `handleERC20Transfer()` Permanently Bricks Bridge Transfers for Non-Bool-Returning Tokens — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.handleERC20Transfer()` calls `ERC20Mintable(_tokenAddress).mint(_to, _value)` via a raw high-level Solidity interface call wrapped in `require()`. Solidity's ABI decoder expects the callee to return a `bool`. If a registered token's `mint()` implementation returns no data (non-standard), the decoder reverts unconditionally. This permanently bricks `handleERC20Transfer()` for that token in `modeMintBurn` mode: operators can never complete the bridge transfer, while the user's tokens have already been burned on the source chain — a permanent, irrecoverable loss of bridged assets.

---

### Finding Description

In `modeMintBurn` mode, the bridge burns tokens on the source chain via `ERC20Burnable(_tokenAddress).burn(_value)` inside `_requestERC20Transfer()`, and is expected to mint them on the destination chain via `handleERC20Transfer()`. The mint call at line 69 is:

```solidity
require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
```

This is a raw high-level interface call. The `ERC20Mintable` interface (from the bundled OpenZeppelin v2 library) declares `mint()` as `returns (bool)`:

```solidity
// ERC20Mintable.sol line 20
function mint(address account, uint256 amount) public onlyMinter returns (bool) {
    _mint(account, amount);
    return true;
}
```

Solidity's generated ABI decoder for this call expects at least 32 bytes of return data encoding a `bool`. When a non-standard token's `mint()` executes but returns no data (empty returndata), the decoder reverts — not because the mint failed, but because the return-data decoding fails. The `require()` message `"handleERC20Transfer: mint failed"` is never even reached.

The non-`modeMintBurn` path on line 71 correctly uses `IERC20(_tokenAddress).safeTransfer(_to, _value)` via `SafeERC20`, which explicitly handles empty returndata:

```solidity
// SafeERC20.sol lines 67-73
(bool success, bytes memory returndata) = address(token).call(data);
require(success, "SafeERC20: low-level call failed");
if (returndata.length > 0) {
    require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
}
```

No equivalent protection exists for the `mint()` call site.

---

### Impact Explanation

For any bridge in `modeMintBurn` mode with a registered token whose `mint()` does not return a `bool`:

- `handleERC20Transfer()` reverts on every operator call — the ABI decoder fails before any state is committed (all state changes in `_setHandledRequestTxHash`, `handleNoncesToBlockNums`, `_updateHandleNonce` are rolled back).
- Operators can never accumulate a quorum that survives to completion; every attempt reverts.
- The user's tokens are already burned on the source chain (in `_requestERC20Transfer`, `ERC20Burnable(_tokenAddress).burn(_value)` executes and commits before the cross-chain message is sent).
- The bridged asset is permanently destroyed on the source chain and never recreated on the destination chain.
- Additionally, because `handleNoncesToBlockNums[_requestedNonce]` is never set, `_updateHandleNonce`'s sequential scan (`handleNoncesToBlockNums[i] > 0`) stalls at the stuck nonce, preventing `lowerHandleNonce` from ever advancing past it — degrading the bridge's nonce-accounting for all subsequent transfers.

---

### Likelihood Explanation

The trigger requires a registered token whose `mint()` returns no value. Non-standard ERC20 tokens that omit the `bool` return from `mint()` exist in practice (analogous to USDT's non-returning `transfer()`/`approve()`). The bridge owner controls registration, but the defect is in the bridge code itself — no validation of the token's ABI compliance is performed at registration time. Any operator-initiated `handleERC20Transfer()` call for such a token unconditionally triggers the revert.

---

### Recommendation

Replace the raw `ERC20Mintable.mint()` call with a low-level call that tolerates empty returndata, mirroring the `SafeERC20.callOptionalReturn()` pattern already used in the same contract:

```diff
- require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
+ (bool ok, bytes memory ret) = _tokenAddress.call(
+     abi.encodeWithSelector(ERC20Mintable(_tokenAddress).mint.selector, _to, _value)
+ );
+ require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "handleERC20Transfer: mint failed");
```

Apply the same fix to `BridgeTransferERC721.handleERC721Transfer()` line 67, which has the identical pattern for `ERC721MetadataMintable.mintWithTokenURI()`.

---

### Proof of Concept

1. Deploy a bridge with `modeMintBurn = true`.
2. Register a token whose `mint(address, uint256)` executes successfully but returns no data (no `bool`).
3. User calls `requestERC20Transfer` on the source chain → `ERC20Burnable.burn(_value)` executes and commits; tokens are destroyed.
4. Operators call `handleERC20Transfer` on the destination chain.
5. Execution reaches line 69: `require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...)`.
6. The token's `mint()` runs but returns empty data.
7. Solidity's ABI decoder attempts to read a `bool` from 0 bytes of returndata → reverts.
8. All state changes in `handleERC20Transfer` are rolled back; the nonce is not consumed.
9. Every subsequent operator attempt produces the same revert.
10. The user's tokens are permanently lost: burned on the source chain, never minted on the destination chain.

---

**Affected locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC20/ERC20Mintable.sol (L20-23)
```text
    function mint(address account, uint256 amount) public onlyMinter returns (bool) {
        _mint(account, amount);
        return true;
    }
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC20/SafeERC20.sol (L55-74)
```text
    function callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves.

        // A Solidity high level call has three parts:
        //  1. The target address is checked to verify it contains contract code
        //  2. The call itself is made, and success asserted
        //  3. The return value is decoded, which in turn checks the size of the returned data.
        // solhint-disable-next-line max-line-length
        require(address(token).isContract(), "SafeERC20: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```
