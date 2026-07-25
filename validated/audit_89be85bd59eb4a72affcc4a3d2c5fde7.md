### Title
`handleERC20Transfer` and `handleERC721Transfer` accept unvalidated `_tokenAddress` parameter, allowing operators to drain wrong tokens from the destination bridge — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `contracts/service_chain/bridge/BridgeTransferERC721.sol`)

---

### Summary

The destination-side bridge handler functions `handleERC20Transfer` and `handleERC721Transfer` accept `_tokenAddress` as a caller-supplied parameter with no validation that it is a registered token on the destination bridge. The source-side function `_requestERC20Transfer` enforces `onlyRegisteredToken(_tokenAddress)`, but the destination-side handler has no equivalent guard. With the default operator threshold of 1, a single operator (including the automated relay node) can call `handleERC20Transfer` with an arbitrary token address, causing the bridge to transfer the wrong token to the recipient and permanently consuming the request nonce.

---

### Finding Description

`_requestERC20Transfer` (the source-side entry point) enforces two modifiers:

```solidity
internal
onlyRegisteredToken(_tokenAddress)
onlyUnlockedToken(_tokenAddress)
``` [1](#0-0) 

`handleERC20Transfer` (the destination-side handler) has neither:

```solidity
public
onlyOperators
``` [2](#0-1) 

The function directly executes a token transfer using the caller-supplied `_tokenAddress` without checking `registeredTokens[_tokenAddress]`:

```solidity
if (modeMintBurn) {
    require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
} else {
    IERC20(_tokenAddress).safeTransfer(_to, _value);
}
``` [3](#0-2) 

The same pattern exists in `handleERC721Transfer`: [4](#0-3) 

The voting mechanism uses `keccak256(msg.data)` as the vote key, so operators must agree on the exact calldata including `_tokenAddress`. However, the default `operatorThresholds` is initialized to **1** for all vote types:

```solidity
for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
    operatorThresholds[uint8(i)] = 1;
}
``` [5](#0-4) 

This means a **single operator** can unilaterally execute `handleERC20Transfer` with any `_tokenAddress`.

The Go relay (`bridge_manager.go`) is the typical operator. It automatically processes `RequestValueTransfer` events and calls `handleERC20Transfer` with `ctpartTokenAddr`: [6](#0-5) 

The relay resolves `ctpartTokenAddr` via a fallback path that queries `counterpartBridge.RegisteredTokens(nil, tokenAddr)` using the **source** token address against the **destination** bridge's registry: [7](#0-6) 

Because the destination bridge maps `dstToken → srcToken` (not `srcToken → dstToken`), this fallback can return an unexpected address under misconfiguration, causing the relay to call `handleERC20Transfer` with the wrong token address automatically and without any human intervention.

---

### Impact Explanation

In **non-mintBurn mode**: `IERC20(_tokenAddress).safeTransfer(_to, _value)` transfers `_value` of the wrong token from the bridge's balance to the recipient. If the bridge holds multiple ERC20 tokens (which is normal for a multi-token bridge), any of those tokens can be drained.

In **mintBurn mode**: `ERC20Mintable(_tokenAddress).mint(_to, _value)` is called on an arbitrary contract. If the bridge holds minting rights on unregistered tokens, this inflates supply.

In both cases, the request nonce is consumed (`_setHandledRequestTxHash`, `_updateHandleNonce`, `closedValueTransferVotes[nonce] = true`) before the transfer executes. Once the wrong-token transfer succeeds, the legitimate transfer for that nonce is **permanently blocked** — the nonce is closed and cannot be re-processed. [8](#0-7) 

---

### Likelihood Explanation

- The default operator threshold is 1, so a single operator suffices — no multi-party collusion required.
- The relay node in `bridge_manager.go` is an automated system (analogous to a Gelato/Keep3r keeper in the external report). A relay bug, misconfiguration of the `counterpartToken` map, or a compromised relay key is sufficient to trigger the wrong-token path.
- The fallback resolution path (`counterpartBridge.RegisteredTokens(nil, tokenAddr)`) queries the destination bridge with the source token address, which is semantically incorrect and can silently return an unexpected non-zero address if the destination bridge was misconfigured (e.g., tokens registered in the wrong direction).
- The source side enforces `onlyRegisteredToken` but the destination side does not — this asymmetry is a latent defect that will manifest under any operator mistake or relay misconfiguration, not just under adversarial conditions.

---

### Recommendation

Add `onlyRegisteredToken(_tokenAddress)` to both `handleERC20Transfer` and `handleERC721Transfer`:

```diff
 function handleERC20Transfer(
     bytes32 _requestTxHash,
     address _from,
     address _to,
     address _tokenAddress,
     uint256 _value,
     uint64 _requestedNonce,
     uint64 _requestedBlockNumber,
     bytes memory _extraData
 )
     public
     onlyOperators
+    onlyRegisteredToken(_tokenAddress)
 {
```

This mirrors the guard already present on `_requestERC20Transfer` and ensures the destination bridge only ever transfers tokens that were explicitly registered by the owner, regardless of what `_tokenAddress` value an operator supplies.

Additionally, consider raising the default `operatorThresholds` above 1 for production deployments to require multi-operator consensus before any value transfer executes.

---

### Proof of Concept

1. Deploy a bridge pair in non-mintBurn mode. Register token **A** (source) ↔ token **B** (destination). Also deposit token **C** into the destination bridge (e.g., from a previous transfer or airdrop).

2. A user calls `requestERC20Transfer(tokenA, recipient, 1000, ...)` on the source bridge. The source bridge emits `RequestValueTransfer(ERC20, user, recipient, tokenA, 1000, nonce=5, ...)`.

3. The relay (operator, threshold=1) — whether compromised, buggy, or misconfigured — calls on the destination bridge:
   ```
   handleERC20Transfer(txHash, user, recipient, tokenC, 1000, 5, blockNum, "")
   ```
   instead of the correct `tokenB`.

4. `_voteValueTransfer(5)` returns `true` immediately (threshold=1). `closedValueTransferVotes[5]` is set to `true`. `handleNoncesToBlockNums[5]` is written.

5. `IERC20(tokenC).safeTransfer(recipient, 1000)` executes — 1000 units of **token C** are transferred to `recipient` instead of token B.

6. Nonce 5 is now permanently closed. Any subsequent attempt to call `handleERC20Transfer(..., tokenB, 1000, 5, ...)` reverts with `"closed vote"` or `"removed vote"`, permanently blocking the legitimate transfer of token B to the recipient. [9](#0-8) [10](#0-9)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L42-43)
```text
        public
        onlyOperators
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L51-54)
```text
        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-86)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L29-70)
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
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L55-57)
```text
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L103-116)
```text
    function _voteValueTransfer(uint64 _requestNonce)
        internal
        returns(bool)
    {
        require(!closedValueTransferVotes[_requestNonce], "closed vote");

        bytes32 voteKey = keccak256(msg.data);
        if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
            closedValueTransferVotes[_requestNonce] = true;
            return true;
        }

        return false;
    }
```

**File:** node/sc/bridge_manager.go (L303-318)
```go
	ctpartTokenAddr := bi.GetCounterPartToken(tokenAddr)
	// TODO-Kaia-Servicechain Add counterpart token address in requestValueTransferEvent
	if tokenType != KAIA && ctpartTokenAddr == (common.Address{}) {
		logger.Warn("Unregistered counter part token address.", "addr", ctpartTokenAddr.Hex())
		ctTokenAddr, err := bi.counterpartBridge.RegisteredTokens(nil, tokenAddr)
		if err != nil {
			return err
		}
		if ctTokenAddr == (common.Address{}) {
			return errors.New("can't get counterpart token from bridge")
		}
		if err := bi.RegisterToken(tokenAddr, ctTokenAddr); err != nil {
			return err
		}
		ctpartTokenAddr = ctTokenAddr
		logger.Info("Register counter part token address.", "addr", ctpartTokenAddr.Hex(), "cpAddr", ctTokenAddr.Hex())
```

**File:** node/sc/bridge_manager.go (L338-340)
```go
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
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
