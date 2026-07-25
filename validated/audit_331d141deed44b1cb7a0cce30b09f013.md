### Title
Unvalidated `_tokenAddress` in `handleERC20Transfer` Allows Operator to Drain Bridge Token Holdings — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

### Summary

`BridgeTransferERC20.handleERC20Transfer` accepts an operator-supplied `_tokenAddress` and uses it directly for the final token mint or transfer without checking that it is a registered token on the destination bridge. The request-side function `_requestERC20Transfer` enforces `onlyRegisteredToken(_tokenAddress)`, but the handle-side function has no equivalent guard. This is the direct analog of the reported collection/pool mismatch: the processing logic (nonce accounting, event emission) runs against the operator-supplied token address, and the final asset transfer executes on that same unvalidated address.

### Finding Description

`_requestERC20Transfer` (the source-chain deposit path) enforces two modifiers: [1](#0-0) 

```solidity
internal
onlyRegisteredToken(_tokenAddress)
onlyUnlockedToken(_tokenAddress)
```

`handleERC20Transfer` (the destination-chain withdrawal path) has **no such modifiers**. It accepts `_tokenAddress` from the caller and passes it directly to `mint` or `safeTransfer`: [2](#0-1) 

```solidity
function handleERC20Transfer(
    ...
    address _tokenAddress,   // ← operator-supplied, never validated
    ...
) public onlyOperators {
    ...
    if (modeMintBurn) {
        require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
    } else {
        IERC20(_tokenAddress).safeTransfer(_to, _value);
    }
}
```

The Go-side bridge manager correctly resolves the counterpart token before calling the contract: [3](#0-2) 

But this resolution happens off-chain. The Solidity contract itself imposes no on-chain constraint that `_tokenAddress` must appear in `registeredTokens`. Any operator can call `handleERC20Transfer` directly on-chain with an arbitrary token address, bypassing the Go-layer lookup entirely.

The voting mechanism `_voteValueTransfer(_requestedNonce)` is keyed only on the nonce: [4](#0-3) 

It does not commit to the full parameter set (`_tokenAddress`, `_value`, `_to`). Consequently, if operator A votes for nonce N with `tokenCorrect` and operator B (malicious) votes for nonce N with `tokenVictim`, both votes accumulate toward the same nonce threshold. Whichever operator casts the deciding vote controls which `_tokenAddress` is used for the actual transfer.

### Impact Explanation

In **lock/unlock mode** (`modeMintBurn = false`): the bridge calls `IERC20(_tokenAddress).safeTransfer(_to, _value)`. A malicious operator who casts the deciding vote can set `_tokenAddress` to any ERC-20 token the bridge contract holds, draining those holdings to an arbitrary `_to` address.

In **mint/burn mode** (`modeMintBurn = true`): the bridge calls `ERC20Mintable(_tokenAddress).mint(_to, _value)`. If the bridge has been granted minting rights on a token other than the intended one, arbitrary tokens can be minted.

The corrupted value is the bridge's ERC-20 token balance (lock/unlock) or the total supply of a mintable token (mint/burn). This is an unauthorized token transfer affecting bridged assets — within the allowed impact gate.

### Likelihood Explanation

Operators are semi-trusted external parties registered by the bridge owner. A single operator who can time their call to be the deciding vote (threshold − 1 honest votes already cast) can execute the attack unilaterally. This is a minority-operator attack, not majority collusion. The attack surface is reachable on every `handleERC20Transfer` call where the bridge holds tokens of more than one registered type.

### Recommendation

Add an `onlyRegisteredToken(_tokenAddress)` modifier (or an equivalent inline check against `registeredTokens[_tokenAddress]`) to `handleERC20Transfer` and `handleERC721Transfer`:

```solidity
function handleERC20Transfer(
    ...
    address _tokenAddress,
    ...
) public onlyOperators onlyRegisteredToken(_tokenAddress) {
    ...
}
```

Additionally, the voting mechanism should commit to the full parameter hash (not just the nonce) so that votes for different `_tokenAddress` values for the same nonce do not aggregate.

### Proof of Concept

1. Bridge is deployed in lock/unlock mode. It holds 1000 `TokenA` and 1000 `TokenB`, both registered.
2. A legitimate `RequestValueTransfer` event for `TokenA`, nonce 7, is emitted on the source chain.
3. Honest operator calls `handleERC20Transfer(txHash, from, to, TokenA, 1000, 7, blockNum, "")` → vote count = 1, threshold not reached.
4. Malicious operator calls `handleERC20Transfer(txHash, from, attackerAddr, TokenB, 1000, 7, blockNum, "")` → vote count = 2, threshold reached, `TokenB.safeTransfer(attackerAddr, 1000)` executes.
5. Attacker receives 1000 `TokenB` from the bridge without having deposited any `TokenB` on the source chain. The bridge's `TokenB` holdings are drained.

The root cause is in `contracts/service_chain/bridge/BridgeTransferERC20.sol` at the `handleERC20Transfer` function (lines 32–73), which lacks the `onlyRegisteredToken` guard present on the request path (lines 84–86). The same pattern applies to `handleERC721Transfer` in `contracts/service_chain/bridge/BridgeTransferERC721.sol`. [2](#0-1) [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-73)
```text
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
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-86)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
```

**File:** node/sc/bridge_manager.go (L303-319)
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
	}
```

**File:** node/sc/bridge_manager.go (L338-346)
```go
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC20], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC721:
		uri := GetURI(ev)
		handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, uri, extraData)
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L32-35)
```text
    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
    }
```
