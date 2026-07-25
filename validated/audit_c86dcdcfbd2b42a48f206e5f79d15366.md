### Title
`handleERC20Transfer` Bypasses Token Deregistration Check, Allowing Unauthorized Mint/Transfer of Deregistered Bridged Tokens — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

The `handleERC20Transfer` function in `BridgeTransferERC20.sol` does not verify that the token being transferred is still registered (whitelisted) on the bridge. While the user-facing `_requestERC20Transfer` enforces `onlyRegisteredToken` and `onlyUnlockedToken`, the operator-facing `handleERC20Transfer` only checks `onlyOperators`. After a token is deregistered via `deregisterToken`, bridge operators can still call `handleERC20Transfer` to mint (in mintBurn mode) or transfer (in lock mode) the deregistered token, bypassing the deregistration mechanism entirely.

---

### Finding Description

`BridgeTransferERC20` inherits from `BridgeTokens`, which provides token registration/deregistration. The `deregisterToken` function removes a token from `registeredTokens` and `lockedTokens`. The `onlyRegisteredToken` modifier enforces that only registered tokens can be used.

The user-facing `_requestERC20Transfer` correctly applies both `onlyRegisteredToken(_tokenAddress)` and `onlyUnlockedToken(_tokenAddress)`: [1](#0-0) 

However, the operator-facing `handleERC20Transfer` only applies `onlyOperators`, with no check on token registration status: [2](#0-1) 

The deregistration function removes the token from the registry: [3](#0-2) 

After deregistration, `registeredTokens[_token]` is zero, so `onlyRegisteredToken` would revert — but `handleERC20Transfer` never invokes it. In `modeMintBurn = true`, line 69 calls `ERC20Mintable(_tokenAddress).mint(_to, _value)` unconditionally; in `modeMintBurn = false`, line 71 calls `IERC20(_tokenAddress).safeTransfer(_to, _value)` from bridge reserves — both with no registration guard.

The Go-layer bridge manager (`node/sc/bridge_manager.go`) drives this call automatically upon observing a `RequestValueTransfer` event on the counterpart chain: [4](#0-3) 

There is no registration check in the Go relay path either.

---

### Impact Explanation

- **Unauthorized mint (modeMintBurn = true):** Operators can mint arbitrary amounts of a deregistered token to any recipient, inflating the token supply on the destination chain.
- **Unauthorized transfer (modeMintBurn = false):** Operators can drain the bridge's locked reserves of a deregistered token.
- The deregistration mechanism — intended as a safety valve to halt all transfers of a specific token (e.g., a token found to be malicious or compromised) — is rendered completely ineffective for the handle (destination) side.
- This directly matches the allowed impact gate: *unauthorized mint/transfer affecting bridged assets*.

---

### Likelihood Explanation

- A legitimate operator relaying source-chain `RequestValueTransfer` events may call `handleERC20Transfer` for a token that has been deregistered on the destination bridge but not yet on the source bridge — no malice required.
- A compromised or rogue operator can exploit this indefinitely, since the deregistration that was supposed to stop them has no effect on `handleERC20Transfer`.
- The asymmetry is structural: the request path is guarded, the handle path is not, so any operator can trigger the impact without any additional privilege beyond their existing operator role.

---

### Recommendation

Add `onlyRegisteredToken(_tokenAddress)` (and optionally `onlyUnlockedToken`) to `handleERC20Transfer`:

```solidity
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
+   onlyRegisteredToken(_tokenAddress)   // mirror _requestERC20Transfer guard
{
```

This mirrors the guard already present in `_requestERC20Transfer` and ensures that deregistering a token stops transfers in both directions.

---

### Proof of Concept

1. Deploy bridge in `modeMintBurn = true`.
2. Register Token X: `registerToken(tokenX, ctokenX)`.
3. Deregister Token X: `deregisterToken(tokenX)` — `registeredTokens[tokenX]` is now `address(0)`.
4. As an authorized operator, call:
   ```solidity
   handleERC20Transfer(txHash, from, victim, tokenX, 1_000_000e18, nonce, blockNum, "")
   ```
5. The call succeeds — `onlyOperators` passes, no registration check fires — and `ERC20Mintable(tokenX).mint(victim, 1_000_000e18)` executes, minting 1 million deregistered tokens to an arbitrary recipient.
6. The deregistration that was intended to stop Token X transfers had zero effect on the handle path. [5](#0-4) [6](#0-5)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-87)
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
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L32-50)
```text
    modifier onlyRegisteredToken(address _token) {
        require(registeredTokens[_token] != address(0), "not allowed token");
        _;
    }

    modifier onlyNotRegisteredToken(address _token) {
        require(registeredTokens[_token] == address(0), "allowed token");
        _;
    }

    modifier onlyLockedToken(address _token) {
        require(lockedTokens[_token], "unlocked token");
        _;
    }

    modifier onlyUnlockedToken(address _token) {
        require(!lockedTokens[_token], "locked token");
        _;
    }
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L73-89)
```text
    // deregisterToken can remove the token in registeredToken list.
    function deregisterToken(address _token)
        external
        onlyOwner
        onlyRegisteredToken(_token)
    {
        delete registeredTokens[_token];
        delete lockedTokens[_token];

        uint idx = indexOfTokens[_token];
        delete indexOfTokens[_token];

        if (idx < registeredTokenList.length-1) {
            registeredTokenList[idx] = registeredTokenList[registeredTokenList.length-1];
            indexOfTokens[registeredTokenList[idx]] = idx;
        }
        registeredTokenList.length--;
```

**File:** node/sc/bridge_manager.go (L338-343)
```go
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC20], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
```
