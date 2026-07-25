### Title
Bridge `handleERC20Transfer` / `handleERC721Transfer` Bypass Registered-Token and Lock Invariants — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

### Summary

`handleERC20Transfer` and `handleERC721Transfer` in the Kaia service-chain bridge are callable by any registered operator but carry **no** `onlyRegisteredToken` or `onlyUnlockedToken` guard. The outbound request path (`_requestERC20Transfer`, `_requestERC721Transfer`) enforces both modifiers, but the inbound handle path does not. A single compromised operator (default threshold = 1) can therefore transfer or mint any token the bridge holds rights over, including tokens the owner has explicitly locked to halt transfers.

### Finding Description

`_requestERC20Transfer` enforces the allowlist and lock state:

```solidity
function _requestERC20Transfer(...) internal
    onlyRegisteredToken(_tokenAddress)   // ← present
    onlyUnlockedToken(_tokenAddress)     // ← present
``` [1](#0-0) 

`handleERC20Transfer`, which operators call to settle incoming cross-chain requests, has neither guard:

```solidity
function handleERC20Transfer(...) public onlyOperators {
    // no onlyRegisteredToken check
    // no onlyUnlockedToken check
    ...
    if (modeMintBurn) {
        require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
    } else {
        IERC20(_tokenAddress).safeTransfer(_to, _value);
    }
}
``` [2](#0-1) 

The same asymmetry exists for ERC-721: [3](#0-2) 

The operator threshold defaults to **1**, so a single operator can execute the call unilaterally: [4](#0-3) 

The `lockedTokens` mapping and `onlyUnlockedToken` modifier exist precisely to let the owner halt transfers of a specific token (e.g., during an incident): [5](#0-4) 

### Impact Explanation

**Locked-token bypass (highest impact):** The bridge owner calls `lockToken(T)` to freeze token `T` in response to a security event. A single compromised operator immediately calls `handleERC20Transfer(..., T, victim, amount, ...)`. Because there is no `onlyUnlockedToken` check on the handle path, the call succeeds and drains `amount` of `T` from the bridge to an attacker-controlled address — directly contradicting the owner's emergency freeze.

**Unregistered-token drain (mintBurn = false):** Any ERC-20 token accidentally sent to the bridge (or deregistered but still held) can be swept out by an operator supplying its address as `_tokenAddress`.

**Arbitrary mint (mintBurn = true):** If the bridge holds `MinterRole` on any token contract beyond the registered set, an operator can mint unbounded supply to any address.

### Likelihood Explanation

- Default `operatorThreshold` is 1; no multi-sig quorum is required.
- Operators are registered by the owner but are external accounts that can be compromised.
- The call is indistinguishable from a legitimate handle call at the RPC level; no on-chain alarm is raised.
- The Go relay layer (`bridge_manager.go`) passes `ctpartTokenAddr` from its local registry, but the Solidity contract itself imposes no such restriction, so a direct contract call bypasses the relay entirely. [6](#0-5) 

### Recommendation

Add `onlyRegisteredToken(_tokenAddress)` and `onlyUnlockedToken(_tokenAddress)` to both `handleERC20Transfer` and `handleERC721Transfer`, mirroring the guards already present on the request path:

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
    onlyRegisteredToken(_tokenAddress)   // ADD
    onlyUnlockedToken(_tokenAddress)     // ADD
{
    ...
}
```

Apply the same fix to `handleERC721Transfer`.

### Proof of Concept

1. Deploy the bridge in non-mintBurn mode; register and fund token `T`; register operator `Op`.
2. Owner calls `lockToken(T)` — `lockedTokens[T] == true`.
3. `Op` calls directly on the contract:
   ```
   bridge.handleERC20Transfer(
       txhash, attacker, attacker, T, bridge.balanceOf(T), 0, 1, ""
   )
   ```
4. No revert occurs. `T` is transferred to `attacker`. The lock is silently bypassed.
5. Repeat with any unregistered token address the bridge holds a balance of.

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

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L54-57)
```text
    constructor() internal {
        for (uint8 i = 0; i < uint8(VoteType.Max); i++) {
            operatorThresholds[uint8(i)] = 1;
        }
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L25-50)
```text
    mapping(address => bool) public lockedTokens;

    event TokenRegistered(address indexed token);
    event TokenDeregistered(address indexed token);
    event TokenLocked(address indexed token);
    event TokenUnlocked(address indexed token);

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

**File:** node/sc/bridge_manager.go (L338-343)
```go
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC20], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
```
