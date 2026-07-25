### Title
Lock Bypass on Bridge Handle Path Allows KLAY/Token Transfer Despite Owner-Set Lock — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge defines lock flags (`isLockedKLAY`, `lockedTokens`) that the owner can set to halt all asset movement. These flags are enforced only on the **request** (deposit) path. The **handle** (settlement/withdrawal) path — `handleKLAYTransfer`, `handleERC20Transfer`, `handleERC721Transfer` — carries no lock check, so any registered operator can settle pending transfers and move KLAY or bridged tokens out of the bridge contract even while the lock is active.

---

### Finding Description

`BridgeTransferKLAY.sol` declares `isLockedKLAY` and two modifiers:

```solidity
modifier lockedKLAY   { require( isLockedKLAY, "unlocked"); _; }
modifier unlockedKLAY { require(!isLockedKLAY, "locked");   _; }
```

The request path correctly applies the guard:

```solidity
// _requestKLAYTransfer — line 103-105
function _requestKLAYTransfer(...) internal unlockedKLAY nonReentrant { ... }
```

The handle path does not:

```solidity
// handleKLAYTransfer — lines 62-99
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    _lowerHandleNonceCheck(_requestedNonce);
    if (!_voteValueTransfer(_requestedNonce)) { return; }
    ...
    (bool ok, ) = _to.call.value(_value)("");   // KLAY sent unconditionally
    require(ok, "handleKLAYTransfer: transfer failed");
}
```

The same asymmetry exists in `BridgeTransferERC20.sol`:

- `_requestERC20Transfer` carries `onlyUnlockedToken(_tokenAddress)` (line 86)
- `handleERC20Transfer` carries only `onlyOperators` (line 43); no `lockedTokens` check

And in `BridgeTransferERC721.sol`:

- `_requestERC721Transfer` carries `onlyUnlockedToken(_tokenAddress)` (line 83)
- `handleERC721Transfer` carries only `onlyOperators` (line 41); no `lockedTokens` check

The Go bridge manager (`node/sc/bridge_manager.go`, `handleRequestValueTransferEvent`, lines 331–354) calls all three handle functions automatically whenever a counterpart `RequestValueTransfer` event is observed, with no awareness of the lock state.

---

### Impact Explanation

When the owner calls `lockKLAY()` or `lockToken()` — typically in response to a security incident — the intent is to freeze all KLAY/token movement through the bridge. Because `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` ignore the lock flags, any registered operator (or the automated bridge relayer) can continue to settle pending cross-chain requests, draining the bridge contract's KLAY balance or minting/transferring bridged ERC-20/ERC-721 tokens to arbitrary recipients. The corrupted value is the exact KLAY amount or token quantity transferred by each `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` call executed after the lock is set.

---

### Likelihood Explanation

The bridge relayer (`BridgeInfo.handleRequestValueTransferEvent`) calls the handle functions automatically and continuously. After the owner sets the lock, any in-flight or newly observed `RequestValueTransfer` event on the counterpart chain will trigger a handle call before the operator is deregistered or the relayer is stopped. The window is bounded only by the time between the owner's `lockKLAY()` transaction and a manual operator deregistration — a gap that is non-zero in any realistic incident response.

---

### Recommendation

Add the lock check to each handle function, mirroring the request path:

```solidity
// BridgeTransferKLAY.sol
function handleKLAYTransfer(...) public onlyOperators nonReentrant unlockedKLAY { ... }

// BridgeTransferERC20.sol
function handleERC20Transfer(...) public onlyOperators onlyUnlockedToken(_tokenAddress) { ... }

// BridgeTransferERC721.sol
function handleERC721Transfer(...) public onlyOperators onlyUnlockedToken(_tokenAddress) { ... }
```

Alternatively, if the intent is that the lock only blocks new deposits (not in-flight settlements), the documentation and the lock function's name/comment must be updated to reflect that, and the security model must account for the continued outflow.

---

### Proof of Concept

1. Deploy the bridge contract; fund it with 100 KLAY.
2. Register an operator (or use the deployer, who is the initial operator).
3. Owner calls `lockKLAY()` → `isLockedKLAY = true`.
4. Verify that `requestKLAYTransfer` reverts with `"locked"`.
5. Operator calls `handleKLAYTransfer(txHash, from, victim, 100 ether, nonce, blockNum, "")`.
6. Transaction succeeds; bridge balance drops to 0; `victim` receives 100 KLAY.
7. The lock had no effect on the settlement path.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-99)
```text
    function handleKLAYTransfer(
        bytes32 _requestTxHash,
        address _from,
        address payable _to,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
        nonReentrant
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
            TokenType.KLAY,
            _from,
            _to,
            address(0),
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-106)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
```

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-87)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L81-84)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L42-50)
```text
    modifier onlyLockedToken(address _token) {
        require(lockedTokens[_token], "unlocked token");
        _;
    }

    modifier onlyUnlockedToken(address _token) {
        require(!lockedTokens[_token], "locked token");
        _;
    }
```

**File:** node/sc/bridge_manager.go (L331-354)
```go
	switch tokenType {
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC20], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC721:
		uri := GetURI(ev)
		handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, uri, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC721], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	default:
		logger.Error("Got Unknown Token Type ReceivedEvent", "bridge", contractAddr, "nonce", requestNonce, "from", from)
		return nil
	}
```
