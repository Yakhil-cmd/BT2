### Title
Inbound Bridge Handle Path Bypasses `isRunning` Emergency Stop and `isLockedKLAY` Policy, Allowing Unauthorized Minting/Transfer of KAIA and Bridged Assets — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge enforces `isRunning` and `isLockedKLAY`/`lockedTokens` guards exclusively on the **outbound request path** (`_requestKLAYTransfer`, `_requestERC20Transfer`, `_requestERC721Transfer`). The **inbound handle path** (`handleKLAYTransfer`, `handleERC20Transfer`, `handleERC721Transfer`) carries none of these checks. When the bridge owner sets `isRunning = false` or `isLockedKLAY = true` as an emergency control, registered operators can still call the handle functions and cause the bridge to mint tokens or transfer KAIA/ERC20/ERC721 to arbitrary recipients, bypassing the intended freeze.

---

### Finding Description

**Outbound path — guards present:**

`_requestKLAYTransfer` enforces both `unlockedKLAY` and `isRunning`:

```solidity
// BridgeTransferKLAY.sol
function _requestKLAYTransfer(address _to, uint256 _feeLimit, bytes memory _extraData)
    internal
    unlockedKLAY          // ← blocks when isLockedKLAY == true
    nonReentrant
{
    require(isRunning, "stopped bridge");   // ← blocks when isRunning == false
    ...
}
```

`_requestERC20Transfer` and `_requestERC721Transfer` similarly enforce `isRunning` and `onlyUnlockedToken`.

**Inbound path — no guards:**

`handleKLAYTransfer` carries only `onlyOperators` and `nonReentrant`:

```solidity
// BridgeTransferKLAY.sol
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
    if (!_voteValueTransfer(_requestedNonce)) { return; }
    ...
    (bool ok, ) = _to.call.value(_value)("");   // ← KAIA sent regardless of isRunning / isLockedKLAY
    require(ok, "handleKLAYTransfer: transfer failed");
}
```

`handleERC20Transfer` and `handleERC721Transfer` are identical in structure — no `isRunning` check, no token-lock check — and in `modeMintBurn` mode they call `ERC20Mintable.mint` / `ERC721MetadataMintable.mintWithTokenURI` directly.

The same asymmetry exists in the Go-layer relay: `handleRequestValueTransferEvent` in `node/sc/bridge_manager.go` calls `HandleKLAYTransfer`, `HandleERC20Transfer`, or `HandleERC721Transfer` unconditionally, without consulting `bi.isRunning`.

---

### Impact Explanation

When the bridge owner invokes `setRunningStatus(false)` or `lockKLAY()` to freeze the bridge (e.g., in response to a security incident, a counterpart-chain exploit, or a regulatory hold), the freeze is **one-directional**:

- No user can initiate a new outbound request — the `isRunning` / `isLockedKLAY` guards block them.
- Any registered operator can still call `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` and cause the bridge to:
  - Send KAIA from the bridge's balance to an arbitrary `_to` address (lock/transfer mode), or
  - Mint new ERC20 or ERC721 tokens to an arbitrary `_to` address (`modeMintBurn` mode).

The corrupted value is the recipient's balance: KAIA or bridged-token balances increase on the destination side even though the bridge is supposed to be frozen. In `modeMintBurn` mode this is an unauthorized mint of bridged assets; in lock/transfer mode it is an unauthorized withdrawal of KAIA held by the bridge contract.

---

### Likelihood Explanation

The trigger requires a registered bridge operator to call a handle function while `isRunning == false` or `isLockedKLAY == true`. Operators are semi-trusted (registered by the owner), but the `isRunning` flag is explicitly designed to override normal bridge operation as an emergency control. The SubBridge relay daemon (`handleRequestValueTransferEvent`) will automatically attempt to relay any pending counterpart-chain events regardless of the local bridge's running status, so the bypass can occur without any deliberate malice — it is the default behavior of the relay when the bridge is stopped mid-flight. A malicious or compromised operator can also exploit this intentionally.

---

### Recommendation

Add `isRunning` and the relevant lock checks to all three handle functions, mirroring the outbound path:

```solidity
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    require(isRunning, "stopped bridge");   // add
    require(!isLockedKLAY, "locked");       // add
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

function handleERC20Transfer(...) public onlyOperators {
    require(isRunning, "stopped bridge");                  // add
    require(!lockedTokens[_tokenAddress], "locked token"); // add
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

function handleERC721Transfer(...) public onlyOperators {
    require(isRunning, "stopped bridge");                  // add
    require(!lockedTokens[_tokenAddress], "locked token"); // add
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}
```

The Go relay in `handleRequestValueTransferEvent` should also check `bi.isRunning` before submitting a handle transaction, consistent with how `UpdateInfo` already reads and caches this flag.

---

### Proof of Concept

1. Deploy `Bridge` with `modeMintBurn = true` and two operators (threshold = 1).
2. Register an ERC20 token pair; fund the bridge with KAIA for the KLAY case.
3. Call `bridge.start(false)` (owner stops the bridge).
4. Confirm `bridge.isRunning() == false`.
5. As operator, call:
   ```solidity
   bridge.handleKLAYTransfer(txhash, from, victim, 1 ether, 0, blockNum, "0x");
   ```
6. Observe that `victim` receives 1 KAIA even though the bridge is stopped — `isRunning` was never checked.
7. Repeat with `handleERC20Transfer` in mint mode: a new ERC20 balance is minted to `victim` despite `isRunning == false`.

The `isRunning` guard on `_requestKLAYTransfer` (line 108 of `BridgeTransferKLAY.sol`) is absent from `handleKLAYTransfer` (lines 62–100 of the same file), confirming the bypass. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-100)
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
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-109)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
        require(isRunning, "stopped bridge");
        require(msg.value > _feeLimit, "insufficient amount");
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-95)
```text
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L83-92)
```text
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
```

**File:** node/sc/bridge_manager.go (L292-360)
```go
// handleRequestValueTransferEvent handles the given request value transfer event.
func (bi *BridgeInfo) handleRequestValueTransferEvent(ev IRequestValueTransferEvent) error {
	var (
		tokenType                         = ev.GetTokenType()
		tokenAddr, from, to, contractAddr = ev.GetTokenAddress(), ev.GetFrom(), ev.GetTo(), ev.GetRaw().Address
		txHash                            = ev.GetRaw().TxHash
		valueOrTokenId                    = ev.GetValueOrTokenId()
		requestNonce, blkNumber           = ev.GetRequestNonce(), ev.GetRaw().BlockNumber
		extraData                         = ev.GetExtraData()
	)

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

	bridgeAcc := bi.account

	bridgeAcc.Lock()
	defer bridgeAcc.UnLock()

	auth := bridgeAcc.GenerateTransactOpts()

	var handleTx *types.Transaction
	var err error

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

	bridgeAcc.IncNonce()

	bi.bridgeDB.WriteHandleTxHashFromRequestTxHash(txHash, handleTx.Hash())
	return nil
}
```
