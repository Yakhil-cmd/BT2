### Title
`handleERC20Transfer`, `handleERC721Transfer`, and `handleKLAYTransfer` Bypass Token Lock State, Enabling Unauthorized Token Mint/Transfer When Tokens Are Locked — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`, `BridgeTransferKLAY.sol`)

---

### Summary

The Kaia service-chain bridge enforces token lock and bridge-running checks only on the **outgoing (request) side** of value transfers. The **incoming (handle) side** — `handleERC20Transfer`, `handleERC721Transfer`, and `handleKLAYTransfer` — carries no `onlyRegisteredToken`, `onlyUnlockedToken`, `lockedKLAY`, or `isRunning` guard. This is the direct structural analog of the reported bug: a protected-state flag (`lockedTokens` / `isLockedKLAY` / `isRunning`) is checked on one path but silently skipped on the symmetric path, allowing operators to mint or release bridged assets after the owner has explicitly locked them.

---

### Finding Description

**Request side (outgoing) — guards present:**

`_requestERC20Transfer` in `BridgeTransferERC20.sol` carries both `onlyRegisteredToken` and `onlyUnlockedToken`:

```solidity
function _requestERC20Transfer(...)
    internal
    onlyRegisteredToken(_tokenAddress)   // ← enforced
    onlyUnlockedToken(_tokenAddress)     // ← enforced
{
    require(isRunning, "stopped bridge"); // ← enforced
    ...
}
``` [1](#0-0) 

`_requestKLAYTransfer` carries `unlockedKLAY` and `isRunning`:

```solidity
function _requestKLAYTransfer(...)
    internal
    unlockedKLAY          // ← enforced
    nonReentrant
{
    require(isRunning, "stopped bridge"); // ← enforced
    ...
}
``` [2](#0-1) 

**Handle side (incoming) — guards absent:**

`handleERC20Transfer` carries only `onlyOperators` — no registration, lock, or running check:

```solidity
function handleERC20Transfer(...)
    public
    onlyOperators          // ← only guard
{
    ...
    if (modeMintBurn) {
        require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...); // mints unconditionally
    } else {
        IERC20(_tokenAddress).safeTransfer(_to, _value);              // transfers unconditionally
    }
}
``` [3](#0-2) 

`handleERC721Transfer` is identical — only `onlyOperators`, no lock check: [4](#0-3) 

`handleKLAYTransfer` carries `onlyOperators` and `nonReentrant` but **not** `lockedKLAY`: [5](#0-4) 

The lock modifiers and the `isRunning` flag are defined and enforced on the request path: [6](#0-5) [7](#0-6) 

---

### Impact Explanation

When the bridge owner calls `lockToken(token)` or `lockKLAY()` — typically as an emergency stop in response to a security incident — the intent is to halt **all** movement of that asset. Because `handleERC20Transfer` / `handleERC721Transfer` / `handleKLAYTransfer` ignore `lockedTokens`, `isLockedKLAY`, and `isRunning`, operators continue to process pending cross-chain requests and:

- In **`modeMintBurn` mode**: call `ERC20Mintable.mint` or `ERC721MetadataMintable.mintWithTokenURI` on the locked token, creating new supply that the owner believed was frozen.
- In **lock-and-hold mode**: call `IERC20.safeTransfer` or `IERC721.transferFrom` to release tokens held by the bridge contract, draining the bridge's reserves despite the lock.
- For **KLAY**: send native KLAY to recipients even when `isLockedKLAY == true`.

The corrupted value is the recipient's token/KLAY balance: it increases by `_value` / `_tokenId` when the owner's invariant requires it to remain unchanged.

---

### Likelihood Explanation

The trigger requires only a registered operator (semi-trusted, not the owner) to call a handle function after the owner has locked the token. This is the normal operational path: the off-chain bridge relayer (`BridgeInfo.handleRequestValueTransferEvent` in `node/sc/bridge_manager.go`) automatically calls `HandleERC20Transfer` / `HandleERC721Transfer` for every pending cross-chain event it observes. [8](#0-7) 

Any pending request that was emitted before the lock is applied will be processed by the relayer after the lock, because the relayer does not re-check the lock state before submitting the handle transaction. No attacker capability beyond being a registered operator is required.

---

### Recommendation

Add the symmetric guards to each handle function:

```solidity
// BridgeTransferERC20.sol
function handleERC20Transfer(...) public onlyOperators onlyRegisteredToken(_tokenAddress) onlyUnlockedToken(_tokenAddress) {
    require(isRunning, "stopped bridge");
    ...
}

// BridgeTransferERC721.sol
function handleERC721Transfer(...) public onlyOperators onlyRegisteredToken(_tokenAddress) onlyUnlockedToken(_tokenAddress) {
    require(isRunning, "stopped bridge");
    ...
}

// BridgeTransferKLAY.sol
function handleKLAYTransfer(...) public onlyOperators unlockedKLAY nonReentrant {
    require(isRunning, "stopped bridge");
    ...
}
```

This ensures that locking a token or stopping the bridge halts both directions of value flow, matching the invariant the owner expects when invoking `lockToken` / `lockKLAY` / `setRunningStatus(false)`.

---

### Proof of Concept

```solidity
// Scenario: owner locks ERC20 token; operator still mints via handleERC20Transfer (modeMintBurn)
// 1. Deploy bridge in modeMintBurn=true, register token, add operator.
// 2. Owner calls bridge.lockToken(tokenAddr).
// 3. Operator calls bridge.handleERC20Transfer(txHash, from, victim, tokenAddr, 1e18, nonce, blockNum, "").
// 4. ERC20Mintable(tokenAddr).mint(victim, 1e18) executes successfully.
// 5. victim's balance increases by 1e18 despite the token being locked.
//
// Expected: revert with "locked token"
// Actual:   mint succeeds; victim receives 1e18 tokens
```

The same pattern applies to `handleERC721Transfer` (mints NFT to victim) and `handleKLAYTransfer` (sends KLAY to victim) when the respective lock is active.

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-88)
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
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L29-37)
```text
    modifier lockedKLAY {
        require(isLockedKLAY, "unlocked");
        _;
    }

    modifier unlockedKLAY {
        require(!isLockedKLAY, "locked");
        _;
    }
```

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
