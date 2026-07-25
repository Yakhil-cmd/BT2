### Title
Bridge `isRunning` Flag Not Enforced in `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The `isRunning` flag in `BridgeTransfer.sol` is the owner-controlled circuit-breaker for the service-chain bridge. It is correctly enforced on every **request** path (user-facing), but is never checked on any **handle** path (operator-facing). After the owner calls `setRunningStatus(false)`, bridge operators — including the automated `valueTransferRecovery` relayer — can still call `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` to push KAIA, ERC20, and ERC721 assets to recipients on the destination chain, defeating the emergency stop entirely.

---

### Finding Description

`BridgeTransfer.sol` declares `isRunning` as a public boolean (default `true`) and exposes `setRunningStatus(bool)` (owner-only) to toggle it. [1](#0-0) 

Every **request** function guards itself with `require(isRunning, "stopped bridge")`:

- `_requestKLAYTransfer` [2](#0-1) 
- `_requestERC20Transfer` [3](#0-2) 
- `_requestERC721Transfer` [4](#0-3) 

None of the three **handle** functions contain any `isRunning` check:

- `handleKLAYTransfer` — only `onlyOperators` + `nonReentrant` [5](#0-4) 
- `handleERC20Transfer` — only `onlyOperators` [6](#0-5) 
- `handleERC721Transfer` — only `onlyOperators` [7](#0-6) 

The Go-side bridge manager reads `isRunning` from the contract into `bi.isRunning` during `UpdateInfo()`, but this field is never consulted before dispatching handle transactions. [8](#0-7) 

The automated `valueTransferRecovery` goroutine continuously replays unhandled request events by calling `handleRequestValueTransferEvent`, which directly submits `HandleKLAYTransfer` / `HandleERC20Transfer` / `HandleERC721Transfer` transactions regardless of the contract's `isRunning` state. [9](#0-8) 

---

### Impact Explanation

When the bridge owner calls `setRunningStatus(false)` — the intended emergency stop — operators (and the automated relayer) can still:

1. Mint or transfer ERC20 tokens to arbitrary recipients via `handleERC20Transfer` (mint path: `ERC20Mintable.mint`).
2. Transfer KAIA out of the bridge contract to arbitrary recipients via `handleKLAYTransfer`.
3. Mint or transfer ERC721 tokens via `handleERC721Transfer`.

This constitutes **unauthorized transfer of KAIA and bridged assets** after the protected `isRunning` flag has been set to `false`. In a mint-burn bridge deployment, operators can mint unbounded ERC20/ERC721 tokens on the child chain even while the bridge is nominally stopped.

---

### Likelihood Explanation

The most common reason to call `setRunningStatus(false)` is an active security incident (e.g., a counterpart-chain exploit or a bridge contract bug). In exactly that scenario, the automated `valueTransferRecovery` relayer is running and will continue to submit handle transactions for every pending request event it finds, draining or minting assets while the operator believes the bridge is halted. Operators are semi-trusted (registered by the owner but distinct from the owner), so this does not require owner-level compromise.

---

### Recommendation

Add an `isRunning` guard to all three handle functions, mirroring the pattern already used on the request side:

```solidity
// In handleKLAYTransfer, handleERC20Transfer, handleERC721Transfer:
require(isRunning, "stopped bridge");
```

Alternatively, introduce a dedicated `isHandlingEnabled` flag if the intent is to allow independent control of inbound vs. outbound transfers, and enforce it consistently in all handle paths.

---

### Proof of Concept

1. Bridge owner deploys the bridge and registers operators (including an automated relayer).
2. A user on the parent chain calls `requestKLAYTransfer`, emitting a `RequestValueTransfer` event with `requestNonce = N`.
3. The bridge owner detects an exploit and calls `setRunningStatus(false)`. New user requests now revert with `"stopped bridge"`.
4. The automated `valueTransferRecovery` relayer, running in `node/sc/vt_recovery.go`, scans for unhandled request events and finds nonce `N`.
5. The relayer calls `handleKLAYTransfer(txHash, from, to, value, N, blockNum, extraData)` on the child-chain bridge.
6. Because `handleKLAYTransfer` contains no `isRunning` check, the call succeeds: `_to.call.value(_value)("")` transfers KAIA to the recipient.
7. The bridge is "stopped" but assets continue to flow — the emergency stop has no effect on the handle path.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L28-57)
```text
    bool public isRunning = true;

    uint64 public requestNonce; // the number of value transfer request that this contract received.
    uint64 public lowerHandleNonce; // a minimum nonce of a value transfer request that will be handled.
    uint64 public upperHandleNonce; // a maximum nonce of the counterpart bridge's value transfer request that is handled.
    uint64 public recoveryBlockNumber = 1; // the block number that recovery start to filter log from.
    mapping(uint64 => uint64) public handleNoncesToBlockNums;  // <request nonce> => <request blockNum>

    event RunningStatusChanged(bool _status);

    using SafeMath for uint256;

    enum TokenType {
        KLAY,
        ERC20,
        ERC721
    }

    constructor(bool _modeMintBurn) BridgeFee(address(0)) internal {
        modeMintBurn = _modeMintBurn;
    }

    // setRunningStatus can allow or disallow the value transfer request.
    function setRunningStatus(bool _status)
        public
        onlyOwner
    {
        isRunning = _status;
        emit RunningStatusChanged(_status);
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L108-108)
```text
        require(isRunning, "stopped bridge");
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L88-88)
```text
        require(isRunning, "stopped bridge");
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L85-85)
```text
        require(isRunning, "stopped bridge");
```

**File:** node/sc/bridge_manager.go (L283-288)
```go
	isRunning, err := bi.bridge.IsRunning(nil)
	if err != nil {
		return err
	}
	bi.isRunning = isRunning

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
