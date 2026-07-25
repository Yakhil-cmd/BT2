### Title
Bridge `handle*Transfer` Functions Execute Despite `isRunning = false` Stopped State — (File: `contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferKLAY.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The `BridgeTransfer` contract exposes an `isRunning` flag that the owner can set to `false` to stop bridge operations. However, the three handle-side functions — `handleERC20Transfer`, `handleKLAYTransfer`, and `handleERC721Transfer` — do not check `isRunning`. When the bridge is stopped, any registered operator can still call these functions to mint or transfer bridged assets (ERC20, KLAY, ERC721) to arbitrary addresses, bypassing the intended emergency stop.

---

### Finding Description

`BridgeTransfer.sol` declares `bool public isRunning = true` and provides `setRunningStatus(bool)` (owner-only) to halt the bridge. [1](#0-0) 

The `isRunning` guard is applied only on the **request** side:

- `_requestERC20Transfer` — `require(isRunning, "stopped bridge");`
- `_requestKLAYTransfer` — `require(isRunning, "stopped bridge");`
- `_requestERC721Transfer` — `require(isRunning, "stopped bridge");` [2](#0-1) [3](#0-2) [4](#0-3) 

The **handle** side functions carry only `onlyOperators` (and `nonReentrant` for KLAY) — no `isRunning` check:

```solidity
// BridgeTransferERC20.sol
function handleERC20Transfer(...) public onlyOperators {
    // no isRunning check
    ...
    ERC20Mintable(_tokenAddress).mint(_to, _value);  // or safeTransfer
}

// BridgeTransferKLAY.sol
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    // no isRunning check
    ...
    (bool ok, ) = _to.call.value(_value)("");
}

// BridgeTransferERC721.sol
function handleERC721Transfer(...) public onlyOperators {
    // no isRunning check
    ...
    ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI);
}
``` [5](#0-4) [6](#0-5) [7](#0-6) 

This is the exact structural analog to the external report: the outer function (`handleERC20Transfer`) does not check the stopped/paused state, and neither does the base function it calls into (`BridgeTransfer`), so execution proceeds unconditionally.

---

### Impact Explanation

When the bridge owner calls `setRunningStatus(false)` — typically in response to a security incident, a discovered exploit, or a planned maintenance window — the intent is to halt **all** bridge asset movement. Because the handle functions bypass `isRunning`, any registered operator can:

- **Mint ERC20 tokens** to arbitrary addresses (in `modeMintBurn = true` mode) via `handleERC20Transfer`
- **Transfer ERC20 tokens** from the bridge's locked reserves to arbitrary addresses (in `modeMintBurn = false` mode)
- **Transfer KLAY** from the bridge's KLAY balance to arbitrary addresses via `handleKLAYTransfer`
- **Mint ERC721 tokens** to arbitrary addresses (in `modeMintBurn = true` mode) via `handleERC721Transfer`
- **Transfer ERC721 tokens** from bridge custody to arbitrary addresses

The corrupted value is the bridge's token/KLAY balance and the total supply of mintable bridged tokens. This is an unauthorized transfer/mint of bridged assets — a directly in-scope impact.

---

### Likelihood Explanation

**Medium.** Operators are semi-trusted (registered by the owner via `registerOperator`), but the owner's explicit act of calling `setRunningStatus(false)` signals that no further asset movement should occur. The window of exploitation is any period during which the bridge is stopped but operators remain registered. A malicious or compromised operator can exploit this gap to continue processing (or fabricating) handle requests. The off-chain bridge relay (`node/sc/bridge_manager.go`) also calls these handle functions automatically upon observing request events, meaning the bypass can occur without any deliberate operator action. [8](#0-7) 

---

### Recommendation

**Short term:** Add an `isRunning` check to all three handle functions, or introduce a shared modifier:

```solidity
modifier onlyRunning() {
    require(isRunning, "stopped bridge");
    _;
}
```

Apply `onlyRunning` to `handleERC20Transfer`, `handleKLAYTransfer`, and `handleERC721Transfer`.

**Long term:** Consolidate the running-state guard in `BridgeTransfer` base contract so that any derived contract (e.g., `ExtBridge`) inherits the protection automatically, mirroring the recommendation in the external report to fix the base contract rather than each child.

---

### Proof of Concept

1. Owner deploys `Bridge` contract (`Bridge.sol` inherits all three transfer contracts).
2. Owner registers `operator` via `registerOperator(operator)`.
3. Owner calls `setRunningStatus(false)` — bridge is now stopped; `isRunning == false`.
4. Any user attempting `requestKLAYTransfer(...)` or `requestERC20Transfer(...)` is correctly rejected with `"stopped bridge"`.
5. `operator` calls `handleERC20Transfer(txHash, from, to, tokenAddr, value, nonce, blockNum, data)` — **succeeds** despite `isRunning == false`, minting or transferring `value` tokens to `to`.
6. `operator` calls `handleKLAYTransfer(txHash, from, to, value, nonce, blockNum, data)` — **succeeds**, transferring `value` KLAY from the bridge to `to`.
7. `operator` calls `handleERC721Transfer(txHash, from, to, tokenAddr, tokenId, nonce, blockNum, uri, data)` — **succeeds**, minting or transferring the NFT to `to`.

The existing test suite confirms only the request side is blocked when stopped, with no test asserting that handle operations are also blocked: [9](#0-8)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L27-57)
```text
    bool public modeMintBurn = false;
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-88)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-108)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L81-85)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
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

**File:** contracts/test/Bridge/bridge.test.ts (L851-858)
```typescript
    it("stopped bridge", async function() {
      const fixture = await loadFixture(deployBridgeConfiguredFixture);
      const { bridge, owner, user1 } = fixture;

      await bridge.connect(owner).start(false);
      expect(bridge.connect(user1).fallback({value: parseEther("1.0")}))
        .to.be.revertedWith("stopped bridge");
    });
```
