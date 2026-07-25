### Title
Bridge Handle Functions Execute Asset Transfers While Bridge Is Stopped — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`handleKLAYTransfer` and `handleERC20Transfer` lack an `isRunning` guard, allowing bridge operators to transfer KAIA and ERC20 tokens out of the bridge contract even after the owner has stopped the bridge via `setRunningStatus(false)`.

---

### Finding Description

`BridgeTransfer` exposes an `isRunning` boolean that the owner can set to `false` to halt all bridge operations — the intended invariant being that no value movement occurs while the bridge is stopped.

The user-facing request functions correctly enforce this invariant:

- `_requestKLAYTransfer` in `BridgeTransferKLAY.sol` line 108: `require(isRunning, "stopped bridge")`
- `_requestERC20Transfer` in `BridgeTransferERC20.sol` line 88: `require(isRunning, "stopped bridge")` [1](#0-0) [2](#0-1) 

However, the operator-facing handle functions carry **no such check**:

- `handleKLAYTransfer` (lines 62–100 of `BridgeTransferKLAY.sol`) only checks `onlyOperators` and `nonReentrant`.
- `handleERC20Transfer` (lines 32–73 of `BridgeTransferERC20.sol`) only checks `onlyOperators`. [3](#0-2) [4](#0-3) 

When `isRunning = false`, any registered bridge operator can still call these functions and:

1. Transfer KAIA out of the bridge via `_to.call.value(_value)("")`
2. Transfer or mint ERC20 tokens via `IERC20.safeTransfer` / `ERC20Mintable.mint`
3. Mutate `lowerHandleNonce`, `upperHandleNonce`, `handleNoncesToBlockNums`, and `closedValueTransferVotes` [5](#0-4) [6](#0-5) 

The `isRunning` flag is set and read in `BridgeTransfer.sol`: [7](#0-6) 

The Go-layer bridge manager (`node/sc/bridge_manager.go`) drives these handle calls automatically in response to counterpart chain events, meaning operators will continue processing pending transfers even after the owner stops the bridge: [8](#0-7) 

---

### Impact Explanation

When the bridge owner calls `setRunningStatus(false)` — typically in response to a security incident, exploit, or emergency — the intent is to freeze all asset movement. Because `handleKLAYTransfer` and `handleERC20Transfer` bypass this guard, operators (or the automated bridge relay) continue to drain KAIA and ERC20 tokens from the bridge contract. In mint-burn mode, `handleERC20Transfer` also mints new tokens on the destination chain. Both the bridge's KAIA balance and its ERC20 holdings are at risk of unauthorized transfer while the bridge is nominally stopped.

---

### Likelihood Explanation

Bridge operators are semi-trusted accounts that run automated relay software (`node/sc/bridge_manager.go`). The relay calls `handleKLAYTransfer`/`handleERC20Transfer` automatically for every pending `RequestValueTransfer` event it observes. An operator does not need to act maliciously — the relay will naturally continue processing queued events after the owner stops the bridge, because the relay has no awareness of `isRunning`. A single operator with threshold=1 (the default) is sufficient to complete a transfer.

---

### Recommendation

Add `require(isRunning, "stopped bridge")` at the top of both handle functions, mirroring the guard already present in the request functions:

```solidity
// BridgeTransferKLAY.sol
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    require(isRunning, "stopped bridge");   // ADD THIS
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

// BridgeTransferERC20.sol
function handleERC20Transfer(...) public onlyOperators {
    require(isRunning, "stopped bridge");   // ADD THIS
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}
```

---

### Proof of Concept

1. Deploy `Bridge` with two operators (`op1`, `op2`) and threshold 2. Fund the bridge with 1000 KAIA.
2. Owner calls `bridge.start(false)` → `isRunning = false`.
3. `op1` calls `bridge.handleKLAYTransfer(txHash, from, attacker, 500 ether, 0, blockNum, "0x")`.
4. `op2` calls the same function with identical arguments, reaching threshold.
5. Despite `isRunning = false`, the call succeeds: 500 KAIA is transferred to `attacker`, `lowerHandleNonce` advances, and `closedValueTransferVotes[0]` is set to `true`.
6. The bridge's KAIA balance is reduced by 500 KAIA while the bridge is stopped.

The existing test suite confirms `handleKLAYTransfer` succeeds with only `onlyOperators` as the gate and no `isRunning` check: [9](#0-8)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-89)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
        require(_value > 0, "zero ERC20 token amount");
```

**File:** contracts/service_chain/bridge/BridgeTransfer.sol (L26-57)
```text
contract BridgeTransfer is BridgeHandledRequests, BridgeFee, BridgeOperator {
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

**File:** contracts/test/Bridge/bridge.test.ts (L763-789)
```typescript
    it("receive", async function() {
      const fixture = await loadFixture(deployBridgeConfiguredFixture);
      const { bridge, owner, op1, op2, user1, user2 } = fixture;

      // Add liquidity
      await bridge.connect(owner).chargeWithoutEvent({value: parseEther("1000.0")});

      expect(bridge.connect(op1).handleKLAYTransfer(txhash, user1.address, user2.address, parseEther("1.0"), 0, blockNum, "0x"))
        .to.be.revertedWith("msg.sender is not an operator");

      await bridge.connect(op1).handleKLAYTransfer(txhash, user1.address, user2.address, parseEther("1.0"), 0, blockNum, "0x");
      expect(await bridge.connect(op2).handleKLAYTransfer(txhash, user1.address, user2.address, parseEther("1.0"), 0, blockNum, "0x"))
        .to.emit(bridge, "HandleValueTransfer")
        .withArgs(
          txhash,
          TokenType.KLAY,
          user1.address,
          user2.address,
          AddressZero,
          parseEther("1.0"),
          0, // requestNonce
          0, // lowerHandleNonce
          "0x",
        );

      expect(await ethers.provider.getBalance(user2.address)).to.equal(parseEther("1.0"));
    });
```
