### Title
`isRunning` Guard Not Enforced in Bridge `handle*Transfer` Functions — (`contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge contracts expose a `bool public isRunning` flag in `BridgeTransfer.sol` that is documented as the mechanism to "allow or disallow the value transfer." All three `_request*Transfer` internal functions enforce `require(isRunning, "stopped bridge")`. However, the three public `handle*Transfer` functions — `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` — never check `isRunning`. This is the direct structural analog of the WeirollWallet `isForfeitable` bug: a guard field exists, is checked on one side of the operation, and is silently ignored on the other side where the actual asset movement occurs.

---

### Finding Description

`BridgeTransfer.sol` declares the guard:

```solidity
bool public isRunning = true;
```

and the setter:

```solidity
// setRunningStatus can allow or disallow the value transfer request.
function setRunningStatus(bool _status) public onlyOwner {
    isRunning = _status;
    emit RunningStatusChanged(_status);
}
``` [1](#0-0) 

Every `_request*Transfer` internal function enforces the guard:

```solidity
require(isRunning, "stopped bridge");   // in _requestKLAYTransfer
require(isRunning, "stopped bridge");   // in _requestERC20Transfer
require(isRunning, "stopped bridge");   // in _requestERC721Transfer
``` [2](#0-1) [3](#0-2) 

But the three public `handle*Transfer` functions that actually move assets contain **no `isRunning` check**:

```solidity
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    _lowerHandleNonceCheck(_requestedNonce);
    if (!_voteValueTransfer(_requestedNonce)) { return; }
    // ... no isRunning check ...
    (bool ok, ) = _to.call.value(_value)("");   // KLAY sent here
    require(ok, "handleKLAYTransfer: transfer failed");
}
``` [4](#0-3) 

```solidity
function handleERC20Transfer(...) public onlyOperators {
    _lowerHandleNonceCheck(_requestedNonce);
    if (!_voteValueTransfer(_requestedNonce)) { return; }
    // ... no isRunning check ...
    IERC20(_tokenAddress).safeTransfer(_to, _value);   // or mint
}
``` [5](#0-4) 

```solidity
function handleERC721Transfer(...) public onlyOperators {
    // ... no isRunning check ...
    IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);  // or mint
}
``` [6](#0-5) 

The Go-side bridge manager mirrors this gap. `handleRequestValueTransferEvent` reads `bi.isRunning` into the `BridgeInfo` struct but never consults it before dispatching `HandleKLAYTransfer`, `HandleERC20Transfer`, or `HandleERC721Transfer` to the counterpart bridge:

```go
switch tokenType {
case KAIA:
    handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, ...)
case ERC20:
    handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ...)
case ERC721:
    handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ...)
}
``` [7](#0-6) 

The `isRunning` field is populated from the contract but never used as a gate: [8](#0-7) 

---

### Impact Explanation

When the bridge owner calls `setRunningStatus(false)` — the intended emergency-stop mechanism — the contract stops accepting new cross-chain transfer requests. However, any bridge operator can still call `handleKLAYTransfer`, `handleERC20Transfer`, or `handleERC721Transfer` directly and the contract will:

- Transfer KLAY from the bridge contract balance to an arbitrary `_to` address, or
- Transfer (or mint) ERC-20 tokens to an arbitrary `_to` address, or
- Transfer (or mint) ERC-721 tokens to an arbitrary `_to` address.

This directly matches the "Unauthorized transfer, mint, unlock, burn … affecting KAIA, bridged assets" impact gate. The bridge stop mechanism is rendered ineffective for the asset-disbursement side of every transfer type.

---

### Likelihood Explanation

The trigger requires a caller that satisfies `onlyOperators`. Bridge operators are semi-trusted: they are registered by the owner and are expected to relay legitimate cross-chain events. The scenario where this matters is precisely the one the `isRunning` flag is designed for — an emergency stop triggered because an operator key is suspected compromised, or because a bug is being exploited. In that window, before the owner can also deregister operators, any remaining operator (or the compromised key) can drain KLAY and bridged tokens by calling the handle functions directly. The Go-side bridge node software also continues to dispatch these calls automatically from its pending-event queue, so no manual operator action is even required.

---

### Recommendation

Add an `isRunning` guard to all three `handle*Transfer` functions, mirroring the pattern already used on the request side:

```solidity
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

function handleERC20Transfer(...) public onlyOperators {
    require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

function handleERC721Transfer(...) public onlyOperators {
    require(isRunning, "stopped bridge");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}
```

Alternatively, extract the check into a shared modifier (e.g., `onlyRunning`) and apply it to all six request and handle entry points. On the Go side, `handleRequestValueTransferEvent` should also gate on `bi.isRunning` before submitting any handle transaction.

---

### Proof of Concept

1. Deploy the bridge pair (parent + child) in the normal configuration.
2. Fund the parent bridge with 10 KLAY.
3. Owner calls `setRunningStatus(false)` on the parent bridge — bridge is now "stopped."
4. Verify: `requestKLAYTransfer` reverts with `"stopped bridge"`. ✓
5. Operator directly calls `handleKLAYTransfer(txHash, attacker, victim, 10 ether, nonce, blockNum, "")` on the parent bridge.
6. Observe: the call succeeds, 10 KLAY is transferred to `victim` (or any `_to`), `isRunning = false` is never checked, and the bridge balance is drained despite being in the stopped state.

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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L31-71)
```text
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
