### Title
`handleERC20Transfer` / `handleERC721Transfer` / `handleKLAYTransfer` Bypass `isRunning` and `lockedTokens` Protected-State Flags — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`, `BridgeTransferKLAY.sol`)

---

### Summary

The Kaia service-chain bridge enforces three protected-state flags on the **outbound** (request) path — `isRunning`, `lockedTokens[token]`, and `isLockedKLAY` — but none of these flags are checked on the **inbound** (handle) path. A bridge operator can therefore call `handleERC20Transfer`, `handleERC721Transfer`, or `handleKLAYTransfer` to mint or transfer bridged assets even after the bridge owner has explicitly stopped the bridge or locked a token, defeating the emergency-pause mechanism entirely.

---

### Finding Description

**Outbound path — all three guards present:**

`_requestERC20Transfer` in `BridgeTransferERC20.sol` carries:

```solidity
internal
onlyRegisteredToken(_tokenAddress)   // guard 1
onlyUnlockedToken(_tokenAddress)     // guard 2
{
    require(isRunning, "stopped bridge"); // guard 3
``` [1](#0-0) 

`_requestKLAYTransfer` in `BridgeTransferKLAY.sol` carries:

```solidity
internal
unlockedKLAY          // guard 1
nonReentrant
{
    require(isRunning, "stopped bridge"); // guard 2
``` [2](#0-1) 

**Inbound path — zero guards:**

`handleERC20Transfer` has only `onlyOperators` and nonce checks; no `isRunning`, no `lockedTokens`, no `registeredTokens` check:

```solidity
public
onlyOperators
{
    _lowerHandleNonceCheck(_requestedNonce);
    if (!_voteValueTransfer(_requestedNonce)) { return; }
    ...
    if (modeMintBurn) {
        require(ERC20Mintable(_tokenAddress).mint(_to, _value), ...);
    } else {
        IERC20(_tokenAddress).safeTransfer(_to, _value);
    }
}
``` [3](#0-2) 

`handleERC721Transfer` is identical in structure — no `isRunning` or `lockedTokens` check: [4](#0-3) 

`handleKLAYTransfer` has `onlyOperators` and `nonReentrant` but no `isLockedKLAY` or `isRunning` check: [5](#0-4) 

The `lockedTokens` mapping and `isLockedKLAY` flag are defined in `BridgeTokens` and `BridgeTransferKLAY` respectively: [6](#0-5) [7](#0-6) 

The Go relay layer (`BridgeInfo.handleRequestValueTransferEvent`) calls all three handle functions unconditionally, with no pre-flight check of bridge state: [8](#0-7) 

---

### Impact Explanation

| Mode | Bypassed flag | Concrete effect |
|---|---|---|
| `modeMintBurn = true` | `lockedTokens[token]` | Operator mints ERC-20/ERC-721 tokens on the destination chain even after the owner locked the token (e.g., in response to a token-contract exploit) |
| `modeMintBurn = true` | `isRunning = false` | Operator mints tokens after the owner issued an emergency stop |
| `modeMintBurn = false` | `isRunning = false` | Operator drains the bridge's token reserve after an emergency stop |
| KLAY | `isLockedKLAY` | Operator sends KLAY from the bridge contract after the owner locked KLAY transfers |

In `modeMintBurn` mode the impact is an **unauthorized mint** of bridged assets. In lock-mode the impact is an **unauthorized transfer** of assets held by the bridge contract. Both are within the allowed impact gate.

---

### Likelihood Explanation

The trigger requires a registered bridge operator. Operators are semi-trusted: they are registered by the owner but run as separate automated processes. The realistic attack paths are:

1. **Compromised operator key** — an attacker who obtains an operator key can call `handleERC20Transfer` with arbitrary parameters (any `_tokenAddress`, any `_value`, any `_to`) even when the bridge is stopped.
2. **Race condition** — the owner stops the bridge to respond to an incident; the operator's relay daemon has already queued a `handleERC20Transfer` call and submits it before the daemon is halted.
3. **Operator ignores bridge state** — the Go relay (`handleRequestValueTransferEvent`) never reads `isRunning` or `lockedTokens` before submitting handle transactions, so the relay will naturally bypass the flags without any malicious intent.

Path 3 is unconditional and requires no compromise at all.

---

### Recommendation

Add the same guards to the handle path that exist on the request path:

```solidity
// BridgeTransferERC20.sol — handleERC20Transfer
function handleERC20Transfer(...) public onlyOperators {
+   require(isRunning, "stopped bridge");
+   require(!lockedTokens[_tokenAddress], "locked token");
+   require(registeredTokens[_tokenAddress] != address(0), "not allowed token");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}

// BridgeTransferKLAY.sol — handleKLAYTransfer
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
+   require(isRunning, "stopped bridge");
+   require(!isLockedKLAY, "locked");
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}
```

Apply the same pattern to `handleERC721Transfer`. Alternatively, introduce a shared internal helper that enforces all three invariants and call it from every handle function.

---

### Proof of Concept

1. Deploy bridge in `modeMintBurn = true` mode; register and unlock ERC-20 token T; register two operators op1, op2.
2. Owner calls `lockToken(T)` — `lockedTokens[T] == true`.
3. Owner calls `start(false)` — `isRunning == false`.
4. op1 calls `handleERC20Transfer(txhash, alice, bob, T, 1e18, 0, blockNum, "0x")` — succeeds (no revert).
5. op2 calls the same — threshold reached, `ERC20Mintable(T).mint(bob, 1e18)` executes.
6. `bob` now holds 1e18 T tokens minted after the emergency stop, violating the owner's intent.

The existing test `TestBridgeContract_TokenLock` confirms that `requestValueTransfer` is correctly blocked when a token is locked, but no analogous test exists for `handleERC20Transfer` under the same condition, confirming the gap. [9](#0-8)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-88)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L24-37)
```text
    bool public isLockedKLAY;

    event KLAYLocked();
    event KLAYUnlocked();

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

**File:** node/sc/bridge_test.go (L907-967)
```go
// TestBridgeContract_TokenLock checks the following:
// - the token can be lock to prevent value transfer requests.
func TestBridgeContract_TokenLock(t *testing.T) {
	env := generateBridgeTokenTestEnv(t)
	defer env.backend.Close()

	backend := env.backend
	operator := env.operator
	tester := env.tester
	b := env.bridge
	erc20 := env.erc20
	erc721 := env.erc721
	erc20Addr := env.erc20Addr
	erc721Addr := env.erc721Addr

	// lock token
	tx, err := b.LockToken(operator, erc20Addr)
	assert.NoError(t, err)
	backend.Commit()
	CheckReceipt(backend, tx, 1*time.Second, types.ReceiptStatusSuccessful, t)

	tx, err = b.LockToken(operator, erc721Addr)
	assert.NoError(t, err)
	backend.Commit()
	CheckReceipt(backend, tx, 1*time.Second, types.ReceiptStatusSuccessful, t)

	tx, err = b.LockKLAY(operator)
	assert.NoError(t, err)
	backend.Commit()
	CheckReceipt(backend, tx, 1*time.Second, types.ReceiptStatusSuccessful, t)

	// check value after locking
	isLocked, err := b.LockedTokens(nil, erc20Addr)
	assert.NoError(t, err)
	assert.Equal(t, true, isLocked)

	isLocked, err = b.LockedTokens(nil, erc721Addr)
	assert.NoError(t, err)
	assert.Equal(t, true, isLocked)

	isLocked, err = b.IsLockedKLAY(nil)
	assert.NoError(t, err)
	assert.Equal(t, true, isLocked)

	// check to prevent value transfer
	tx, err = erc20.RequestValueTransfer(tester, big.NewInt(1), operator.From, big.NewInt(0), nil)
	assert.NoError(t, err)
	backend.Commit()
	assert.NotNil(t, bind.CheckWaitMined(backend, tx))

	tx, err = erc721.RequestValueTransfer(tester, big.NewInt(1), operator.From, nil)
	assert.NoError(t, err)
	backend.Commit()
	assert.NotNil(t, bind.CheckWaitMined(backend, tx))

	tester.Value = big.NewInt(1)
	tx, err = b.RequestKLAYTransfer(tester, tester.From, big.NewInt(1), nil)
	assert.NoError(t, err)
	backend.Commit()
	assert.NotNil(t, bind.CheckWaitMined(backend, tx))
	tester.Value = nil
```
