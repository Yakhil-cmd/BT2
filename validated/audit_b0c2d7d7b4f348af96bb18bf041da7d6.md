### Title
Deregistering a Bridge Token While Pending `RequestValueTransfer` Events Exist Permanently Locks Bridged Assets — (`contracts/service_chain/bridge/BridgeTokens.sol`, `node/sc/bridge_manager.go`)

---

### Summary

The ServiceChain bridge allows the bridge owner to deregister a token via `BridgeTokens.deregisterToken()` or the RPC wrapper `doDeregisterToken()`. Neither path checks whether there are unhandled `RequestValueTransfer` events for that token. Once the token is removed from the on-chain registry and the off-chain `BridgeInfo.counterpartToken` map, the bridge manager's `handleRequestValueTransferEvent()` permanently fails to process those pending events, leaving user funds burned or locked on the source chain with no corresponding mint or unlock on the destination chain.

---

### Finding Description

**Step 1 — User initiates a cross-chain transfer.**

A user calls `requestERC20Transfer` (or `onERC20Received`) on the source bridge. The `_requestERC20Transfer` internal function enforces `onlyRegisteredToken` and `onlyUnlockedToken`, then either burns the tokens (`modeMintBurn = true`) or locks them in the bridge contract, and emits a `RequestValueTransfer` event with an incremented `requestNonce`. [1](#0-0) 

**Step 2 — Admin deregisters the token.**

The bridge owner calls `deregisterToken` on `BridgeTokens.sol`. The function removes the token from `registeredTokens`, `lockedTokens`, and `registeredTokenList` with no check for outstanding pending requests. [2](#0-1) 

The RPC-level wrapper `doDeregisterToken` in `api_bridge.go` additionally clears the in-memory `counterpartToken` map on both `BridgeInfo` objects before submitting the on-chain transactions, so the in-memory state is invalidated immediately. [3](#0-2) 

**Step 3 — Off-chain bridge manager fails to handle the pending event.**

When `processingPendingRequestEvents` dequeues the pending `RequestValueTransfer` event and calls `handleRequestValueTransferEvent`, the function first looks up the counterpart token address: [4](#0-3) 

`bi.GetCounterPartToken(tokenAddr)` returns `address(0)` because the in-memory map was cleared. The fallback then queries `bi.counterpartBridge.RegisteredTokens(nil, tokenAddr)` on-chain, which also returns `address(0)` because the token was deregistered. The function returns `errors.New("can't get counterpart token from bridge")`.

**Step 4 — Events are re-queued indefinitely.**

The error causes `processingPendingRequestEvents` to re-add all unprocessed events back to the pending queue: [5](#0-4) 

Every subsequent processing attempt fails identically. The `vt_recovery.go` recovery path also feeds events back through `AddRequestValueTransferEvents` → `processingPendingRequestEvents`, hitting the same dead end.

**Step 5 — `handleERC20Transfer` itself has no registration guard.**

Critically, the on-chain `handleERC20Transfer` function carries only `onlyOperators` — no `onlyRegisteredToken` check. An operator who manually submits the handle transaction would succeed. The permanent loss is caused entirely by the off-chain bridge manager's registration check, not by any on-chain guard. [6](#0-5) 

---

### Impact Explanation

- **`modeMintBurn = true`**: User's tokens are burned on the source chain at request time. The corresponding mint on the destination chain never occurs. Tokens are permanently destroyed with no compensation.
- **`modeMintBurn = false`**: User's tokens are locked inside the source bridge contract. The corresponding unlock/transfer on the destination chain never occurs. Tokens are permanently frozen.

In both cases the source bridge's `requestNonce` advances past the destination bridge's `handleNonce` by the number of affected requests, and that gap can never be closed automatically. The corrupted state is the permanent divergence between `requestNonce` (source) and `lowerHandleNonce` (destination) for the deregistered token. [7](#0-6) 

---

### Likelihood Explanation

The trigger requires the bridge owner to call `deregisterToken` (or the RPC `DeregisterToken`) while at least one `RequestValueTransfer` event for that token has been emitted but not yet handled. This is a realistic operational scenario: token migration, bridge maintenance, or emergency shutdown. The bridge owner has no on-chain or off-chain warning that pending requests exist, and no guard prevents the action.

---

### Recommendation

1. **In `BridgeTokens.sol`**: Add a check in `deregisterToken` that reverts if there are any unhandled requests for the token. This requires the bridge contract to track per-token pending counts, or the owner must verify off-chain that `requestNonce == handleNonce` for the token before deregistering.

2. **In `doDeregisterToken` (`api_bridge.go`)**: Before clearing the in-memory map and submitting on-chain transactions, verify that `bi.requestNonce == bi.handleNonce` (or more precisely, that no pending events for the token exist in `pendingRequestEvent`). Return an error if pending events exist.

3. **In `handleRequestValueTransferEvent` (`bridge_manager.go`)**: When the counterpart token cannot be resolved, instead of returning an error that causes re-queuing, log a permanent failure and skip the event (or emit a recoverable alert), so the bridge manager does not loop forever on an unresolvable event.

---

### Proof of Concept

```
1. Deploy bridge pair (child + parent) with ERC20 token T registered on both sides.
   modeMintBurn = true on parent bridge.

2. User calls requestERC20Transfer(T, recipient, 1000) on child bridge.
   → T.burn(1000) executes on child chain.
   → RequestValueTransfer(ERC20, user, recipient, T, 1000, nonce=5) emitted.
   → child bridge requestNonce = 6.

3. Bridge manager picks up the event, adds it to pendingRequestEvent queue.
   (Assume processing is momentarily delayed — e.g., parent chain congestion.)

4. Bridge owner calls doDeregisterToken(childBridge, parentBridge, T, T').
   → counterpartToken map cleared in memory immediately.
   → On-chain deregisterToken(T) submitted to child bridge.
   → On-chain deregisterToken(T') submitted to parent bridge.

5. Bridge manager calls processingPendingRequestEvents():
   → handleRequestValueTransferEvent(ev) called for nonce=5.
   → bi.GetCounterPartToken(T) == address(0)  [in-memory map cleared].
   → bi.counterpartBridge.RegisteredTokens(nil, T) == address(0)  [on-chain deregistered].
   → returns error "can't get counterpart token from bridge".
   → event re-queued.

6. Every subsequent retry fails identically.
   → parent bridge handleNonce stays at 5.
   → 1000 T tokens are permanently burned with no mint on parent chain.
   → User loses 1000 T with no recourse through the automated bridge.
``` [2](#0-1) [4](#0-3) [3](#0-2)

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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-107)
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

        emit RequestValueTransfer(
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            requestNonce,
            fee,
            _extraData
        );
        requestNonce++;
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L74-92)
```text
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

        emit TokenDeregistered(_token);
    }
```

**File:** node/sc/api_bridge.go (L479-519)
```go
func (sb *SubBridgeAPI) doDeregisterToken(cBridgeAddr, pBridgeAddr, cTokenAddr, pTokenAddr common.Address) error {
	if !sb.subBridge.bridgeManager.IsValidBridgePair(cBridgeAddr, pBridgeAddr) {
		return ErrInvalidBridgePair
	}

	cBi, cExist := sb.subBridge.bridgeManager.GetBridgeInfo(cBridgeAddr)
	pBi, pExist := sb.subBridge.bridgeManager.GetBridgeInfo(pBridgeAddr)

	if !cExist || !pExist {
		return ErrNoBridgeInfo
	}

	pTokenAddrCheck := cBi.GetCounterPartToken(cTokenAddr)
	cTokenAddrCheck := pBi.GetCounterPartToken(pTokenAddr)

	if pTokenAddr != pTokenAddrCheck || cTokenAddr != cTokenAddrCheck {
		return errors.New("invalid toke pair")
	}

	cBi.DeregisterToken(cTokenAddr, pTokenAddr)
	pBi.DeregisterToken(pTokenAddr, cTokenAddr)

	cBi.account.Lock()
	defer cBi.account.UnLock()
	tx, err := cBi.bridge.DeregisterToken(cBi.account.GenerateTransactOpts(), cTokenAddr)
	if err != nil {
		return err
	}
	cBi.account.IncNonce()
	logger.Debug("cBridge deregistered token", "txHash", tx.Hash().String(), "cToken", cTokenAddr.String(), "pToken", pTokenAddr.String())

	pBi.account.Lock()
	defer pBi.account.UnLock()
	tx, err = pBi.bridge.DeregisterToken(pBi.account.GenerateTransactOpts(), pTokenAddr)
	if err != nil {
		return err
	}
	pBi.account.IncNonce()
	logger.Debug("pBridge deregistered token", "txHash", tx.Hash().String(), "cToken", cTokenAddr.String(), "pToken", pTokenAddr.String())
	return err
}
```

**File:** node/sc/bridge_manager.go (L89-117)
```go
type BridgeInfo struct {
	subBridge *SubBridge
	bridgeDB  database.DBManager

	counterpartBackend Backend
	address            common.Address
	counterpartAddress common.Address // TODO-Kaia need to set counterpart
	account            *accountInfo
	bridge             *bridgecontract.Bridge
	counterpartBridge  *bridgecontract.Bridge
	onChildChain       bool
	subscribed         bool

	counterpartToken map[common.Address]common.Address
	ctTokenMu        sync.RWMutex

	pendingRequestEvent *bridgepool.ItemSortedMap

	isRunning                   bool
	handleNonce                 uint64 // the nonce from the handle value transfer event from the bridge.
	lowerHandleNonce            uint64 // the lower handle nonce from the bridge.
	requestNonceFromCounterPart uint64 // the nonce from the request value transfer event from the counter part bridge.
	requestNonce                uint64 // the nonce from the request value transfer event from the counter part bridge.

	newEvent chan struct{}
	closed   chan struct{}

	handledEvent *bridgepool.ItemSortedMap
}
```

**File:** node/sc/bridge_manager.go (L248-259)
```go
	for idx, ev := range ReadyEvent {
		if ev.GetRequestNonce() < bi.lowerHandleNonce || bi.handledEvent.Exist(ev.GetRequestNonce()) {
			logger.Trace("handled requests can be ignored", "RequestNonce", ev.GetRequestNonce(), "lowerHandleNonce", bi.lowerHandleNonce)
			continue
		}

		if err := bi.handleRequestValueTransferEvent(ev); err != nil {
			bi.AddRequestValueTransferEvents(ReadyEvent[idx:])
			logger.Error("Failed handle request value transfer event", "err", err, "len(RePutEvent)", len(ReadyEvent[idx:]))
			return
		}
	}
```

**File:** node/sc/bridge_manager.go (L303-319)
```go
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
```
