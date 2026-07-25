### Title
Unvalidated `_from` Parameter in `onERC20Received` Allows Any Registered Token Contract to Forge Bridge Transfer Requests and Drain Bridged Assets — (`contracts/service_chain/bridge/BridgeTransferERC20.sol`)

---

### Summary

`BridgeTransferERC20.onERC20Received` is `public` with no validation that the caller-supplied `_from` parameter matches the actual token sender. Any contract whose address appears in `registeredTokens` can call `onERC20Received` directly with an arbitrary `_from`, forging a `RequestValueTransfer` event attributed to a victim and redirecting fee refunds — or, in lock mode, triggering a counterpart-chain token transfer without depositing anything on the source side.

---

### Finding Description

The 1-step deposit path for ERC20 tokens is:

```
ERC20ServiceChain.requestValueTransfer()
  → transfer tokens to bridge
  → bridge.onERC20Received(msg.sender, _to, _amount, _feeLimit, _extraData)
```

The bridge's `onERC20Received` is declared `public` with no caller restriction on `_from`:

```solidity
// BridgeTransferERC20.sol line 111-121
function onERC20Received(
    address _from,
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
)
    public
{
    _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
}
``` [1](#0-0) 

The only guard inside `_requestERC20Transfer` is `onlyRegisteredToken(_tokenAddress)`, which checks that `msg.sender` is a registered token — it says nothing about whether `_from` is the account that actually deposited tokens:

```solidity
// BridgeTransferERC20.sol line 76-91
function _requestERC20Transfer(
    address _tokenAddress,
    address _from,
    ...
)
    internal
    onlyRegisteredToken(_tokenAddress)   // ← only msg.sender is checked
    onlyUnlockedToken(_tokenAddress)
{
    ...
    uint256 fee = _payERC20FeeAndRefundChange(_from, _tokenAddress, _feeLimit);
    ...
    emit RequestValueTransfer(TokenType.ERC20, _from, _to, ...);
``` [2](#0-1) 

`_payERC20FeeAndRefundChange` then transfers tokens from the bridge's own balance to the caller-controlled `_from`:

```solidity
// BridgeFee.sol line 68-88
function _payERC20FeeAndRefundChange(address from, address _token, uint256 _feeLimit) internal returns(uint256) {
    ...
    if (_feeLimit > 0) {
        IERC20(_token).safeTransfer(from, _feeLimit);   // ← bridge balance → arbitrary `from`
    }
    return 0;
}
``` [3](#0-2) 

Token registration is `onlyOwner`:

```solidity
// BridgeTokens.sol line 57-71
function registerToken(address _token, address _cToken)
    external
    onlyOwner
    onlyNotRegisteredToken(_token)
{ ... }
``` [4](#0-3) 

So the precondition is controlling a registered token contract — a semi-trusted actor, not an arbitrary unprivileged user.

The bridge operator in `bridge_manager.go` processes every `RequestValueTransfer` event without independently verifying that tokens were actually deposited:

```go
// bridge_manager.go line 331-354
switch tokenType {
case ERC20:
    handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, ...)
``` [5](#0-4) 

---

### Impact Explanation

**Impact 1 — Fee-refund theft from bridge balance (lock mode or mint-burn mode).**  
A registered token contract calls `onERC20Received(attacker, attacker, 1, B, "")` where `B` equals the bridge's current balance of that token. `_payERC20FeeAndRefundChange` executes `IERC20(token).safeTransfer(attacker, B)`, draining the bridge's entire token balance to the attacker. This is an unauthorized transfer of bridged assets.

**Impact 2 — Counterpart-chain drain without deposit (lock mode).**  
In lock mode `_requestERC20Transfer` performs no token movement on the source side. A registered token contract calls `onERC20Received(victim, attacker, V, 0, "")`. The bridge emits `RequestValueTransfer(from=victim, to=attacker, value=V)`. The bridge operator relays this to the counterpart bridge, which executes `IERC20(cToken).safeTransfer(attacker, V)` — transferring real tokens to the attacker with zero deposit on the source chain.

**Impact 3 — Identity forgery.**  
The `from` field in `RequestValueTransfer` / `HandleValueTransfer` events is the only on-chain record of who initiated a cross-chain transfer. Forging it corrupts bridge accounting and any off-chain system that relies on it.

---

### Likelihood Explanation

The attacker must control a contract address that the bridge owner has registered via `registerToken`. This is a semi-trusted actor scenario: a legitimate token contract that is later compromised, a token contract with a re-entrancy or delegatecall surface, or a token registered by a bridge operator who was socially engineered. The precondition is non-trivial but not implausible in a live service-chain deployment with multiple registered tokens.

---

### Recommendation

1. **Validate `_from` inside `onERC20Received`**: require that `_from == msg.sender` is not the right fix (msg.sender is the token contract), but the token contract itself should be the only entity that can supply `_from`. The bridge should not accept `_from` as a free parameter from an external call.

2. **Restrict `onERC20Received` to registered tokens only** by adding `onlyRegisteredToken(msg.sender)` directly on `onERC20Received` (not just inside the internal function), so the revert happens before any state is read.

3. **Preferred fix**: mirror the `requestERC20Transfer` pattern — use `msg.sender` as `_from` inside `onERC20Received` and ignore the caller-supplied `_from` parameter entirely, or remove the `_from` parameter and derive it from the token contract's own transfer records.

```solidity
// Suggested fix
function onERC20Received(
    address /* _from */,   // ignore caller-supplied value
    address _to,
    uint256 _value,
    uint256 _feeLimit,
    bytes memory _extraData
)
    public
    onlyRegisteredToken(msg.sender)   // early guard
{
    // Use msg.sender as the token address; derive _from from the token's
    // transferFrom records or require the token contract to authenticate _from.
    _requestERC20Transfer(msg.sender, msg.sender, _to, _value, _feeLimit, _extraData);
}
```

The same issue exists in `onERC721Received` in `BridgeTransferERC721.sol` (no fee impact, but identity forgery and lock-mode drain still apply). [6](#0-5) 

---

### Proof of Concept

**Setup:**
- Bridge deployed in lock mode (`modeMintBurn = false`).
- `attackerToken` is a registered ERC20 token (registered by bridge owner).
- Counterpart bridge holds 1000 `cAttackerToken` tokens.
- Bridge holds 500 `attackerToken` tokens (from prior legitimate deposits).

**Attack — drain bridge balance via fee refund:**
```
attacker.call(
  bridge.onERC20Received(
    _from      = attacker,   // arbitrary, not validated
    _to        = attacker,
    _value     = 1,          // must be > 0
    _feeLimit  = 500,        // equals bridge's token balance
    _extraData = ""
  ),
  { from: attackerToken }    // msg.sender must be registered token
)
```

Execution path:
1. `_requestERC20Transfer(attackerToken, attacker, attacker, 1, 500, "")` — passes `onlyRegisteredToken(attackerToken)`.
2. `_payERC20FeeAndRefundChange(attacker, attackerToken, 500)` — `feeReceiver == 0`, so `IERC20(attackerToken).safeTransfer(attacker, 500)` executes. Bridge loses 500 tokens.
3. `emit RequestValueTransfer(ERC20, attacker, attacker, attackerToken, 1, nonce, 0, "")`.
4. Bridge operator relays → counterpart bridge transfers 1 `cAttackerToken` to attacker.

**Net result:** attacker receives 500 `attackerToken` from the source bridge balance plus 1 `cAttackerToken` from the counterpart bridge, with no legitimate deposit. [7](#0-6) [3](#0-2) [8](#0-7)

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L76-107)
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

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L110-121)
```text
    // onERC20Received function of ERC20 token for 1-step deposits to the Bridge.
    function onERC20Received(
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeLimit,
        bytes memory _extraData
    )
        public
    {
        _requestERC20Transfer(msg.sender, _from, _to, _value, _feeLimit, _extraData);
    }
```

**File:** contracts/service_chain/bridge/BridgeFee.sol (L68-88)
```text
    function _payERC20FeeAndRefundChange(address from, address _token, uint256 _feeLimit) internal returns(uint256) {
        uint256 fee = feeOfERC20[_token];

        if (feeReceiver != address(0) && fee > 0) {
            require(_feeLimit >= fee, "insufficient feeLimit");

            IERC20(_token).safeTransfer(feeReceiver, fee);

            uint256 feeRefund = _feeLimit.sub(fee);
            if (feeRefund > 0) {
                IERC20(_token).safeTransfer(from, feeRefund);
            }

            return fee;
        }

        if (_feeLimit > 0) {
            IERC20(_token).safeTransfer(from, _feeLimit);
        }
        return 0;
    }
```

**File:** contracts/service_chain/bridge/BridgeTokens.sol (L57-71)
```text
    function registerToken(address _token, address _cToken)
        external
        onlyOwner
        onlyNotRegisteredToken(_token)
    {
        // If _cToken == 0 then registeredTokens[_token] = 0, which confuses the
        // onlyRegisteredToken and onlyNotRegisteredToken modifiers.
        require(_cToken != address(0), "counterpart token address is zero");

        registeredTokens[_token] = _cToken;
        indexOfTokens[_token] = registeredTokenList.length;
        registeredTokenList.push(_token);

        emit TokenRegistered(_token);
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

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L108-118)
```text
    // onERC721Received function of ERC721 token for 1-step deposits to the Bridge
    function onERC721Received(
        address _from,
        uint256 _tokenId,
        address _to,
        bytes memory _extraData
    )
        public
    {
        _requestERC721Transfer(msg.sender, _from, _to, _tokenId, _extraData);
    }
```
